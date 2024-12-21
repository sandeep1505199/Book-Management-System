# Import required modules for FastAPI, Pydantic, password hashing, and MySQL database handling
from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel, Field, validator
from passlib.context import CryptContext
from typing import Optional
import re  # Regular expressions for email validation
import mysql.connector
from mysql.connector import Error

# ---------------- In-Memory Session Storage -------------------
# This is a simple in-memory dictionary used to track logged-in users.
user_sessions = {}

# ---------------- Database Configuration -------------------
# Configuration for connecting to the MySQL database
DATABASE_CONFIG = {
    "host": "localhost",  # Database host (localhost in this case)
    "user": "root",       # Username for MySQL database
    "password": "sandeep1505",  # Password for the MySQL user
    "database": "bookdb"  # The specific database to use
}

# ---------------- FastAPI Application ----------------------
# Create an instance of the FastAPI application
app = FastAPI()

# ---------------- Password Hashing -------------------------
# Initialize the password hashing context using bcrypt algorithm
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------- Validation Helper Functions --------------
# Function to validate the email format using a regular expression
def validate_email(email: str):
    """Validate email format."""
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
        raise ValueError("Invalid email address.")  # Raise error if invalid
    return email

# Function to validate password strength
def validate_password(password: str):
    """Validate password strength."""
    if len(password) < 6:  # Password must be at least 6 characters long
        raise ValueError("Password must be at least 6 characters long.")
    if not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):  # Password must have at least one letter and one number
        raise ValueError("Password must contain at least one letter and one number.")
    return password

# Function to validate if the user role is either 'admin' or 'user'
def validate_role(role: str):
    """Validate user role."""
    if role not in ["admin", "user"]:  # Only allow 'admin' or 'user' roles
        raise ValueError("Role must be either 'admin' or 'user'.")
    return role

# ---------------- Pydantic Schemas -------------------------
# Define a Pydantic model for user creation (used for request validation)
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, description="Username must be at least 3 characters long.")
    password: str
    email: str
    role: Optional[str] = "user"  # Default role is 'user' if not provided

    # Validators to check the data
    _validate_email = validator("email", allow_reuse=True)(validate_email)
    _validate_password = validator("password", allow_reuse=True)(validate_password)
    _validate_role = validator("role", allow_reuse=True)(validate_role)

# Define a Pydantic model for user login (used for request validation)
class UserLogin(BaseModel):
    username: str
    password: str

# Define a base model for books (used for book creation and retrieval)
class BookBase(BaseModel):
    title: str
    author: str
    description: str

# Define a model for book creation, inheriting from BookBase
class BookCreate(BookBase):
    pass

# Define a model for books (with an ID field), used for returning book data
class Book(BookBase):
    id: int

    # This allows FastAPI to work with ORM models like SQLAlchemy models
    class Config:
        orm_mode = True

# ---------------- Database Utility Functions ---------------
# Function to get a connection to the MySQL database
def get_connection():
    try:
        # Establish a connection to the database using the provided credentials
        connection = mysql.connector.connect(**DATABASE_CONFIG)
        return connection
    except Error as e:
        # If an error occurs during connection, print the error and raise an HTTP exception
        print(f"Database Connection Error: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")

# Function to authenticate a user by verifying their credentials
def authenticate_user(username: str, password: str):
    """Authenticate user credentials."""
    connection = get_connection()  # Get database connection
    cursor = connection.cursor(dictionary=True)  # Create a cursor to execute queries
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))  # Fetch the user by username
    user = cursor.fetchone()  # Get the first result (user) from the query
    cursor.close()  # Close the cursor after the query
    connection.close()  # Close the connection to the database

    # If the user exists and the password matches the hashed password, return the user data
    if user and pwd_context.verify(password, user["password_hash"]):
        return user
    return None  # Return None if authentication fails

# ---------------- Dependencies ----------------------------
# Dependency function to check if the current user has admin privileges
def admin_required(username: str):
    """Ensure the user has admin privileges."""
    connection = get_connection()  # Get database connection
    cursor = connection.cursor(dictionary=True)  # Create a cursor
    cursor.execute("SELECT role FROM users WHERE username = %s", (username,))  # Get the user role
    user = cursor.fetchone()  # Fetch the user role
    cursor.close()  # Close the cursor
    connection.close()  # Close the connection
    if not user or user["role"] != "admin":  # If no user is found or role is not 'admin'
        raise HTTPException(status_code=403, detail="Only admins can perform this action")

# ---------------- Authentication Endpoints -----------------
# Endpoint to register a new user
@app.post("/register/")
def register(user: UserCreate):
    """Register a new user."""
    hashed_password = pwd_context.hash(user.password)  # Hash the user's password before storing it
    connection = get_connection()  # Get database connection
    cursor = connection.cursor()  # Create a cursor
    try:
        # Insert the new user into the 'users' table with the provided details
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, role) VALUES (%s, %s, %s, %s)",
            (user.username, hashed_password, user.email, user.role),
        )
        connection.commit()  # Commit the transaction to the database
    except Error:
        # If there is a database error (e.g., duplicate user), raise an HTTP exception
        raise HTTPException(status_code=400, detail="User already exists")
    finally:
        cursor.close()  # Close the cursor
        connection.close()  # Close the database connection
    return {"message": "User registered successfully"}  # Return a success message

# Endpoint to log in a user
@app.post("/login/")
def login(user_data: UserLogin):
    """User login endpoint."""
    user = authenticate_user(user_data.username, user_data.password)  # Authenticate the user
    if not user:
        # If authentication fails, return a 401 Unauthorized response
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    user_sessions[user['username']] = True  # Add the user to the session (simulate login)
    return {"message": f"Logged in as {user['role']}", "username": user['username']}  # Return a success message

# Endpoint to log out a user
@app.post("/logout/")
def logout(username: str):
    """Logout the user and clear the session."""
    if username in user_sessions:
        del user_sessions[username]  # Remove the user from the session (simulate logout)
        return {"message": f"User '{username}' logged out successfully"}  # Return a success message
    raise HTTPException(status_code=400, detail="User is not logged in")  # If user is not in session, raise an error

# ---------------- CRUD Operations -------------------------
# Endpoint to create a new book (only accessible to admins)
@app.post("/books/", response_model=Book)
def create_book(book: BookCreate, username: str):
    """Add a new book to the database (Admin Only)."""
    admin_required(username)  # Ensure the user is an admin
    connection = get_connection()  # Get the database connection
    cursor = connection.cursor()  # Create a cursor
    query = "INSERT INTO books (title, author, description) VALUES (%s, %s, %s)"  # SQL query to insert the new book
    cursor.execute(query, (book.title, book.author, book.description))  # Execute the query
    connection.commit()  # Commit the transaction
    book_id = cursor.lastrowid  # Get the ID of the newly created book
    cursor.close()  # Close the cursor
    connection.close()  # Close the connection
    return {"id": book_id, "title": book.title, "author": book.author, "description": book.description}  # Return the created book

# Endpoint to retrieve all books from the database
@app.get("/books/", response_model=list[Book])
def read_books():
    """Retrieve all books from the database."""
    connection = get_connection()  # Get database connection
    cursor = connection.cursor(dictionary=True)  # Create a cursor
    cursor.execute("SELECT * FROM books")  # Execute a query to get all books
    books = cursor.fetchall()  # Fetch all the books from the database
    cursor.close()  # Close the cursor
    connection.close()  # Close the connection
    return books  # Return the list of books

# Endpoint to retrieve a specific book by its ID
@app.get("/books/{book_id}", response_model=Book)
def read_book(book_id: int):
    """Retrieve a specific book by its ID."""
    connection = get_connection()  # Get database connection
    cursor = connection.cursor(dictionary=True)  # Create a cursor
    cursor.execute("SELECT * FROM books WHERE id = %s", (book_id,))  # Query the database for the specific book by ID
    book = cursor.fetchone()  # Fetch the book
    cursor.close()  # Close the cursor
    connection.close()  # Close the connection
    if not book:
        # If the book is not found, raise an HTTP 404 Not Found error
        raise HTTPException(status_code=404, detail="Book not found")
    return book  # Return the book data

# Endpoint to delete a book by its ID (only accessible to admins)
@app.delete("/books/{book_id}", response_model=Book)
def delete_book(book_id: int, username: str):
    """Delete a book by its ID (Admin Only)."""
    admin_required(username)  # Ensure the user is an admin
    connection = get_connection()  # Get database connection
    cursor = connection.cursor(dictionary=True)  # Create a cursor
    cursor.execute("SELECT * FROM books WHERE id = %s", (book_id,))  # Query to check if the book exists
    book = cursor.fetchone()  # Fetch the book
    if not book:
        cursor.close()  # Close the cursor
        connection.close()  # Close the connection
        raise HTTPException(status_code=404, detail="Book not found")  # Raise error if book not found
    cursor.execute("DELETE FROM books WHERE id = %s", (book_id,))  # Delete the book from the database
    connection.commit()  # Commit the deletion transaction
    cursor.close()  # Close the cursor
    connection.close()  # Close the connection
    return book  # Return the deleted book data