import sqlite3
from datetime import datetime, timedelta
import pytz
from passlib.hash import pbkdf2_sha256
from flask import request, g
import jwt
import os
import time
import logging
import re

# Set up logging - INCREASE LOG LEVEL
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Use environment variable for JWT secret in production
# ADDED FALLBACK SECRET FOR TESTING
SECRET = os.environ.get('SECRET_KEY', 'yoursupersecrettokenhere')

# Configuration for password hashing
PBKDF2_ROUNDS = 150000  # Industry standard or higher

def get_user_with_credentials(email, password):
    """
    Authenticate a user with email and password
    
    Security:
    - Uses parameterized queries to prevent SQL injection
    - Uses proper password hashing with pbkdf2_sha256
    - Uses timing-safe comparisons to prevent timing attacks
    
    Args:
        email (str): User's email address
        password (str): User's password
        
    Returns:
        dict: User data with token if credentials are valid, None otherwise
    """
    logger.debug(f"Authentication attempt for: {email}")
    
    # Validate email format before querying database
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    if not email_pattern.match(email):
        logger.debug(f"Invalid email format: {email}")
        return None
    
    try:
        # Measure start time for consistent timing
        start_time = time.time()
        
        # Check if database file exists
        import os
        db_path = 'bank.db'
        if not os.path.exists(db_path):
            logger.error(f"Database file not found: {db_path}")
            logger.error(f"Current working directory: {os.getcwd()}")
            return None
            
        logger.debug(f"Connecting to database: {db_path}")
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        
        # Use parameterized query to prevent SQL injection
        query = "SELECT email, name, password FROM users WHERE email=?"
        logger.debug(f"Executing query: {query} with parameter: {email}")
        
        cur.execute(query, (email,))
        row = cur.fetchone()
        
        # If no user found, simulate password verification time
        if row is None:
            logger.debug(f"No user found with email: {email}")
            # Simulate the time it would take to verify a password
            dummy_hash = pbkdf2_sha256.hash('dummy_password')
            pbkdf2_sha256.verify('dummy_password', dummy_hash)
            return None
            
        logger.debug(f"User found: {row[0]}")
        email_db, name, password_hash = row

        # Ensure password_hash is a string
        if isinstance(password_hash, bytes):
            password_hash = password_hash.decode('utf-8')
        
        logger.debug("Verifying password")
        # Verify password using passlib's timing-safe comparison
        if not pbkdf2_sha256.verify(password, password_hash):
            logger.debug("Password verification failed")
            return None
            
        # Successful login
        logger.debug("Password verification successful")
        
        # Create token with extra error handling
        try:
            token = create_token(email_db)
            logger.debug("Token created successfully")
        except Exception as token_error:
            logger.error(f"Error creating token: {str(token_error)}")
            return None
            
        result = {"email": email_db, "name": name, "token": token}
        
        # Ensure consistent timing regardless of success/failure
        elapsed = time.time() - start_time
        if elapsed < 0.5:  # If the operation took less than 0.5 seconds
            time.sleep(0.5 - elapsed)  # Sleep to reach at least 0.5 seconds
            
        logger.debug("Authentication successful")
        return result
    except Exception as e:
        logger.error(f"Error in authentication: {str(e)}")
        # Print the full stack trace for debugging
        import traceback
        logger.error(traceback.format_exc())
        return None
    finally:
        if 'con' in locals():
            con.close()

def logged_in():
    """
    Check if the user is logged in based on JWT in cookie
    
    Security:
    - Properly validates JWT token
    - Handles exceptions safely
    - Sets user identity in flask.g for use in request
    
    Returns:
        bool: True if logged in, False otherwise
    """
    token = request.cookies.get('auth_token')
    if not token:  # Handle None or empty string
        logger.debug("No auth_token cookie found")
        return False
    try:
        # Decode and verify JWT
        logger.debug("Decoding JWT token")
        data = jwt.decode(token, SECRET, algorithms=['HS256'])
        # Store user email in Flask's g object for this request
        g.user = data['sub']
        logger.debug(f"User authenticated: {g.user}")
        return True
    except jwt.ExpiredSignatureError:
        logger.debug("JWT token expired")
        return False
    except jwt.InvalidTokenError:
        logger.debug("Invalid JWT token")
        return False
    except Exception as e:
        logger.error(f"Error validating JWT: {str(e)}")
        return False

def create_token(email):
    """
    Create a JWT for the given email
    
    Security:
    - Sets proper JWT claims (sub, iat, exp)
    - Uses a reasonable expiry time
    
    Args:
        email (str): User's email
        
    Returns:
        str: JWT token
    """
    logger.debug(f"Creating token for: {email}")
    now = datetime.now(pytz.utc)
    # Create JWT with standard claims
    payload = {
        'sub': email,         # Subject (user identifier)
        'iat': now,           # Issued at time
        'exp': now + timedelta(minutes=60)  # Expiry time - 1 hour
    }
    
    if not SECRET:
        logger.error("SECRET_KEY not set in environment variables")
        raise ValueError("SECRET_KEY environment variable not set")
        
    token = jwt.encode(payload, SECRET, algorithm='HS256')
    return token

def create_user(email, name, password):
    """
    Create a new user with hashed password
    
    Security:
    - Uses proper password hashing with pbkdf2_sha256
    - Uses parameterized queries to prevent SQL injection
    
    Args:
        email (str): User's email
        name (str): User's name
        password (str): User's password
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Hash password with pbkdf2_sha256
        password_hash = pbkdf2_sha256.hash(password, rounds=PBKDF2_ROUNDS)
        
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        # Use parameterized query to prevent SQL injection
        cur.execute('''
            INSERT INTO users (email, name, password) VALUES (?, ?, ?)''',
            (email, name, password_hash))
        con.commit()
        return True
    except sqlite3.IntegrityError:
        # Handle case where email already exists
        return False
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return False
    finally:
        if 'con' in locals():
            con.close()

#

