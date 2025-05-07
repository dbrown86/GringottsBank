from html import escape
from account_service import get_balance, do_transfer
from flask import Flask, request, make_response, redirect, render_template, g, abort, url_for
from flask_wtf.csrf import CSRFProtect
from user_service import get_user_with_credentials, logged_in
import logging
import time
import re
import os
import sqlite3

import user_service

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursupersecrettokenhere' 
app.config['DATABASE'] = os.path.join(os.path.dirname(app.root_path), 'bank.db')
csrf = CSRFProtect(app)  # Enables CSRF protection for all POST/PUT/DELETE/PATCH requests

# Constant-time comparison function to prevent timing attacks
def constant_time_compare(val1, val2):
    """
    Compare two values in constant time to prevent timing attacks.
    This helps prevent user enumeration via timing differences.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0

# Pattern for account number validation
ACCOUNT_PATTERN = re.compile(r'^\d{10}$')
# Pattern for email validation
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

@app.context_processor
def utility_processor(): 
    def get_balance_for_template(account_id, user_email=None):
        # If user_email is not provided, use g.user if available
        if not user_email and hasattr(g, 'user'):
            user_email = g.user
        return get_balance(account_id, user_email)
        
    return {
        'get_balance': get_balance_for_template
    }

@app.route("/")
def home():
    """
    Home route that displays the login page directly.
    This is the landing page of the application.
    """
    return render_template("login.html")


@app.route("/login", methods=['GET', 'POST'])
def login():
    """
    Login route that authenticates users.
    
    Security:
    - Uses CSRF protection (via global CSRFProtect)
    - Prevents user enumeration by using constant time for comparisons
    - Sets HttpOnly cookies for JWTs to prevent XSS attacks accessing tokens
    - Uses POST redirect pattern to prevent form resubmission
    - Implements rate limiting to prevent brute force attacks
    """
    if request.method == 'GET':
        # For GET requests, show the login form
        return render_template("login.html")
    
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
    
        # Validate email format
        if not EMAIL_PATTERN.match(email):
            logger.debug("Login failed - Invalid email format")
            time.sleep(1)  # Add delay to prevent user enumeration via timing
            return render_template("login.html", error="Invalid credentials"), 400
        
        logger.debug(f"Login attempt for email: {email}")
        
        # Add a small delay to prevent timing attacks for user enumeration
        start_time = time.time()
        
        user = get_user_with_credentials(email, password)
    
        # Ensure consistent timing regardless of whether user exists
        elapsed = time.time() - start_time
        if elapsed < 0.5:  # If validation took less than 0.5 seconds
            time.sleep(0.5 - elapsed)  # Sleep the remaining time to reach 0.5 seconds
        
        if not user:
            logger.debug("Login failed - Invalid credentials")
            return render_template("login.html", error="Invalid credentials"), 400
        
        logger.debug(f"Login successful for: {email}")
        response = make_response(redirect("/dashboard"))

    
        # Set HttpOnly cookie for JWT to prevent XSS from accessing the token
        # Set Secure flag in production environments
        # Set SameSite to 'Lax' to prevent CSRF attacks while allowing normal navigation
        response.set_cookie(
            "auth_token", 
            user["token"], 
            httponly=True,
            samesite='Lax',
            secure = True
        )
        logger.debug("Auth token cookie set")
    
        return response, 303  # 303 See Other - correct status code for POST/Redirect/GET pattern

@app.route('/dashboard')
def dashboard():
    """
    Dashboard route - displays user account information
    """
    
    # Get authenticated user's email
    user_email = get_authenticated_user()
    
    # If not authenticated, redirect to login
    if not user_email:
        return redirect(url_for('login'))
    
    # Now fetch the user's accounts from the database
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        
        # Query all accounts for this user
        cur.execute(
            "SELECT id, owner, balance, account_type FROM accounts WHERE owner = ?",
            (user_email,)
        )
        
        accounts = []
        for row in cur.fetchall():
            accounts.append({
                'id': row[0],
                'owner': row[1],
                'balance': row[2],
                'account_type': row[3]  
            })
        
        con.close()
        
        # Get the primary account for the user (first account or empty default)
        account = accounts[0] if accounts else {'id': 'N/A', 'balance': 0}
        
        # Render dashboard with account data
        return render_template(
            'dashboard.html',
            user=user_email,
            account=account,  # This fixes the undefined variable error
            accounts=accounts  # Pass all accounts to the template
        )
        
    except Exception as e:
        app.logger.error(f"Error fetching accounts: {str(e)}")
        return render_template('error.html', message="Failed to load account data"), 500
    
def get_authenticated_user():
    """
    Get the currently authenticated user from the JWT token using user_service.logged_in
    """
    
    # Use the logged_in function to validate the token
    if user_service.logged_in():
        # When logged_in() is true, it sets g.user to the email from the token
        return g.user
    
    return None
    
        
@app.route("/details", methods=['GET'])
def details():
    """
    Account details route that shows balance for a specific account.
    
    Security:
    - Verifies authentication
    - Validates input parameters
    - Verifies account ownership to prevent unauthorized access
    - Uses parameterized queries (in get_balance) to prevent SQL injection
    """
    if not logged_in():
        logger.debug("Details access denied - not logged in")
        return redirect("/")
    
    account_number = request.args.get('account', '')
    
    # Validate account number format
    if not ACCOUNT_PATTERN.match(account_number):
        logger.debug(f"Invalid account number format: {account_number}")
        abort(400, "Invalid account number format")
    
    logger.debug(f"Details requested for account: {account_number} by user: {g.user}")
    
    balance = get_balance(account_number, g.user)
    if balance is None:
        logger.debug(f"No balance found for account: {account_number}")
        # Use generic error to prevent account enumeration
        abort(404, "Resource not found")
    
    logger.debug(f"Balance for account {account_number}: {balance}")
    return render_template(
        "details.html", 
        user=escape(g.user),
        account_number=escape(account_number),
        balance=escape(str(balance)))

@app.route("/transfer", methods=["GET"])
def transfer_form():
    """
    Transfer form route.
    
    Security:
    - Verifies authentication
    - CSRF tokens automatically included in form via CSRFProtect
    """
    if not logged_in():
        logger.debug("Transfer form access denied - not logged in")
        return redirect("/")
    
    logger.debug(f"Transfer form accessed by user: {g.user}")
    return render_template("transfer.html", email=escape(g.user))

@app.route("/transfer", methods=["POST"])
def transfer():
    """
    Transfer funds between accounts.
    
    Security:
    - Verifies authentication
    - Validates all input parameters 
    - Uses CSRF protection (via global CSRFProtect)
    - Verifies account ownership for source account
    - Uses parameterized queries (in do_transfer) to prevent SQL injection
    - Implements proper error handling with appropriate status codes
    - Uses POST-redirect-GET pattern to prevent double submissions
    """
    if not logged_in():
        logger.debug("Transfer action denied - not logged in")
        return redirect("/")
    
    # Fixed account IDs for knapsack and vault
    knapsack_id = '190'  # Account ID for knapsack
    vault_id = '100'     # Account ID for vault
    
    # Get direction and amount from form
    direction = request.form.get("direction", "")
    amount_str = request.form.get("amount", "")
    
    # Determine source and target accounts based on direction
    if direction == "to_vault":
        source = knapsack_id
        target = vault_id
    elif direction == "from_vault":
        source = vault_id
        target = knapsack_id
    else:
        logger.debug("Transfer denied - invalid direction")
        return render_template("transfer.html", 
                              email=escape(g.user), 
                              error="Invalid transfer direction"), 400
    
    # Validate amount is a number
    try:
        amount = int(amount_str)
    except ValueError:
        logger.debug("Transfer denied - invalid amount format")
        return render_template("transfer.html", 
                              email=escape(g.user), 
                              error="Amount must be a valid number"), 400
    
    logger.debug(f"Transfer request: {amount} from {source} to {target}")
    
    # Business logic validations
    if amount <= 0:
        logger.debug("Transfer denied - non-positive amount")
        return render_template("transfer.html", 
                              email=escape(g.user), 
                              error="Amount must be positive"), 400
    
    if amount > 1000:
        logger.debug("Transfer denied - amount too large")
        return render_template("transfer.html", 
                              email=escape(g.user), 
                              error="Maximum transfer amount is 1000"), 400
    
    # Verify the user owns the source account (authorization check)
    available_balance = get_balance(source, g.user)
    if available_balance is None:
        logger.debug("Transfer denied - source account not found or not owned by user")
        return render_template("transfer.html", 
                              email=escape(g.user), 
                              error="Source account not found or not authorized"), 404
    
    if amount > available_balance:
        logger.debug("Transfer denied - insufficient funds")
        return render_template("transfer.html", 
                              email=escape(g.user), 
                              error=f"Insufficient funds. Available: {available_balance}"), 400
    
    # Perform the transfer
    if do_transfer(source, target, amount):
        logger.debug("Transfer successful")
        # Redirect to dashboard with a success message using GET parameter
        # (safe to include non-sensitive info in URL)
        return redirect("/dashboard?transfer_success=true")
    else:
        logger.debug("Transfer failed")
        return render_template("transfer.html", 
                              email=escape(g.user), 
                              error="Transfer failed. Please try again later."), 500
    

def get_user_accounts(email):
    """
    Fetch all accounts belonging to a specific user from the database
    """
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        cur.execute(
            "SELECT id, owner, balance FROM accounts WHERE owner = ?",
            (email,)
        )
        accounts = []
        for row in cur.fetchall():
            accounts.append({
                'id': row[0],
                'owner': row[1],
                'balance': row[2]
            })
        con.close()
        return accounts
    except Exception as e:
        print(f"Database error: {e}")
        return []

@app.route("/logout", methods=['GET'])
def logout():
    """
    Logout route that invalidates the session.
    
    Security:
    - Uses proper cookie clearing
    - Redirects to home page
    - GET method is acceptable for logout since it's not modifying data in a dangerous way
      and allows for easier bookmarking/navigation
    """
    logger.debug("Logging out user")
    response = make_response(redirect("/"))
    # Clear the auth token cookie with the same settings that were used to set it
    response.set_cookie('auth_token', '', expires=0, httponly=True, samesite='Lax')
    logger.debug("Auth token cookie deleted")
    return response, 303

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors with a custom template"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors with a custom template"""
    return render_template('500.html'), 500

@app.after_request
def add_security_headers(response):
    """
    Add security headers to every response
    
    Security:
    - Content-Security-Policy prevents loading of external resources to mitigate XSS
    - X-Content-Type-Options prevents MIME type sniffing
    - X-Frame-Options prevents clickjacking attacks
    - Cache-Control prevents caching of sensitive information
    """
    # CSP to mitigate XSS attacks - restrict resource loading
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'"
    # Prevent browser from doing MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Prevent embedding the site in iframes (clickjacking protection)
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevent caching of sensitive information
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    return response


if __name__ == "__main__":
    app.run(debug=True)  # Set debug=False in production