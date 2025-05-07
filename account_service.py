import sqlite3
from passlib.hash import pbkdf2_sha256
import os


def get_balance(account_id, user_email):
    """
    Get the balance for a specific account ID owned by the given user.
    """
    try:
        conn = sqlite3.connect('bank.db')
        cur = conn.cursor()
        cur.execute(
            "SELECT balance FROM accounts WHERE id = ? AND owner = ?",
            (account_id, user_email)
        )
        result = cur.fetchone()
        conn.close()
        return result[0] if result else 0
    except Exception as e:
        print(f"Error fetching balance: {e}")
        return 0

def do_transfer(from_account, to_account, amount):
    """
    Transfer funds between accounts
    """
    try:
        conn = sqlite3.connect('bank.db')
        cur = conn.cursor()
        
        # Check if source account has sufficient funds
        cur.execute("SELECT balance FROM accounts WHERE id = ?", (from_account,))
        source_balance = cur.fetchone()
        
        if not source_balance or source_balance[0] < amount:
            conn.close()
            return False
        
        # Perform the transfer
        cur.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", 
                   (amount, from_account))
        cur.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", 
                   (amount, to_account))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error during transfer: {e}")
        return False