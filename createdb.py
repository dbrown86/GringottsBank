import sqlite3
from passlib.hash import pbkdf2_sha256

con = sqlite3.connect('bank.db')
cur = con.cursor()
cur.execute('''
    CREATE TABLE users (
        email text primary key, name text, password text)''')
cur.execute(
    "INSERT INTO users VALUES (?, ?, ?)",
    ('alice@example.com', 'Alice Xu', pbkdf2_sha256.hash("123456").decode('utf-8')))
cur.execute(
    "INSERT INTO users VALUES (?, ?, ?)",
    ('bob@example.com', 'Bobby Tables', pbkdf2_sha256.hash("123456").decode('utf-8')))
con.commit()
con.close()