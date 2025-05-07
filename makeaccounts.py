import sqlite3
from passlib.hash import pbkdf2_sha256

con = sqlite3.connect('bank.db')
cur = con.cursor()
cur.execute('''
    CREATE TABLE accounts (
        id text primary key, owner text, balance integer,
        foreign key(owner) references users(email))''')
cur.execute(
    "INSERT INTO accounts VALUES (?, ?, ?)",
    ('100', 'alice@example.com', 7500))
cur.execute(
    "INSERT INTO accounts VALUES (?, ?, ?)",
    ('190', 'alice@example.com', 200))
cur.execute(
    "INSERT INTO accounts VALUES (?, ?, ?)",
    ('998', 'bob@example.com', 1000))
con.commit()
con.close()