import os
import sqlite3

def run_command(cmd):
    # Vulnerability: exec usage
    exec(cmd)

def calculate(expression):
    # Vulnerability: eval usage
    return eval(expression)

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    # Vulnerability: Raw SQL injection
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor = conn.execute(query)
    return cursor.fetchall()
