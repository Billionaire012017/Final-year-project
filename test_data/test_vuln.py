# This is a test file for the automated remediation pipeline
import os
import ast

def unsafe_fn(user_input):
    # Vulnerability 1: EVAL_INJECTION
    result = eval(user_input)
    return result

def another_unsafe_fn(data):
    # Vulnerability 2: EXEC_INJECTION
    exec(data)

def sql_fn(query_part):
    # Vulnerability 3: SQL_INJECTION
    query = "SELECT * FROM users WHERE id = " + query_part
    print(f"Executing: {query}")
