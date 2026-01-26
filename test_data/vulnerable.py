import os

def check_password(password):
    # Hardcoded password - should be caught by Semgrep/Bandit
    if password == "supersecret123":
        print("Access granted")

def run_code(code):
    # Eval usage - should be caught by Bandit
    eval(code)

check_password("guest")
