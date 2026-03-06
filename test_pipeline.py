import os
import sys
from server import scan_file_content, get_remediation_info, ALLOWED_VULN_TYPES

# Mock objects if needed
print(f"Testing with ALLOWED_VULN_TYPES: {ALLOWED_VULN_TYPES}")

test_code = """
def unsafe_fn(user_input):
    # Vulnerability 1: EVAL_INJECTION
    result = eval(user_input)
    return result

def sql_fn(query_part):
    # Vulnerability 2: SQL_INJECTION
    query = "SELECT * FROM users WHERE id = " + query_part
    print(f"Executing: {query}")
"""

print("--- Running scan_file_content ---")
vulns = scan_file_content(test_code, "test_file.py")
print(f"Detected {len(vulns)} vulnerabilities.")

for v in vulns:
    print(f"ID: {v['id']} | type: {v['vulnerability_type']} | status: {v['status']}")
    print(f"Snippet: {v['code_snippet']}")
    print(f"Fix suggestion: {v['suggested_fix']}")
    print("-" * 20)

if len(vulns) >= 2:
    print("SUCCESS: Detection engine is working locally.")
else:
    print("FAILURE: Detection engine failed to find vulnerabilities.")
