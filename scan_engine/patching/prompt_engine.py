from jinja2 import Template
from scan_engine.intel.models import VulnerabilityRecord

class PromptEngine:
    def __init__(self):
        self.template = Template("""
You are a security expert. Fix the following vulnerability in Python code.

Vulnerability: {{ vuln.name }}
Description: {{ vuln.description }}
File: {{ vuln.file_path }}
Line: {{ vuln.line_number }}

Vulnerable Code:
```python
{{ vuln.code_snippet }}
```

Task:
1. Analyze the potentially insecure code.
2. Provide a secure patched version of the code.
3. Explain why the patch is secure.

Use the following secure coding practices:
- If SQL Injection: Use parameterized queries.
- If Hardcoded Password: Use environment variables.
- If Eval: Use ast.literal_eval or remove.

Output Format:
Return ONLY the patched code block followed by a brief explanation.
""")

    def create_prompt(self, vuln: VulnerabilityRecord) -> str:
        return self.template.render(vuln=vuln)
