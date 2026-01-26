from abc import ABC, abstractmethod

class BaseAIService(ABC):
    @abstractmethod
    def generate_patch(self, prompt: str) -> dict:
        """
        Returns a dict with 'patched_code' and 'explanation'.
        """
        pass

class MockAIService(BaseAIService):
    def generate_patch(self, prompt: str) -> dict:
        print(f"[MockAI] Received prompt length: {len(prompt)}")
        
        # Simple pattern matching to return relevant mocks
        if "hardcoded_password" in prompt or "password =" in prompt:
            return {
                "patched_code": "import os\n\ndef check_password(password):\n    # Securely fetched from env var\n    if password == os.environ.get('SECRET_PASSWORD'):\n        print('Access granted')",
                "explanation": "Replaced hardcoded password with environment variable retrieval using os.environ.get()."
            }
        elif "eval(" in prompt:
            return {
                "patched_code": "import ast\n\ndef run_code(code):\n    # Use ast.literal_eval for safe evaluation\n    ast.literal_eval(code)",
                "explanation": "Replaced dangerous `eval()` with `ast.literal_eval()` which only evaluates literals, preventing arbitrary code execution."
            }
        
        return {
            "patched_code": "# AI could not generate a patch for this.",
            "explanation": "No specific pattern matched in Mock AI."
        }
