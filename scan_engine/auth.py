from enum import Enum
from typing import List

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"

class AuthService:
    def __init__(self):
        # Define permissions
        self.permissions = {
            "scan": [UserRole.ADMIN, UserRole.DEVELOPER, UserRole.VIEWER],
            "dashboard": [UserRole.ADMIN, UserRole.DEVELOPER, UserRole.VIEWER],
            "patch": [UserRole.ADMIN, UserRole.DEVELOPER],
            "review": [UserRole.ADMIN, UserRole.DEVELOPER],
            "export_audit": [UserRole.ADMIN],
        }

    def check_permission(self, role: str, action: str) -> bool:
        allowed_roles = self.permissions.get(action, [])
        # Simple string matching for role enum
        try:
            user_enum = UserRole(role.upper())
            return user_enum in allowed_roles
        except ValueError:
            return False
