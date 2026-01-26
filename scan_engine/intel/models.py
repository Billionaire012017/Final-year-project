from typing import Optional
from sqlmodel import SQLModel, Field
from scan_engine.models import Severity

class VulnerabilityRecord(SQLModel, table=True):
    id: str = Field(primary_key=True)
    name: str
    description: str
    severity: str  # Stored as string, mapped to Enum
    file_path: str
    line_number: int
    scanner_name: str
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    state: str = Field(default="DETECTED") # DETECTED, REMEDIATING, FIXED
    ai_remediation_supported: bool = Field(default=False)
