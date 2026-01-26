from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field
from enum import Enum
from scan_engine.models import Severity

class VulnerabilityState(str, Enum):
    DETECTED = "DETECTED"
    FIX_GENERATED = "FIX_GENERATED"
    VALIDATED = "VALIDATED"
    UNDER_REVIEW = "UNDER_REVIEW"
    FIXED = "FIXED"
    REJECTED = "REJECTED"

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
    state: VulnerabilityState = Field(default=VulnerabilityState.DETECTED) 
    ai_remediation_supported: bool = Field(default=False)

class VulnerabilityHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: str = Field(index=True)
    old_state: Optional[str] = None
    new_state: str
    action: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
