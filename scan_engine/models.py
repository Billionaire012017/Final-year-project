from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

class Vulnerability(BaseModel):
    id: str = Field(..., description="Unique ID for the vulnerability instance")
    name: str = Field(..., description="Name or title of the vulnerability")
    description: str = Field(..., description="Detailed description")
    severity: Severity
    file_path: str
    line_number: int
    scanner_name: str
    cwe_id: Optional[str] = None
    fix_recommendation: Optional[str] = None

class ScanStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"

class ScanResult(BaseModel):
    scan_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: ScanStatus
    vulnerabilities: List[Vulnerability] = []
    metadata: dict = {}
