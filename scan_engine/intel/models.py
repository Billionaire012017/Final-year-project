import uuid
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field
from enum import Enum

class VulnerabilityStatus(str, Enum):
    DETECTED = "Detected"
    AI_FIX_GENERATED = "AI_Fix_Generated"
    VALIDATED = "Validated"
    FIXED = "Fixed"
    REJECTED = "Rejected"

class ScanRecord(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    target: str
    status: str # SUCCESS, FAILURE, RUNNING
    findings_count: int = 0
    severity_breakdown: str = "{}" # JSON string representation

class VulnerabilityRecord(SQLModel, table=True):
    id: str = Field(primary_key=True)
    scan_id: Optional[str] = Field(default=None, foreign_key="scanrecord.id")
    project_id: str = Field(default="DEFAULT_PROJECT")
    file_path: str
    file_name: str
    full_code: Optional[str] = None
    vulnerable_lines: str  # Comma separated line numbers or JSON
    vulnerability_type: str
    severity: str
    risk_score: float = Field(default=0.0)
    status: VulnerabilityStatus = Field(default=VulnerabilityStatus.DETECTED)
    ai_explanation: Optional[str] = None
    remediation_guidance: Optional[str] = None
    exploit_scenario: Optional[str] = None
    root_cause: Optional[str] = None
    exploitability: float = Field(default=0.0)
    exposure: float = Field(default=0.0)
    asset_criticality: float = Field(default=0.0)
    business_impact: Optional[str] = None
    ai_reasoning_log: Optional[str] = None # JSON string of steps
    ai_fix_code: Optional[str] = None
    full_code_fixed: Optional[str] = None
    validation_result: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class VulnerabilityHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: str = Field(index=True)
    old_state: Optional[str] = None
    new_state: str
    action: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AssetType(str, Enum):
    APPLICATION = "Application"
    REPOSITORY = "Repository"
    SERVICE = "Service"

class AssetRecord(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    name: str
    type: AssetType
    environment: str = "Production" # Production, Staging, Development
    coverage: float = Field(default=0.0) # 0-100%
    posture_score: float = Field(default=100.0) # 0-100%
    last_scanned: Optional[datetime] = None
    vulnerabilities_count: int = 0
    critical_vulnerabilities: int = 0
    status: str = "Monitoring" # Monitoring, Maintenance, Offline
    description: Optional[str] = None
