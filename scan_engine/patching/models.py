from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class PatchSuggestion(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: str = Field(index=True)
    patched_code: str
    diff: str
    explanation: str
    confidence_score: float
    risk_level: str
    risk_explanation: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
