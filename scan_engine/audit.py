from datetime import datetime
from typing import Optional, List
from sqlmodel import SQLModel, Field
from scan_engine.intel.db import get_session
import json
import csv
import io

class SystemAudit(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    event_type: str # SCAN, PATCH, AUTH, REVIEW
    description: str
    user_id: str = Field(default="system") # Simulated user
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AuditService:
    def __init__(self):
        self.session = get_session()

    def log_event(self, event_type: str, description: str, user_id: str = "system"):
        audit = SystemAudit(
            event_type=event_type,
            description=description,
            user_id=user_id
        )
        self.session.add(audit)
        self.session.commit()

    def export_logs_json(self) -> str:
        logs = self.session.query(SystemAudit).all()
        data = [l.model_dump(mode='json') for l in logs]
        return json.dumps(data, indent=4, default=str)
