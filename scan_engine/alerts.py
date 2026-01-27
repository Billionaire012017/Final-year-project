from datetime import datetime
from typing import Optional, List
from sqlmodel import SQLModel, Field
from scan_engine.intel.db import get_session

class AlertRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    level: str # INFO, WARNING, CRITICAL
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    read: bool = Field(default=False)

class AlertService:
    def __init__(self):
        pass

    def trigger_alert(self, level: str, message: str):
        with get_session() as session:
            alert = AlertRecord(level=level, message=message)
            session.add(alert)
            session.commit()
        # In a real system, send email/slack here
        # print(f"[{level}] ALERT: {message}")

    def get_recent_alerts(self, limit: int = 5) -> List[AlertRecord]:
        with get_session() as session:
            return session.query(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(limit).all()
