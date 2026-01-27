from datetime import datetime
from typing import Optional, List
from sqlmodel import SQLModel, Field
from scan_engine.intel.db import get_session
import json
import csv
import io

class SystemAudit(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    action_type: str  # SCAN, DETECTION, AI_FIX, VALIDATION, APPROVAL, RESOLUTION
    description: str
    actor: str = Field(default="SYSTEM_KERNEL")
    resource_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    checksum: str = Field(default="GENESIS_HASH") # Simulation of immutable chain

class AuditService:
    def __init__(self):
        pass

    def log_event(self, action_type: str, description: str, actor: str = "SYSTEM_KERNEL", resource_id: Optional[str] = None):
        import hashlib
        with get_session() as session:
            # Get last entry checksum for chain simulation
            last_entry = session.query(SystemAudit).order_by(SystemAudit.id.desc()).first()
            prev_hash = last_entry.checksum if last_entry else "GENESIS"
            
            # Create checksum: hash(prev_hash + action + actor + timestamp)
            ts = datetime.utcnow().isoformat()
            raw = f"{prev_hash}|{action_type}|{actor}|{ts}"
            checksum = hashlib.sha256(raw.encode()).hexdigest()

            audit = SystemAudit(
                action_type=action_type,
                description=description,
                actor=actor,
                resource_id=resource_id,
                timestamp=datetime.utcnow(),
                checksum=checksum
            )
            session.add(audit)
            session.commit()

    def export_logs_json(self) -> str:
        with get_session() as session:
            logs = session.query(SystemAudit).order_by(SystemAudit.timestamp.desc()).all()
            data = [l.model_dump(mode='json') for l in logs]
            return json.dumps(data, indent=4, default=str)
