from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field
from scan_engine.intel.db import get_session

class FeedbackRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    patch_id: int = Field(index=True)
    action: str # APPROVE / REJECT
    comments: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class FeedbackService:
    def __init__(self):
        self.session = get_session()

    def record_feedback(self, patch_id: int, action: str, comments: str = None):
        feedback = FeedbackRecord(
            patch_id=patch_id,
            action=action,
            comments=comments
        )
        self.session.add(feedback)
        self.session.commit()
