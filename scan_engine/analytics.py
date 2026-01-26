from datetime import datetime
from scan_engine.intel.db import get_session
from scan_engine.intel.models import VulnerabilityRecord, VulnerabilityState, VulnerabilityHistory
from sqlalchemy import func

class AnalyticsService:
    def __init__(self):
        self.session = get_session()

    def get_kpis(self):
        total = self.session.query(VulnerabilityRecord).count()
        fixed = self.session.query(VulnerabilityRecord).filter(VulnerabilityRecord.state == VulnerabilityState.FIXED).count()
        rejected = self.session.query(VulnerabilityRecord).filter(VulnerabilityRecord.state == VulnerabilityState.REJECTED).count()
        pending = self.session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.state.in_([
                VulnerabilityState.DETECTED, 
                VulnerabilityState.FIX_GENERATED, 
                VulnerabilityState.VALIDATED,
                VulnerabilityState.UNDER_REVIEW
            ])
        ).count()

        success_rate = 0.0
        if fixed + rejected > 0:
            success_rate = (fixed / (fixed + rejected)) * 100.0

        return {
            "total": total,
            "fixed": fixed,
            "rejected": rejected,
            "pending": pending,
            "success_rate": round(success_rate, 1)
        }

    def get_health_score(self) -> int:
        # Health Score = 100 - (High Sev * 20 + Medium Sev * 10 + Low Sev * 2) (Capped at 0-100)
        # For simplicity, let's look at open vulnerabilities
        
        open_vulns = self.session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.state.in_([
                VulnerabilityState.DETECTED, 
                VulnerabilityState.FIX_GENERATED, 
                VulnerabilityState.VALIDATED, 
                VulnerabilityState.UNDER_REVIEW
            ])
        ).all()
        
        penalty = 0
        for v in open_vulns:
            if v.severity == "CRITICAL" or v.severity == "HIGH":
                penalty += 20
            elif v.severity == "MEDIUM":
                penalty += 10
            else:
                penalty += 2
        
        score = max(0, 100 - penalty)
        return score

    def get_trend_data(self):
        # Return simple counts of actions per 'day' or just last N actions for visualization
        # In this demo, we can't easily do Group By Day on SQLite easily without setup.
        # We will return a list of [ ("Action", Count) ]
        
        # Taking last 10 history items
        history = self.session.query(VulnerabilityHistory).order_by(VulnerabilityHistory.timestamp.desc()).limit(15).all()
        
        # Simple list of actions
        actions = [h.new_state for h in history]
        # Reverse to show chronological
        return actions[::-1]

    def get_avg_fix_time_seconds(self):
        # Calculate time difference between DETECTED and FIXED for fixed vulns
        # This is a bit complex in SQLModel/SQLAlchemy without complex joins or native functions,
        # so we'll do a simple python-side aggregation for now (assuming low volume).
        
        fixed_vulns = self.session.query(VulnerabilityRecord).filter(VulnerabilityRecord.state == VulnerabilityState.FIXED).all()
        if not fixed_vulns:
            return 0.0
            
        total_time = 0.0
        count = 0
        
        for vuln in fixed_vulns:
            history = self.session.query(VulnerabilityHistory).filter(
                VulnerabilityHistory.vulnerability_id == vuln.id
            ).order_by(VulnerabilityHistory.timestamp).all()
            
            if not history:
                continue
                
            start_time = history[0].timestamp
            end_time = history[-1].timestamp
            total_time += (end_time - start_time).total_seconds()
            count += 1
            
        if count == 0:
            return 0.0
            
        return round(total_time / count, 1)

    def get_pipeline_data(self):
        # Return list of vulns for the pipeline view
        return self.session.query(VulnerabilityRecord).all()
