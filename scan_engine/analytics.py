from datetime import datetime
from scan_engine.intel.db import get_session
from scan_engine.intel.models import VulnerabilityRecord, VulnerabilityStatus, VulnerabilityHistory
from sqlalchemy import func

class AnalyticsService:
    def __init__(self):
        self.session = get_session()

    def get_kpis(self):
        total = self.session.query(VulnerabilityRecord).count()
        fixed = self.session.query(VulnerabilityRecord).filter(VulnerabilityRecord.status == VulnerabilityStatus.FIXED).count()
        rejected = self.session.query(VulnerabilityRecord).filter(VulnerabilityRecord.status == VulnerabilityStatus.REJECTED).count()
        active = self.session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.status.in_([
                VulnerabilityStatus.DETECTED, 
                VulnerabilityStatus.AI_FIX_GENERATED, 
                VulnerabilityStatus.VALIDATED
            ])
        ).count()

        # Risk Distribution
        severity_counts = self.session.query(
            VulnerabilityRecord.severity, func.count(VulnerabilityRecord.id)
        ).group_by(VulnerabilityRecord.severity).all()
        risk_dist = {str(s).upper(): c for s, c in severity_counts}

        return {
            "total": total,
            "active": active,
            "healed": fixed,
            "mttr": self.get_avg_fix_time_seconds(),
            "risk_distribution": risk_dist,
            "success_rate": round((fixed / (fixed + rejected) * 100) if (fixed + rejected) > 0 else 0.0, 1)
        }

    def get_health_score(self) -> int:
        open_vulns = self.session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.status.in_([
                VulnerabilityStatus.DETECTED, 
                VulnerabilityStatus.AI_FIX_GENERATED, 
                VulnerabilityStatus.VALIDATED
            ])
        ).all()
        
        penalty = 0
        for v in open_vulns:
            sev = str(v.severity).upper()
            if "CRITICAL" in sev: penalty += 25
            elif "HIGH" in sev: penalty += 15
            elif "MEDIUM" in sev: penalty += 5
            else: penalty += 1
        
        return max(0, 100 - penalty)

    def get_trend_data(self):
        history = self.session.query(VulnerabilityHistory).order_by(VulnerabilityHistory.timestamp.desc()).limit(15).all()
        actions = [h.new_state for h in history]
        return actions[::-1]

    def get_avg_fix_time_seconds(self):
        fixed_vulns = self.session.query(VulnerabilityRecord).filter(VulnerabilityRecord.status == VulnerabilityStatus.FIXED).all()
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
        return self.session.query(VulnerabilityRecord).all()
