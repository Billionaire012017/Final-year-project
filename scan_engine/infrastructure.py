from typing import List
from datetime import datetime
from scan_engine.intel.db import get_session
from scan_engine.intel.models import AssetRecord, AssetType

class InfrastructureService:
    def __init__(self):
        self.session = get_session()

    def get_all_assets(self) -> List[AssetRecord]:
        assets = self.session.query(AssetRecord).all()
        if not assets:
            self._seed_demo_assets()
            assets = self.session.query(AssetRecord).all()
        return assets

    def _seed_demo_assets(self):
        demo_assets = [
            AssetRecord(name="Core-API-Gateway", type=AssetType.SERVICE, environment="Production", coverage=98.5, posture_score=94.2, vulnerabilities_count=4, critical_vulnerabilities=0, description="Central entry point for all external traffic."),
            AssetRecord(name="Auth-Provider-Node", type=AssetType.SERVICE, environment="Production", coverage=100.0, posture_score=98.0, vulnerabilities_count=1, critical_vulnerabilities=0, description="Handles JWT/OAuth2 authentication flows."),
            AssetRecord(name="Legacy-Payment-Service", type=AssetType.SERVICE, environment="Production", coverage=82.0, posture_score=65.5, vulnerabilities_count=28, critical_vulnerabilities=4, description="Maintains backwards compatibility for older payment rails."),
            AssetRecord(name="Frontend-Main-Portal", type=AssetType.APPLICATION, environment="Production", coverage=92.0, posture_score=88.5, vulnerabilities_count=15, critical_vulnerabilities=1, description="Primary customer-facing web dashboard."),
            AssetRecord(name="Data-Lake-Ingestion", type=AssetType.SERVICE, environment="Staging", coverage=75.0, posture_score=82.0, vulnerabilities_count=10, critical_vulnerabilities=0, description="Processes raw logs for threat intelligence."),
            AssetRecord(name="Marketing-Static-Site", type=AssetType.REPOSITORY, environment="Staging", coverage=45.0, posture_score=95.0, vulnerabilities_count=2, critical_vulnerabilities=0, description="Public marketing assets and content."),
            AssetRecord(name="Experimental-LLM-Integ", type=AssetType.REPOSITORY, environment="Development", coverage=30.0, posture_score=52.0, vulnerabilities_count=56, critical_vulnerabilities=12, description="R&D branch for AI features."),
        ]
        for asset in demo_assets:
            self.session.add(asset)
        self.session.commit()

    def get_infrastructure_summary(self):
        assets = self.get_all_assets()
        total_assets = len(assets)
        if total_assets == 0:
            return {"total_assets": 0, "average_coverage": 0, "average_posture": 0, "environment_breakdown": {}}
            
        avg_coverage = sum(a.coverage for a in assets) / total_assets
        avg_posture = sum(a.posture_score for a in assets) / total_assets
        
        return {
            "total_assets": total_assets,
            "average_coverage": round(avg_coverage, 1),
            "average_posture": round(avg_posture, 1),
            "environment_breakdown": {
                "Production": len([a for a in assets if a.environment == "Production"]),
                "Staging": len([a for a in assets if a.environment == "Staging"]),
                "Development": len([a for a in assets if a.environment == "Development"])
            }
        }
