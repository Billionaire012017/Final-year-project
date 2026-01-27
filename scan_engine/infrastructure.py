from typing import List, Optional
from datetime import datetime
from scan_engine.intel.db import get_session
from scan_engine.intel.models import AssetRecord, AssetType, SystemAudit
import json
import hashlib

class InfrastructureService:
    def __init__(self):
        pass

    def get_all_assets(self) -> List[AssetRecord]:
        with get_session() as session:
            assets = session.query(AssetRecord).all()
            if not assets:
                self._seed_demo_assets(session) # Pass session to seed_demo_assets
                assets = session.query(AssetRecord).all()
            return assets

    def _seed_demo_assets(self, session): # Accept session as argument
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
            session.add(asset) # Use the passed session
        session.commit() # Use the passed session

    def get_infrastructure_summary(self):
        assets = self.get_all_assets()
        return {
            "total_assets": len(assets),
            "average_posture": round(sum([a.posture_score for a in assets]) / len(assets) if assets else 100, 1),
            "critical_vulnerabilities": sum([a.critical_vulnerabilities for a in assets]),
            "environment_distribution": {
                "Production": len([a for a in assets if a.environment == "Production"]),
                "Staging": len([a for a in assets if a.environment == "Staging"]),
                "Development": len([a for a in assets if a.environment == "Development"])
            }
        }
