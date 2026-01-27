import time
from datetime import datetime
from typing import Dict, Any

class SystemHealthService:
    _start_time = time.time()
    
    def __init__(self):
        # In a real app, these would be polled from a message broker or process manager
        self.ai_status = "ONLINE"
        self.scanner_status = "STANDBY"
        self.queue_depth = 0
        self.last_exec_timestamp = None
        
    def get_health_telemetry(self) -> Dict[str, Any]:
        uptime_seconds = int(time.time() - self._start_time)
        
        return {
            "ai_engine": {
                "status": self.ai_status,
                "load": "Low",
                "threads_active": 12,
                "latency_ms": 42
            },
            "scanner": {
                "status": self.scanner_status,
                "version": "v4.2.0-stable",
                "concurrency": "4/10",
                "memory_usage": "240MB"
            },
            "processing_queues": {
                "remediation_queue": self.queue_depth,
                "validation_queue": 0,
                "enrichment_queue": 0,
                "total_pending": self.queue_depth
            },
            "uptime": self._format_uptime(uptime_seconds),
            "uptime_seconds": uptime_seconds,
            "last_execution": self.last_exec_timestamp or "No recent executions",
            "system_state": "OPTIMAL" if uptime_seconds > 0 else "INITIALIZING"
        }
    
    def _format_uptime(self, seconds: int) -> str:
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        
        parts = []
        if days > 0: parts.append(f"{days}d")
        if hours > 0: parts.append(f"{hours}h")
        if minutes > 0: parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")
        
        return " ".join(parts)

# Singleton instance for simple state tracking in this demo
health_monitor = SystemHealthService()
