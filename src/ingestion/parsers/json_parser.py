import json
from typing import Dict, Any

class JSONParser:
    """Parse JSON formatted logs."""
    
    @staticmethod
    def parse(raw_log: str) -> Dict[str, Any]:
        """Parse JSON log entry."""
        try:
            return json.loads(raw_log)
        except json.JSONDecodeError:
            return {
                "raw": raw_log,
                "parse_error": True,
                "parser": "json"
            }
    
    @staticmethod
    def normalize(log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize log fields."""
        normalized = {
            "timestamp": log_data.get("timestamp", log_data.get("@timestamp")),
            "source_ip": log_data.get("src_ip", log_data.get("source_ip")),
            "dest_ip": log_data.get("dst_ip", log_data.get("dest_ip")),
            "event_type": log_data.get("event_type", log_data.get("action")),
            "severity": log_data.get("severity", "INFO"),
            "raw_data": log_data
        }
        return {k: v for k, v in normalized.items() if v is not None}