import requests
from typing import Dict, Any, Optional

class EventEnricher:
    """Enrich events with additional context."""
    
    def __init__(self):
        self.cache = {}
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with additional data."""
        # Add GeoIP data (simplified - use real GeoIP in production)
        source_ip = event.get("source_ip")
        if source_ip:
            geo_data = self._get_geoip(source_ip)
            if geo_data:
                event["source_geo"] = geo_data
        
        # Add reputation score
        if source_ip:
            reputation = self._get_reputation(source_ip)
            event["source_reputation"] = reputation
        
        return event
    
    def _get_geoip(self, ip: str) -> Optional[Dict[str, str]]:
        """Get GeoIP data (mock implementation)."""
        # In production, use MaxMind or similar service
        if ip in self.cache:
            return self.cache[ip]
        
        # Mock data
        geo = {
            "country": "US",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0
        }
        
        self.cache[ip] = geo
        return geo
    
    def _get_reputation(self, ip: str) -> float:
        """Get IP reputation score (0-1, higher is better)."""
        # Mock implementation - use real reputation service in production
        if ip.startswith("10.") or ip.startswith("192.168."):
            return 0.9  # Internal IPs generally trusted
        
        return 0.5  # Default neutral reputation