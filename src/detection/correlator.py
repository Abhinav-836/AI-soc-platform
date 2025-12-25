"""
Event correlation engine.
"""

from typing import Dict, List, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict

from src.utils.logger import LoggerMixin


class CorrelationEngine(LoggerMixin):
    """Correlates events to detect complex patterns."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.events: List[Dict[str, Any]] = []
        self.windows: Dict[str, Any] = {}
        self.patterns = self._load_correlation_patterns()

    def _load_correlation_patterns(self) -> List[Dict[str, Any]]:
        """Load correlation patterns from config."""
        thresholds = self.config.get("detection", {}).get("thresholds", {})

        patterns = []

        # Brute force pattern
        brute_force = thresholds.get("brute_force", {})
        patterns.append({
            "name": "brute_force_attempts",
            "description": "Multiple failed authentication attempts",
            "conditions": [
                {"event_type": "ssh_failed"},
                {"event_type": "rdp_failed"},
                {"event_type": "web_auth_failed"},
            ],
            "window": brute_force.get("time_window", "5m"),
            "threshold": brute_force.get("failed_logins", 5),
            "group_by": ["src_ip", "user"],
            "severity": "high",
        })

        # Port scan pattern
        port_scan = thresholds.get("port_scan", {})
        patterns.append({
            "name": "port_scan_detected",
            "description": "Multiple ports scanned from single IP",
            "conditions": [
                {"event_type": "firewall_drop"},
                {"status": "denied"},
            ],
            "window": port_scan.get("time_window", "2m"),
            "threshold": port_scan.get("unique_ports", 10),
            "group_by": ["src_ip"],
            "severity": "medium",
        })

        return patterns

    async def add_event(self, event: Dict[str, Any]):
        """Add event to correlation engine."""
        self.events.append(event)

        # Keep only last 24 hours of events
        cutoff = datetime.utcnow() - timedelta(hours=24)
        self.events = [
            e for e in self.events
            if datetime.fromisoformat(e.get("@timestamp", "").replace("Z", "+00:00")) > cutoff
        ]

    async def run_correlation(self) -> List[Dict[str, Any]]:
        """Run correlation and return alerts."""
        alerts = []

        for pattern in self.patterns:
            try:
                pattern_alerts = await self._check_pattern(pattern)
                alerts.extend(pattern_alerts)
            except Exception as e:
                self.logger.error(f"Error checking pattern {pattern['name']}: {e}", exc_info=True)

        return alerts

    async def _check_pattern(self, pattern: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check events against a correlation pattern."""
        window = self._parse_time_window(pattern["window"])
        threshold = pattern["threshold"]
        group_by = pattern.get("group_by", [])

        # Get events in time window
        window_end = datetime.utcnow()
        window_start = window_end - window

        relevant_events = [
            e for e in self.events
            if self._event_matches_conditions(e, pattern["conditions"]) and
            self._is_in_window(e, window_start, window_end)
        ]

        # Group events
        grouped_events = self._group_events(relevant_events, group_by)

        # Check thresholds
        alerts = []
        for group_key, events in grouped_events.items():
            if len(events) >= threshold:
                alert = self._create_correlation_alert(pattern, group_key, events)
                alerts.append(alert)

        return alerts

    def _event_matches_conditions(
        self, event: Dict[str, Any], conditions: List[Dict[str, Any]]
    ) -> bool:
        """Check if event matches any of the conditions."""
        for condition in conditions:
            if all(event.get(k) == v for k, v in condition.items()):
                return True
        return False

    def _is_in_window(
        self, event: Dict[str, Any], window_start: datetime, window_end: datetime
    ) -> bool:
        """Check if event is in time window."""
        try:
            event_time = datetime.fromisoformat(
                event.get("@timestamp", "").replace("Z", "+00:00")
            )
            return window_start <= event_time <= window_end
        except (ValueError, KeyError):
            return False

    def _group_events(
        self, events: List[Dict[str, Any]], group_by: List[str]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group events by specified fields."""
        grouped = defaultdict(list)

        for event in events:
            key_parts = []
            for field in group_by:
                value = event.get(field, "")
                key_parts.append(str(value))

            group_key = "|".join(key_parts)
            grouped[group_key].append(event)

        return dict(grouped)

    def _create_correlation_alert(
        self, pattern: Dict[str, Any], group_key: str, events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create correlation alert."""
        group_values = group_key.split("|")

        alert = {
            "alert_id": self._generate_alert_id(),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "pattern_name": pattern["name"],
            "pattern_description": pattern["description"],
            "severity": pattern.get("severity", "medium"),
            "event_count": len(events),
            "window": pattern["window"],
            "threshold": pattern["threshold"],
            "group_values": dict(zip(pattern.get("group_by", []), group_values)),
            "sample_events": events[:5],  # Include sample events
            "first_seen": min(
                e.get("@timestamp", "") for e in events
            ),
            "last_seen": max(
                e.get("@timestamp", "") for e in events
            ),
        }

        return alert

    def _parse_time_window(self, window_str: str) -> timedelta:
        """Parse time window string to timedelta."""
        if window_str.endswith("m"):
            minutes = int(window_str[:-1])
            return timedelta(minutes=minutes)
        elif window_str.endswith("h"):
            hours = int(window_str[:-1])
            return timedelta(hours=hours)
        elif window_str.endswith("d"):
            days = int(window_str[:-1])
            return timedelta(days=days)
        else:
            # Default to minutes
            return timedelta(minutes=int(window_str))

    def _generate_alert_id(self) -> str:
        """Generate unique correlation alert ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"CORR-{timestamp}"

    def get_stats(self) -> Dict[str, Any]:
        """Get correlation engine statistics."""
        return {
            "events_in_memory": len(self.events),
            "active_patterns": len(self.patterns),
            "time_windows": len(self.windows),
        }

    def clear_events(self):
        """Clear all stored events."""
        self.events.clear()
        self.windows.clear()