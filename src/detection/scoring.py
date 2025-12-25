"""
Alert scoring and prioritization.
"""

from typing import Dict, Any, List
from datetime import datetime

from src.core.logger import LoggerMixin


class AlertScorer(LoggerMixin):
    """Scores and prioritizes alerts."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.scoring_config = config.get("detection", {}).get("scoring", {})

        # Severity weights
        self.severity_weights = self.scoring_config.get("severity_weights", {
            "low": 1,
            "medium": 3,
            "high": 5,
            "critical": 10,
        })

        # Confidence weights
        self.confidence_weights = self.scoring_config.get("confidence_weights", {
            "low": 0.3,
            "medium": 0.6,
            "high": 0.9,
        })

        # Thresholds
        self.composite_threshold = self.scoring_config.get("composite_threshold", 7.5)
        self.auto_escalate = self.scoring_config.get("auto_escalate", True)

    def calculate_score(self, alert: Dict[str, Any]) -> float:
        """
        Calculate composite score for an alert.

        Args:
            alert: Alert dictionary

        Returns:
            Composite score (0-10)
        """
        base_score = self._calculate_base_score(alert)
        confidence_score = self._calculate_confidence_score(alert)
        recency_score = self._calculate_recency_score(alert)
        context_score = self._calculate_context_score(alert)

        # Weighted composite score
        composite = (
            base_score * 0.4 +
            confidence_score * 0.3 +
            recency_score * 0.2 +
            context_score * 0.1
        )

        return min(composite, 10.0)  # Cap at 10

    def _calculate_base_score(self, alert: Dict[str, Any]) -> float:
        """Calculate base score from severity."""
        severity = alert.get("severity", "medium").lower()
        return self.severity_weights.get(severity, 3.0)

    def _calculate_confidence_score(self, alert: Dict[str, Any]) -> float:
        """Calculate confidence score."""
        confidence = alert.get("confidence", 0.5)

        if confidence >= 0.8:
            level = "high"
        elif confidence >= 0.5:
            level = "medium"
        else:
            level = "low"

        base_weight = self.confidence_weights.get(level, 0.6)
        return base_weight * confidence * 10

    def _calculate_recency_score(self, alert: Dict[str, Any]) -> float:
        """Calculate recency score."""
        try:
            alert_time = datetime.fromisoformat(
                alert.get("timestamp", "").replace("Z", "+00:00")
            )
            now = datetime.utcnow()
            age_hours = (now - alert_time).total_seconds() / 3600

            # Exponential decay: newer alerts get higher scores
            if age_hours <= 1:
                return 10.0
            elif age_hours <= 6:
                return 8.0
            elif age_hours <= 24:
                return 5.0
            else:
                return 2.0

        except (ValueError, KeyError):
            return 5.0  # Default score

    def _calculate_context_score(self, alert: Dict[str, Any]) -> float:
        """Calculate context score based on indicators and metadata."""
        score = 5.0  # Baseline

        # Add points for multiple indicators
        indicators = alert.get("indicators", [])
        if len(indicators) >= 3:
            score += 2.0
        elif len(indicators) >= 1:
            score += 1.0

        # Add points for specific indicator types
        indicator_types = {i.get("type") for i in indicators}
        if "ip" in indicator_types:
            score += 1.0
        if "domain" in indicator_types:
            score += 1.5
        if "hash" in indicator_types:
            score += 2.0

        # Add points for correlation
        if alert.get("pattern_name"):
            score += 2.0

        return min(score, 10.0)

    def should_escalate(self, alert: Dict[str, Any]) -> bool:
        """Determine if alert should be escalated."""
        if not self.auto_escalate:
            return False

        score = alert.get("score", 0)
        severity = alert.get("severity", "")

        # Escalate based on score
        if score >= self.composite_threshold:
            return True

        # Always escalate critical alerts
        if severity == "critical":
            return True

        # Escalate high severity with confidence > 0.8
        if severity == "high" and alert.get("confidence", 0) > 0.8:
            return True

        return False

    def get_priority(self, alert: Dict[str, Any]) -> str:
        """Get priority level for alert."""
        score = alert.get("score", 0)

        if score >= 8.0:
            return "P1-Critical"
        elif score >= 6.0:
            return "P2-High"
        elif score >= 4.0:
            return "P3-Medium"
        else:
            return "P4-Low"

    def compare_alerts(self, alert1: Dict[str, Any], alert2: Dict[str, Any]) -> int:
        """Compare two alerts for sorting (higher score first)."""
        score1 = alert1.get("score", 0)
        score2 = alert2.get("score", 0)

        if score1 > score2:
            return -1
        elif score1 < score2:
            return 1
        else:
            return 0

    def sort_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort alerts by score (highest first)."""
        return sorted(alerts, key=lambda a: a.get("score", 0), reverse=True)

    def filter_alerts(
        self,
        alerts: List[Dict[str, Any]],
        min_score: float = 0,
        min_severity: str = "low",
        max_age_hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """Filter alerts based on criteria."""
        filtered = []

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_severity_level = severity_order.get(min_severity.lower(), 1)

        for alert in alerts:
            # Check score
            if alert.get("score", 0) < min_score:
                continue

            # Check severity
            alert_severity = alert.get("severity", "low").lower()
            if severity_order.get(alert_severity, 1) < min_severity_level:
                continue

            # Check age
            try:
                alert_time = datetime.fromisoformat(
                    alert.get("timestamp", "").replace("Z", "+00:00")
                )
                age_hours = (datetime.utcnow() - alert_time).total_seconds() / 3600
                if age_hours > max_age_hours:
                    continue
            except (ValueError, KeyError):
                pass  # Keep alert if we can't determine age

            filtered.append(alert)

        return filtered