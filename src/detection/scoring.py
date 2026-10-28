"""
Alert risk score (0-100) and priority.

  base by severity      low 20 | medium 45 | high 70 | critical 90
  + threat intel hit    +10 (scaled by IOC confidence)
  + attack chain        +10
  + critical asset      +8   (detection.assets)
  + volume              up to +6 for repeated activity
  x confidence          rules carry 0.6-0.9 confidence

Replaces a 0-10 composite that awarded points for "recency" (every new alert
got the maximum), so scores barely varied and nearly everything escalated.
"""
import math
from typing import Any, Dict

BASE = {"low": 20, "medium": 45, "high": 70, "critical": 90}
ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class AlertScorer:
    def __init__(self, config):
        cfg = ((config.get("detection", {}) or {}).get("scoring", {}) or {})
        self.escalate_at = float(cfg.get("escalate_at", 80))
        self.auto_escalate = bool(cfg.get("auto_escalate", True))

    def calculate_score(self, alert: Dict[str, Any]) -> float:
        score = BASE.get(alert.get("severity", "medium"), 45)
        intel = alert.get("intel") or []
        if intel:
            score += 10 * max(float(i.get("confidence", 0.8)) for i in intel)
        if alert.get("source") == "correlation":
            score += 10
        asset = (alert.get("entity") or {}).get("asset") or {}
        if asset.get("criticality") in ("high", "critical"):
            score += 8
        score += min(6, 2 * math.log10(max(int(alert.get("event_count", 1)), 1)))
        confidence = float(alert.get("confidence", 0.8))
        score *= 0.85 + 0.15 * confidence
        return round(min(score, 100.0), 1)

    def priority(self, score: float) -> str:
        if score >= 85:
            return "P1"
        if score >= 65:
            return "P2"
        if score >= 40:
            return "P3"
        return "P4"

    def should_escalate(self, alert: Dict[str, Any]) -> bool:
        return self.auto_escalate and (alert.get("score", 0) >= self.escalate_at or alert.get("severity") == "critical")

    @staticmethod
    def max_severity(a: str, b: str) -> str:
        return a if ORDER.get(a, 0) >= ORDER.get(b, 0) else b
