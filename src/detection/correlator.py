"""
Attack-chain correlation: multi-stage detections across alerts and events.

  chains:
    - id: CHAIN-001
      name: Successful login after brute force
      first: {category: brute_force}            # an alert ...
      then_event: {event_type: ssh_accepted}    # ... followed by an event, or
      # then_alert: {category: [web_attack]}    # ... followed by another alert
      key: src_ip                               # same attacker / host
      window: 30m
      severity: critical
      mitre: [T1110, T1078]

The old correlator compared timezone-aware event times with naive
datetime.utcnow() (TypeError on every run, so it never fired), counted
port-scan *events* instead of distinct ports, and re-raised the same
correlation alert every second with an ID that collided within a second.
"""
from typing import Any, Dict, List, Optional

from src.core.logger import LoggerMixin
from src.core.time_utils import parse_ts, parse_window, utcnow
from src.detection.rules.matcher import compile_mapping


class Chain:
    def __init__(self, spec: Dict[str, Any]):
        self.id = spec["id"]
        self.name = spec.get("name", self.id)
        self.description = spec.get("description", "")
        self.first = compile_mapping(spec.get("first"))
        self.then_event = compile_mapping(spec["then_event"]) if spec.get("then_event") else None
        self.then_alert = compile_mapping(spec["then_alert"]) if spec.get("then_alert") else None
        self.key = spec.get("key", "src_ip")
        self.window = parse_window(spec.get("window", "30m"))
        self.severity = spec.get("severity", "critical")
        self.mitre = list(spec.get("mitre", []) or [])
        self.response = list(spec.get("response", []) or [])
        self.first_seen: Dict[str, Dict[str, Any]] = {}  # key value -> first-stage alert summary
        self.hits = 0

    def hit(self, key_value: str, first: Dict[str, Any], second: Dict[str, Any],
            events: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.hits += 1
        return {
            "rule_id": self.id, "rule_name": self.name, "description": self.description,
            "severity": self.severity, "category": "attack_chain", "mitre": self.mitre, "confidence": 0.9,
            "response": self.response, "source": "correlation", "cooldown": self.window, "references": [],
            "group": {self.key: key_value}, "group_key": str(key_value), "count": 1, "events": events,
            "evidence": {"stages": [first, second], "window_seconds": self.window},
        }


class CorrelationEngine(LoggerMixin):
    def __init__(self, config):
        cfg = ((config.get("detection", {}) or {}).get("correlation", {}) or {})
        self.enabled = bool(cfg.get("enabled", True))
        self.chains: List[Chain] = []
        for spec in cfg.get("chains", []) or []:
            try:
                self.chains.append(Chain(spec))
            except Exception as e:
                self.logger.warning(f"Invalid correlation chain {spec.get('id')}: {e}")

    @staticmethod
    def _alert_view(alert: Dict[str, Any]) -> Dict[str, Any]:
        entity = alert.get("entity") or {}
        return {"alert_id": alert["id"], "rule_id": alert.get("rule_id"), "rule_name": alert.get("rule_name"),
                "category": alert.get("category"), "severity": alert.get("severity"), "source": alert.get("source"),
                "at": alert.get("last_seen") or alert.get("created_at"), **entity}

    def _fresh(self, chain: Chain, key_value: str, at: Any = None) -> Optional[Dict[str, Any]]:
        """First stage for this key, if the second stage (at `at`, event time) falls inside the window.
        Event time - not wall-clock time - so imported/replayed logs correlate correctly."""
        first = chain.first_seen.get(key_value)
        if not first:
            return None
        first_ts = parse_ts(first.get("at"))
        second_ts = parse_ts(at) or utcnow()
        if first_ts and (second_ts - first_ts).total_seconds() > chain.window:
            del chain.first_seen[key_value]
            return None
        return first

    def on_alert(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.enabled or alert.get("source") == "correlation":
            return []
        view = self._alert_view(alert)
        hits = []
        for chain in self.chains:
            key_value = view.get(chain.key)
            if not key_value:
                continue
            if chain.then_alert and chain.then_alert(view):
                first = self._fresh(chain, str(key_value), view.get("at"))
                if first and first["alert_id"] != view["alert_id"]:
                    hits.append(chain.hit(str(key_value), first, view, alert.get("sample_events", [])[:3]))
            if chain.first(view):
                chain.first_seen[str(key_value)] = view
        return hits

    def on_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []
        hits = []
        for chain in self.chains:
            if not chain.then_event:
                continue
            key_value = event.get(chain.key)
            if not key_value or not chain.then_event(event):
                continue
            first = self._fresh(chain, str(key_value), event.get("@timestamp"))
            if first:
                second = {"event_id": event.get("event_id"), "event_type": event.get("event_type"),
                          "at": event.get("@timestamp"), "user": event.get("user")}
                hits.append(chain.hit(str(key_value), first, second, [event]))
        return hits

    def get_stats(self) -> Dict[str, Any]:
        return {"enabled": self.enabled, "chains": [{"id": c.id, "name": c.name, "hits": c.hits,
                                                     "tracking": len(c.first_seen)} for c in self.chains]}
