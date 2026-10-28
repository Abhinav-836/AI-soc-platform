"""
YAML rule engine.

Rule format (config/rules/*.yaml or detection.yaml -> rules.custom.rules):

  - id: SOC-001
    name: SSH brute force
    severity: high               # low | medium | high | critical
    category: brute_force
    mitre: [T1110.001]
    match:                       # all conditions (see matcher.py for modifiers)
      event_type: [ssh_failed, rdp_failed]
    match_any:                   # optional: at least one of these mappings
      - {url|contains: "union select"}
    exclude:                     # optional: skip events matching ALL of these
      src_ip|private: true
    threshold:                   # optional: stateful aggregation
      count: 5                   # fire at >= 5 matching events ...
      window: 5m                 # ... within 5 minutes (event time)
      group_by: [src_ip]         # ... from the same source
      distinct: dst_port         # (optional) count distinct values instead
      sum: bytes_out             # (optional) sum a field; fires at >= `value`
      value: 100000000
    cooldown: 10m                # repeat hits update the existing alert
    response: [block_ip]         # playbooks suggested / auto-run for this rule

Why this replaced the old engine: it split a condition at the first "==" and
compared the event type with the rest of the string
('"ssh_failed" AND count_events(...) > 5'), which can never be equal, so no
rule had ever fired.
"""
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

import yaml

from src.core.logger import LoggerMixin
from src.core.paths import data_dir, resolve
from src.core.time_utils import parse_ts, parse_window, utcnow
from src.detection.rules.matcher import compile_any, compile_mapping

SEVERITIES = ("low", "medium", "high", "critical")
MAX_SAMPLES = 10


class Rule:
    source = "rule"

    def __init__(self, spec: Dict[str, Any]):
        self.id = str(spec["id"])
        self.name = spec.get("name", self.id)
        self.description = spec.get("description", "")
        self.severity = str(spec.get("severity", "medium")).lower()
        if self.severity not in SEVERITIES:
            raise ValueError(f"{self.id}: severity must be one of {SEVERITIES}")
        self.category = spec.get("category", "uncategorized")
        self.mitre = list(spec.get("mitre", []) or [])
        self.enabled = bool(spec.get("enabled", True))
        self.confidence = float(spec.get("confidence", 0.8))
        self.response = list(spec.get("response", []) or [])
        self.cooldown = parse_window(spec.get("cooldown", "10m"))
        self.references = list(spec.get("references", []) or [])

        self._match = compile_mapping(spec.get("match"))
        self._any = compile_any(spec.get("match_any"))
        exclude = spec.get("exclude")
        excludes = exclude if isinstance(exclude, list) else ([exclude] if exclude else [])
        self._exclude = compile_any(excludes)

        th = spec.get("threshold")
        self.threshold = dict(th) if th else None
        self.group_by: List[str] = list((th or {}).get("group_by") or spec.get("group_by") or ["src_ip"])
        if th:
            self.window = parse_window(th.get("window", "5m"))
            self.distinct = th.get("distinct")
            self.sum_field = th.get("sum")
            self.limit = float(th.get("value", th.get("count", 1)))
            self._state: Dict[str, Deque[Tuple[float, Any, Dict[str, Any]]]] = defaultdict(deque)
        self.hits = 0

    def meta(self) -> Dict[str, Any]:
        return {"rule_id": self.id, "rule_name": self.name, "description": self.description,
                "severity": self.severity, "category": self.category, "mitre": self.mitre,
                "confidence": self.confidence, "response": self.response, "source": self.source,
                "cooldown": self.cooldown, "references": self.references}

    def summary(self) -> Dict[str, Any]:
        out = {k: v for k, v in self.meta().items() if k not in ("cooldown",)}
        out.update(enabled=self.enabled, hits=self.hits, threshold=self.threshold, group_by=self.group_by)
        return out

    def matches(self, event: Dict[str, Any]) -> bool:
        if not self._match(event):
            return False
        if self._any and not self._any(event):
            return False
        if self._exclude and self._exclude(event):
            return False
        return True

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled or not self.matches(event):
            return None
        group = {f: event.get(f) for f in self.group_by}
        group_key = "|".join(str(v) for v in group.values())

        if not self.threshold:
            self.hits += 1
            return {**self.meta(), "group": group, "group_key": group_key, "count": 1,
                    "events": [event], "evidence": {"matched": _matched_fields(event)}}

        ts = (parse_ts(event.get("@timestamp")) or utcnow()).timestamp()
        window = self._state[group_key]
        value = event.get(self.distinct) if self.distinct else event.get(self.sum_field) if self.sum_field else 1
        if window and ts < window[-1][0]:  # out-of-order event: keep the deque sorted
            items = sorted([*window, (ts, value, event)], key=lambda x: x[0])
            window.clear()
            window.extend(items)
        else:
            window.append((ts, value, event))
        newest = window[-1][0]
        while window and window[0][0] < newest - self.window:
            window.popleft()

        if self.distinct:
            metric = len({v for _, v, _ in window if v is not None})
        elif self.sum_field:
            metric = sum(float(v or 0) for _, v, _ in window)
        else:
            metric = len(window)
        if metric < self.limit:
            return None

        self.hits += 1
        samples = [e for _, _, e in list(window)[-MAX_SAMPLES:]]
        evidence = {"window_seconds": self.window, "events_in_window": len(window),
                    "threshold": self.limit, "observed": round(metric, 2)}
        if self.distinct:
            evidence["distinct_field"] = self.distinct
            evidence["distinct_values"] = sorted({str(v) for _, v, _ in window if v is not None})[:25]
        if self.sum_field:
            evidence["sum_field"] = self.sum_field
        return {**self.meta(), "group": group, "group_key": group_key, "count": len(window),
                "events": samples, "evidence": evidence}

    def prune(self, now: float):
        if not self.threshold:
            return
        for key in [k for k, w in self._state.items() if not w or w[-1][0] < now - self.window * 2]:
            del self._state[key]


def _matched_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("event_type", "src_ip", "dst_ip", "dst_port", "user", "hostname", "process_name", "command_line",
            "url", "query", "file_hash")
    return {k: event[k] for k in keys if event.get(k) not in (None, "")}


class RuleEngine(LoggerMixin):
    def __init__(self, config):
        self.config = config
        self.rules: List[Any] = []
        self.stats = {"rules_loaded": 0, "rules_failed": 0, "events_evaluated": 0, "load_errors": []}

    def rule_dirs(self) -> List[Path]:
        cfg = ((self.config.get("detection", {}) or {}).get("rules", {}) or {})
        dirs = [resolve(p) for p in (cfg.get("paths") or ["config/rules"])]
        dirs.append(data_dir() / "rules")  # user rules, survive app updates
        return dirs

    def load_rules(self):
        self.rules.clear()
        self.stats.update(rules_loaded=0, rules_failed=0, load_errors=[])
        cfg = ((self.config.get("detection", {}) or {}).get("rules", {}) or {})
        specs: List[Dict[str, Any]] = []
        if (cfg.get("custom") or {}).get("enabled", True):
            specs.extend((cfg.get("custom") or {}).get("rules") or [])
            for directory in self.rule_dirs():
                for path in sorted(directory.glob("*.y*ml")) if directory.is_dir() else []:
                    try:
                        data = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or []
                        specs.extend(data.get("rules", []) if isinstance(data, dict) else data)
                    except Exception as e:
                        self._fail(f"{path.name}: {e}")

        seen = set()
        for spec in specs:
            try:
                rule = Rule(spec)
                if rule.id in seen:
                    continue
                seen.add(rule.id)
                self.rules.append(rule)
                self.stats["rules_loaded"] += 1
            except Exception as e:
                self._fail(f"{spec.get('id', '?') if isinstance(spec, dict) else spec}: {e}")

        if (cfg.get("sigma") or {}).get("enabled", True):
            from src.detection.rules.sigma_parser import load_sigma_rules
            sigma_dirs = [resolve(p) for p in ((cfg.get("sigma") or {}).get("paths") or ["config/rules/sigma"])]
            sigma_dirs.append(data_dir() / "rules" / "sigma")
            rules, errors = load_sigma_rules(sigma_dirs)
            for rule in rules:
                if rule.id not in seen:
                    seen.add(rule.id)
                    self.rules.append(rule)
                    self.stats["rules_loaded"] += 1
            for error in errors:
                self._fail(error)
        self.logger.info(f"Loaded {self.stats['rules_loaded']} detection rules ({self.stats['rules_failed']} failed)")

    def _fail(self, message: str):
        self.stats["rules_failed"] += 1
        self.stats["load_errors"].append(message)
        self.logger.warning(f"Rule load error: {message}")

    def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.stats["events_evaluated"] += 1
        hits = []
        for rule in self.rules:
            try:
                hit = rule.evaluate(event)
            except Exception as e:  # a broken rule must not stop the others
                self.logger.debug(f"Rule {rule.id} failed: {e}")
                continue
            if hit:
                hits.append(hit)
        return hits

    def prune(self):
        now = utcnow().timestamp()
        for rule in self.rules:
            if hasattr(rule, "prune"):
                rule.prune(now)

    def get_rule(self, rule_id: str):
        return next((r for r in self.rules if r.id == rule_id), None)

    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = enabled
        return bool(rule)

    def get_rules_summary(self) -> List[Dict[str, Any]]:
        return [r.summary() for r in self.rules]

    def get_stats(self) -> Dict[str, Any]:
        return {"total_rules": len(self.rules), "enabled_rules": sum(1 for r in self.rules if r.enabled),
                "rules_loaded": self.stats["rules_loaded"], "rules_failed": self.stats["rules_failed"],
                "events_evaluated": self.stats["events_evaluated"], "load_errors": self.stats["load_errors"][-10:]}
