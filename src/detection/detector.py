"""
Detection engine: every normalized event goes through

  enrichment -> threat intel -> YAML/Sigma rules -> ML anomaly -> attack chains

and every hit becomes (or updates) an alert. Repeated hits for the same rule
and entity inside the rule's cooldown update one alert (event count, last
seen, samples) instead of creating a flood - one attack, one alert.

Previously: no rule could match, ML returned [], correlation crashed every
cycle, alerts lived in memory only, and each correlation pass re-created the
same alert every second.
"""
import asyncio
import time
import uuid
from collections import deque
from typing import Any, Awaitable, Callable, Dict, List, Optional

from src.core.logger import LoggerMixin, get_logger
from src.core.time_utils import iso, parse_ts, utcnow
from src.detection.correlator import CorrelationEngine
from src.detection.mitre import describe
from src.detection.rules.custom_rules import RuleEngine
from src.detection.scoring import AlertScorer
from src.intel.enrich import EventEnricher

alerts_log = get_logger("alerts")
MAX_SAMPLES = 10
INTEL_SEVERITY = {"hash": "critical", "domain": "high", "url": "high", "ip": "high", "cidr": "high"}
INTEL_MITRE = {"hash": ["T1204"], "domain": ["T1071"], "url": ["T1071"], "ip": ["T1071"], "cidr": ["T1071"]}


def _public(event: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in event.items() if not k.startswith("_")}


class DetectionEngine(LoggerMixin):
    def __init__(self, config, store=None, intel=None, ml=None):
        self.config = config
        self.store = store
        self.intel = intel
        self.ml = ml
        self.rule_engine = RuleEngine(config)
        self.correlation_engine = CorrelationEngine(config)
        self.scorer = AlertScorer(config)
        self.enricher = EventEnricher(config, intel.matcher if intel else None)
        self.listeners: List[Callable[[str, Dict[str, Any], List[Dict[str, Any]]], Awaitable[None]]] = []
        self.event_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._active: Dict[str, Dict[str, Any]] = {}   # dedup key -> {"id", "until"}
        self._pending_events: List[Dict[str, Any]] = []
        self._flagged: List[str] = []
        self._latency = deque(maxlen=2000)
        self._flush_task: Optional[asyncio.Task] = None
        self.running = False
        self.elastic = None
        self.stats = {"events_processed": 0, "alerts_created": 0, "alerts_updated": 0,
                      "hits": {"rule": 0, "sigma": 0, "intel": 0, "ml": 0, "correlation": 0}, "last_alert": None}

    # --------------------------------------------------------------- lifecycle
    async def start(self):
        self.rule_engine.load_rules()
        self.running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self):
        self.running = False
        if self._flush_task:
            self._flush_task.cancel()
        self._flush()

    def add_listener(self, callback):
        """callback(kind, alert, events) with kind in {'created', 'updated'}."""
        self.listeners.append(callback)

    # --------------------------------------------------------------- pipeline
    async def add_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process one normalized event. Returns alerts created or updated by it."""
        started = time.perf_counter()
        self.enricher.enrich(event)
        hits: List[Dict[str, Any]] = []

        intel_hits = self.intel.match_event(event) if self.intel else []
        for ih in intel_hits:
            hits.append(self._intel_hit(event, ih))
        hits.extend(self.rule_engine.evaluate(event))
        if self.ml:
            ml_hit = self.ml.score(event)
            if ml_hit:
                hits.append(ml_hit)
        hits.extend(self.correlation_engine.on_event(event))

        changed = []
        for hit in hits:
            alert = await self._upsert(hit, intel_hits)
            if alert:
                changed.append(alert)

        self.stats["events_processed"] += 1
        if any(changed):
            event["_flagged"] = True
        self._pending_events.append(event)
        for listener in self.event_listeners:
            try:
                listener(event)
            except Exception:
                pass
        self._latency.append((time.perf_counter() - started) * 1000)
        return changed

    def _intel_hit(self, event: Dict[str, Any], ioc: Dict[str, Any]) -> Dict[str, Any]:
        kind = ioc["type"]
        return {
            "rule_id": f"INTEL-{kind.upper()}", "rule_name": f"Known malicious {kind} ({ioc['value']})",
            "description": ioc.get("description") or f"{ioc['field']} matched a threat-intel indicator "
                                                      f"from {ioc.get('source')}",
            "severity": INTEL_SEVERITY.get(kind, "high"), "category": "threat_intel",
            "mitre": INTEL_MITRE.get(kind, []), "confidence": float(ioc.get("confidence", 0.8)),
            "response": ["block_ip"] if kind in ("ip", "cidr") and ioc["field"] == "src_ip" else [],
            "source": "intel", "cooldown": 1800.0, "references": [],
            "group": {"ioc": ioc["value"], "hostname": event.get("hostname")},
            "group_key": f"{ioc['value']}|{event.get('hostname')}", "count": 1, "events": [event],
            "evidence": {"ioc": {k: ioc.get(k) for k in ("type", "value", "source", "confidence", "field")}},
        }

    async def _upsert(self, hit: Dict[str, Any], intel_hits: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        self.stats["hits"][hit.get("source", "rule")] = self.stats["hits"].get(hit.get("source", "rule"), 0) + 1
        key = f"{hit['rule_id']}|{hit['group_key']}"
        now = time.monotonic()
        events = hit.get("events") or []
        last_event = events[-1] if events else {}
        active = self._active.get(key)
        alert = None
        if active and active["until"] > now:
            alert = self.store.get_alert(active["id"]) if self.store else active.get("alert")
            if alert and alert.get("status") in ("resolved", "false_positive"):
                alert = None

        if alert:  # aggregate into the existing alert
            alert["event_count"] = int(alert.get("event_count", 1)) + 1
            alert["last_seen"] = last_event.get("@timestamp", iso())
            alert["updated_at"] = iso()
            alert["severity"] = self.scorer.max_severity(alert["severity"], hit["severity"])
            known = set(alert.get("event_ids", []))
            for e in events:
                if e.get("event_id") not in known and len(alert["sample_events"]) < MAX_SAMPLES:
                    alert["sample_events"].append(_public(e))
                    alert["event_ids"].append(e.get("event_id"))
            alert["evidence"] = {**alert.get("evidence", {}), **hit.get("evidence", {})}
            self._score(alert)
            self._active[key]["until"] = now + hit.get("cooldown", 600)
            kind = "updated"
            self.stats["alerts_updated"] += 1
        else:
            first = events[0] if events else {}
            entity = {k: first.get(k) for k in ("src_ip", "dst_ip", "user", "hostname") if first.get(k)}
            if first.get("asset"):
                entity["asset"] = first["asset"]
            alert = {
                "id": "ALR-" + uuid.uuid4().hex[:10], "created_at": iso(), "updated_at": iso(),
                "first_seen": first.get("@timestamp", iso()), "last_seen": last_event.get("@timestamp", iso()),
                "rule_id": hit["rule_id"], "rule_name": hit["rule_name"], "description": hit.get("description", ""),
                "severity": hit["severity"], "category": hit.get("category"), "source": hit.get("source", "rule"),
                "confidence": hit.get("confidence", 0.8), "mitre": describe(hit.get("mitre")),
                "references": hit.get("references", []), "entity": entity, "group": hit.get("group", {}),
                "event_count": int(hit.get("count", 1)),
                "sample_events": [_public(e) for e in events[-MAX_SAMPLES:]],
                "event_ids": [e.get("event_id") for e in events[-MAX_SAMPLES:]],
                "evidence": hit.get("evidence", {}),
                "intel": [{k: i.get(k) for k in ("type", "value", "source", "confidence", "field", "description")}
                          for i in intel_hits],
                "status": "new", "assignee": None, "notes": [],
                "suggested_playbooks": hit.get("response", []), "response_ids": [],
            }
            self._score(alert)
            self._active[key] = {"id": alert["id"], "until": now + hit.get("cooldown", 600), "alert": alert}
            kind = "created"
            self.stats["alerts_created"] += 1
            self.stats["last_alert"] = alert["created_at"]
            alerts_log.info(alert["rule_name"], extra={"data": {
                "alert_id": alert["id"], "severity": alert["severity"], "score": alert["score"],
                "rule_id": alert["rule_id"], "entity": entity}})

        self._flagged.extend(e.get("event_id") for e in events)
        if self.store:
            self.store.save_alert(alert)
        if self.elastic:
            await self.elastic.index_alert(alert)
        for listener in self.listeners:
            try:
                await listener(kind, alert, events)
            except Exception as e:
                self.logger.error(f"Alert listener failed: {e}", exc_info=True)

        if kind == "created":
            for chain_hit in self.correlation_engine.on_alert(alert):
                await self._upsert(chain_hit, [])
        return alert

    def _score(self, alert: Dict[str, Any]):
        alert["score"] = self.scorer.calculate_score(alert)
        alert["priority"] = self.scorer.priority(alert["score"])
        alert["escalated"] = self.scorer.should_escalate(alert)

    # --------------------------------------------------------------- storage
    async def _flush_loop(self):
        while self.running:
            await asyncio.sleep(0.5)
            pending = self._flush()
            if self.elastic and pending:
                await self.elastic.index_events(pending)
            if int(time.monotonic()) % 60 == 0:
                self.rule_engine.prune()
                self._active = {k: v for k, v in self._active.items() if v["until"] > time.monotonic()}

    def _flush(self) -> List[Dict[str, Any]]:
        pending, self._pending_events = self._pending_events, []
        flagged, self._flagged = self._flagged, []
        if self.store:
            try:
                self.store.add_events(pending)
                self.store.mark_flagged(f for f in flagged if f)
            except Exception as e:
                self.logger.error(f"Event storage failed: {e}")
        return pending

    # --------------------------------------------------------------- queries
    def get_stats(self) -> Dict[str, Any]:
        lat = sorted(self._latency)
        pct = (lambda q: round(lat[min(int(q * len(lat)), len(lat) - 1)], 3)) if lat else (lambda q: None)
        return {"running": self.running, **self.stats,
                "latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99)},
                "rule_engine": self.rule_engine.get_stats(),
                "correlation_engine": self.correlation_engine.get_stats()}


def event_age_seconds(event: Dict[str, Any]) -> float:
    ts = parse_ts(event.get("@timestamp"))
    return (utcnow() - ts).total_seconds() if ts else 0.0
