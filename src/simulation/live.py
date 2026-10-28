"""
Live simulation: streams generated telemetry into the ingestion pipeline in
real time and keeps a scorecard (which injected attacks were detected, how
fast, and how many alerts were raised on purely normal traffic).
"""
import asyncio
import heapq
import itertools
import time
from typing import Any, Callable, Dict, List, Optional

from src.core.logger import LoggerMixin
from src.core.time_utils import iso
from src.simulation.traffic import SCENARIOS, TrafficGenerator


class LiveSimulator(LoggerMixin):
    def __init__(self, submit: Callable[[Dict[str, Any]], bool], on_change: Optional[Callable] = None):
        self.submit = submit
        self.on_change = on_change
        self.gen = TrafficGenerator()
        self.running = False
        self.rate = 5.0
        self.attack_interval = 45.0  # mean seconds between random attacks
        self._task: Optional[asyncio.Task] = None
        self._queue: List = []
        self._seq = itertools.count()
        self.scenarios: Dict[str, Dict[str, Any]] = {}
        self.false_positive_alerts: set = set()
        self.alerts_on_attacks: set = set()
        self.events_sent = 0

    # ------------------------------------------------------------------ control
    def start(self, rate: float = 5.0, attack_interval: float = 45.0):
        self.rate = max(0.5, min(float(rate), 200.0))
        self.attack_interval = max(5.0, float(attack_interval))
        if not self.running:
            self.running = True
            self._task = asyncio.create_task(self._loop())
            self.logger.info(f"Simulation started: {self.rate} events/s, attack every ~{self.attack_interval}s")

    async def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        self._queue.clear()

    def inject(self, scenario: Optional[str] = None) -> Dict[str, Any]:
        """Schedule one attack scenario now (works whether or not the stream is running)."""
        name, sid, steps = self.gen.attack(scenario)
        now = time.monotonic()
        attacker = next((e.get("src_ip") for _, e in steps), None)
        self.scenarios[sid] = {"id": sid, "scenario": name, "started_at": iso(), "events": len(steps),
                               "entity": attacker, "detected": False, "detected_at": None,
                               "time_to_detect_s": None, "alert_ids": [], "_t0": now}
        for delay, event in steps:
            heapq.heappush(self._queue, (now + delay, next(self._seq), event))
        if not self.running:  # still deliver the scenario
            asyncio.get_running_loop().create_task(self._drain_scheduled())
        self._changed()
        return {k: v for k, v in self.scenarios[sid].items() if not k.startswith("_")}

    # ------------------------------------------------------------------ loop
    async def _loop(self):
        next_attack = time.monotonic() + self.gen.rng.expovariate(1 / self.attack_interval)
        try:
            while self.running:
                tick = 1.0 / self.rate
                now = time.monotonic()
                if now >= next_attack:
                    self.inject()
                    next_attack = now + self.gen.rng.expovariate(1 / self.attack_interval)
                self._send(self.gen.normal_event())
                self._flush_due(now)
                await asyncio.sleep(tick * self.gen.rng.uniform(0.5, 1.5))
        except asyncio.CancelledError:
            pass

    async def _drain_scheduled(self):
        while self._queue and not self.running:
            self._flush_due(time.monotonic())
            await asyncio.sleep(0.1)

    def _flush_due(self, now: float):
        while self._queue and self._queue[0][0] <= now:
            _, _, event = heapq.heappop(self._queue)
            self._send(event)

    def _send(self, event: Dict[str, Any]):
        event["@timestamp"] = iso()
        event["source_type"] = "simulation"
        if self.submit(event):
            self.events_sent += 1

    # ------------------------------------------------------------------ scoring
    def record_alert(self, alert: Dict[str, Any], events: List[Dict[str, Any]]):
        """Called by the detector for every new/updated alert."""
        truths = [e.get("_truth") for e in events if e.get("_truth")]
        if not truths:
            return
        hit_scenarios = {t["scenario_id"] for t in truths if t.get("malicious")}
        if not hit_scenarios:
            self.false_positive_alerts.add(alert["id"])
            self._changed()
            return
        self.alerts_on_attacks.add(alert["id"])
        self.false_positive_alerts.discard(alert["id"])
        for sid in hit_scenarios:
            sc = self.scenarios.get(sid)
            if not sc:
                continue
            if alert["id"] not in sc["alert_ids"]:
                sc["alert_ids"].append(alert["id"])
            if not sc["detected"]:
                sc["detected"] = True
                sc["detected_at"] = iso()
                sc["time_to_detect_s"] = round(time.monotonic() - sc["_t0"], 1)
        self._changed()

    def _changed(self):
        if self.on_change:
            try:
                self.on_change(self.status())
            except Exception:
                pass

    def reset_scorecard(self):
        self.scenarios.clear()
        self.false_positive_alerts.clear()
        self.alerts_on_attacks.clear()

    def status(self) -> Dict[str, Any]:
        items = [{k: v for k, v in s.items() if not k.startswith("_")} for s in self.scenarios.values()]
        finished = [s for s in self.scenarios.values() if time.monotonic() - s["_t0"] > 60 or s["detected"]]
        detected = [s for s in finished if s["detected"]]
        ttd = [s["time_to_detect_s"] for s in detected if s["time_to_detect_s"] is not None]
        by_type: Dict[str, Dict[str, int]] = {}
        for s in finished:
            row = by_type.setdefault(s["scenario"], {"injected": 0, "detected": 0})
            row["injected"] += 1
            row["detected"] += int(s["detected"])
        return {
            "running": self.running, "rate": self.rate, "attack_interval": self.attack_interval,
            "events_sent": self.events_sent, "scenarios_available": list(SCENARIOS),
            "scorecard": {
                "attacks_injected": len(self.scenarios), "attacks_evaluated": len(finished),
                "attacks_detected": len(detected),
                "detection_rate": round(len(detected) / len(finished), 3) if finished else None,
                "mean_time_to_detect_s": round(sum(ttd) / len(ttd), 1) if ttd else None,
                "alerts_on_attacks": len(self.alerts_on_attacks),
                "false_positive_alerts": len(self.false_positive_alerts),
                "by_scenario": by_type,
            },
            "recent": sorted(items, key=lambda s: s["started_at"], reverse=True)[:15],
        }
