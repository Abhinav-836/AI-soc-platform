#!/usr/bin/env python3
"""
AI SOC Platform - orchestrator and command line.

    python run.py                        # API + dashboard on http://127.0.0.1:8080
    python run.py --simulate             # ... and start the traffic/attack simulator
    python run.py analyze data/raw/x.log # one-shot: run detection over a file, print alerts
    python run.py train                  # (re)train the ML model

Previously there were two orchestrators: src/main.py (no API, and it called
asyncio.run() three times on one platform object, so its "oneshot"/"test"
modes crashed) and src/api/app.py (wired ingestion -> detection but never
created threat intel, ML, storage or metrics). Everything is wired here once.
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

if __package__ in (None, ""):  # allow `python src/main.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.api.websocket_manager import WebSocketManager
from src.core.config_loader import ConfigLoader
from src.core.logger import LoggerMixin, setup_logging
from src.core.paths import data_dir, writable
from src.core.time_utils import iso
from src.detection.detector import DetectionEngine
from src.ingestion.pipeline import IngestionPipeline
from src.intel.feeds import ThreatIntelManager
from src.ml.inference import MLInferenceEngine
from src.monitoring.health import component_health
from src.response.executor import ResponseExecutor
from src.simulation.live import LiveSimulator
from src.storage.elastic import ElasticsearchStorage
from src.storage.local_store import SOCStore, since_minutes

VERSION = "2.0.0"


class SOCPlatform(LoggerMixin):
    def __init__(self, config_dir: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None,
                 db_path: Optional[str] = None):
        self.config = ConfigLoader(config_dir, overrides)
        storage = self.config.get("storage", {}) or {}
        sqlite_cfg = storage.get("sqlite", {}) or {}
        self.store = SOCStore(db_path or writable(sqlite_cfg.get("path", "data/soc.db")),
                              max_events=int(sqlite_cfg.get("max_events", 50000)))
        self.elastic = ElasticsearchStorage(self.config)
        self.intel = ThreatIntelManager(self.config, self.store)
        self.ml = MLInferenceEngine(self.config)
        self.detection = DetectionEngine(self.config, self.store, self.intel, self.ml)
        self.detection.elastic = self.elastic
        self.response = ResponseExecutor(self.config, self.store, self.intel)
        self.ingestion = IngestionPipeline(self.config, self.detection.add_event)
        self.ws = WebSocketManager()
        self.simulator = LiveSimulator(self.ingestion.submit, on_change=self._sim_changed)
        self.started_at = None
        self._tasks = []

        self.detection.add_listener(self._on_alert)
        self.detection.add_listener(self.response.on_alert)
        self.detection.event_listeners.append(self._on_event)
        self.response.add_listener(self._on_response)

    # ------------------------------------------------------------ lifecycle
    async def start(self, simulate: Optional[bool] = None):
        self.started_at = iso()
        self.intel.load()
        await self.elastic.connect()
        await self.intel.start()
        await self.detection.start()
        await self.response.start()
        await self.ingestion.start()
        self._tasks.append(asyncio.create_task(self.ml.start()))
        self._tasks.append(asyncio.create_task(self._stats_loop()))
        sim = self.config.get("app", {}).get("simulation", {}) or {}
        if simulate if simulate is not None else str(sim.get("autostart", "false")).lower() == "true":
            self.simulator.start(float(sim.get("rate", 5)), float(sim.get("attack_interval", 45)))
        self.logger.info(f"AI SOC Platform {VERSION} started (data: {data_dir()}, response mode: {self.response.mode})")

    async def stop(self):
        await self.simulator.stop()
        await self.ingestion.stop()
        await self.detection.stop()
        await self.response.stop()
        await self.intel.stop()
        await self.ws.stop()
        await self.elastic.close()
        for task in self._tasks:
            task.cancel()
        self.store.close()

    # ------------------------------------------------------------ live updates
    async def _on_alert(self, kind: str, alert: Dict[str, Any], events):
        self.simulator.record_alert(alert, events)
        self.ws.broadcast({"type": "alert" if kind == "created" else "alert_update", "alert": alert}, "alert")

    def _on_event(self, event: Dict[str, Any]):
        if self.ws.clients:
            public = {k: v for k, v in event.items() if not k.startswith("_") and k != "raw_message"}
            public["flagged"] = bool(event.get("_flagged"))
            self.ws.broadcast({"type": "event", "event": public}, "event")

    async def _on_response(self, item: Dict[str, Any]):
        self.ws.broadcast({"type": "response", "response": item}, "response")

    def _sim_changed(self, status: Dict[str, Any]):
        self.ws.broadcast({"type": "simulation", "simulation": status}, "simulation")

    async def _stats_loop(self):
        while True:
            await asyncio.sleep(2)
            if self.ws.clients:
                self.ws.broadcast({"type": "stats", "stats": self.stats(light=True)}, "stats")

    # ------------------------------------------------------------ queries
    def stats(self, light: bool = False) -> Dict[str, Any]:
        out = {
            "version": VERSION, "started_at": self.started_at, "timestamp": iso(),
            "ingestion": self.ingestion.get_stats(), "detection": self.detection.get_stats(),
            "alerts": self.store.alert_stats(), "response": self.response.get_stats(),
            "ml": self.ml.get_status(), "intel": self.intel.get_stats(), "websocket": self.ws.get_stats(),
            "simulation": self.simulator.status(), "blocked_ips": len(self.store.list_blocks()),
        }
        out["events_by_type_1h"] = self.store.event_counts(since_minutes(60))
        out["events_by_source_1h"] = self.store.event_counts(since_minutes(60), by="source")
        out["event_volume"] = self.store.event_volume(since_minutes(60))
        out["alert_timeline"] = self.store.alert_timeline(since_minutes(60))
        if not light:
            out["elasticsearch"] = self.elastic.get_stats()
            out["health"] = component_health(self)
        return out


# ---------------------------------------------------------------- CLI
async def analyze_file(path: str, config_dir: Optional[str] = None) -> Dict[str, Any]:
    """Run the full detection stack over a log file (JSONL, syslog, CEF, access logs)."""
    platform = SOCPlatform(config_dir, db_path=":memory:", overrides={"response": {"mode": "dry_run"}})
    platform.intel.load()
    platform.ml.load()
    await platform.detection.start()
    platform.response.load_playbooks()
    count = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line) if line.startswith("{") else {"raw_message": line, "source_type": "file"}
            await platform.ingestion.process(raw)
            count += 1
    await platform.detection.stop()
    alerts = platform.store.list_alerts(limit=1000)["alerts"]
    return {"events": count, "alerts": alerts}


def main():
    parser = argparse.ArgumentParser(description="AI SOC Platform")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="run API + dashboard (default)")
    for p in (parser, serve):
        p.add_argument("--config", "-c", default=None, help="config directory (default: ./config)")
        p.add_argument("--host", default=None)
        p.add_argument("--port", "-p", type=int, default=None)
        p.add_argument("--simulate", action="store_true", help="start the traffic/attack simulator")
    analyze = sub.add_parser("analyze", help="detect over a log file and print the alerts")
    analyze.add_argument("file")
    analyze.add_argument("--config", "-c", default=None)
    analyze.add_argument("--json", action="store_true", help="print alerts as JSON")
    train = sub.add_parser("train", help="train the ML anomaly model")
    train.add_argument("--input", help="JSONL/log file of (mostly) normal events; default: simulated traffic")
    train.add_argument("--config", "-c", default=None)
    args = parser.parse_args()
    setup_logging()

    if args.command == "analyze":
        result = asyncio.run(analyze_file(args.file, args.config))
        if args.json:
            print(json.dumps(result["alerts"], indent=2, default=str))
        else:
            print(f"\n{result['events']} events -> {len(result['alerts'])} alerts\n")
            for a in sorted(result["alerts"], key=lambda a: -a["score"]):
                ent = ", ".join(f"{k}={v}" for k, v in a["entity"].items() if isinstance(v, str))
                print(f"  [{a['severity'].upper():8}] {a['score']:5.1f}  {a['rule_name']}  ({ent}) "
                      f"x{a['event_count']}")
        return
    if args.command == "train":
        from src.ml.training import ModelTrainer
        meta = ModelTrainer(ConfigLoader(args.config)).train_and_evaluate(args.input)
        print(json.dumps(meta, indent=2, default=str))
        return

    from src.api.app import serve as run_server
    run_server(config_dir=args.config, host=args.host, port=args.port, simulate=args.simulate)


if __name__ == "__main__":
    main()
