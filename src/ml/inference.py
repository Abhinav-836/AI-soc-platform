"""
Live ML scoring.

Before: the detector's `_apply_ml_detection` was a TODO that returned [], so
none of the ML code ever ran. Now every event is scored against the learned
behavioural baseline; anomalous events become "ML anomaly" hits with the
features that made them unusual.

If no trained model exists, one is trained in the background on simulated
normal traffic (a few seconds) and hot-swapped in; rules keep working
meanwhile. Note that log-scaled features are shown as log values.
"""
import asyncio
import threading
from typing import Any, Dict, List, Optional

from src.core.logger import LoggerMixin, audit
from src.core.time_utils import iso
from src.ml.anomaly.baseline import BaselineAnomalyDetector
from src.ml.drift_monitor import DriftMonitor
from src.ml.features import FeatureExtractor, peer_group
from src.ml.training import ModelTrainer, model_path

FRIENDLY = {
    "src_events_5m_log": "event volume from this source (5 min)",
    "src_failures_5m_log": "failed/blocked events from this source (log)",
    "src_distinct_ports_5m_log": "distinct destination ports from this source",
    "src_distinct_dsts_5m_log": "distinct destinations from this source",
    "src_bytes_out_5m_log": "bytes sent by this source (5 min)",
    "src_distinct_users_5m_log": "distinct user names tried from this source",
    "src_distinct_queries_5m_log": "distinct DNS names queried by this source",
    "bytes_out_log": "bytes sent in this connection",
    "bytes_in_log": "bytes received in this connection",
    "query_len": "DNS name length",
    "query_label_max": "longest DNS label",
    "dst_port_rare": "uncommon destination port",
    "url_len": "URL length",
}


class MLInferenceEngine(LoggerMixin):
    def __init__(self, config):
        ml = (config.get("ml", {}) or {})
        self.config = config
        self.enabled = bool((ml.get("model", {}) or {}).get("enabled", True))
        self.high_severity_excess = float((ml.get("model", {}) or {}).get("high_severity_excess", 6.0))
        # The default baseline is learned from simulated network traffic; a real PC's own
        # connections look different, so host-monitor events are not scored until you
        # retrain on your recent events (which then includes them).
        self.skip_sources = set((ml.get("model", {}) or {}).get("skip_sources", ["host"]))
        self.detector: Optional[BaselineAnomalyDetector] = None
        self.extractor = FeatureExtractor()
        self.drift = DriftMonitor()
        self.training = False
        self.last_error: Optional[str] = None
        self.stats = {"inferences": 0, "anomalies": 0, "last_anomaly": None}
        self._lock = threading.Lock()

    # ------------------------------------------------------------ lifecycle
    def load(self) -> bool:
        path = model_path()
        if path.exists():
            try:
                self.detector = BaselineAnomalyDetector.load(path)
                self.logger.info(f"ML model loaded ({self.detector.metadata.get('samples')} training events)")
                return True
            except Exception as e:  # incompatible sklearn version etc.
                self.last_error = f"could not load model: {e}"
                self.logger.warning(self.last_error)
        return False

    async def start(self):
        if not self.enabled:
            return
        if not self.load():
            await self.retrain()

    async def retrain(self, path: Optional[str] = None, events: Optional[List[Dict[str, Any]]] = None):
        """Train in a worker thread, then swap the model in atomically."""
        if self.training:
            return {"status": "already_training"}
        self.training = True
        self.last_error = None
        loop = asyncio.get_running_loop()

        def job():
            trainer = ModelTrainer(self.config)
            if events:
                detector = trainer.train(events, save=False)
                detector.metadata["evaluation"] = trainer.evaluate(detector)
                detector.metadata["trained_on"] = f"{len(events)} recent stored events"
                detector.save(model_path())
                return detector
            trainer.train_and_evaluate(path)
            return BaselineAnomalyDetector.load(model_path())

        try:
            detector = await loop.run_in_executor(None, job)
            with self._lock:
                self.detector = detector
                self.drift = DriftMonitor()
            audit("ml_retrained", samples=detector.metadata.get("samples"),
                  evaluation=detector.metadata.get("evaluation"))
            self.logger.info(f"ML model ready: {detector.metadata.get('evaluation')}")
            return {"status": "trained", **detector.metadata}
        except Exception as e:
            self.last_error = str(e)
            self.logger.error(f"ML training failed: {e}", exc_info=True)
            return {"status": "failed", "error": str(e)}
        finally:
            self.training = False

    # ------------------------------------------------------------ scoring
    def score(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Returns an ML hit for anomalous events, else None. Always updates context features."""
        if not self.enabled:
            return None
        detector = self.detector
        if event.get("source_type") in self.skip_sources and not (
                detector and "recent" in str(detector.metadata.get("trained_on", ""))):
            return None
        vec = self.extractor.transform(event)
        if detector is None:
            return None
        group = peer_group(event)
        score = float(detector.score([vec], [group])[0])
        self.stats["inferences"] += 1
        self.drift.add(score)
        event["_ml_score"] = round(score, 3)
        if score <= detector.margin:
            return None
        self.stats["anomalies"] += 1
        self.stats["last_anomaly"] = iso()
        reasons = detector.explain(vec, group)
        for r in reasons:
            r["text"] = f"{FRIENDLY.get(r['feature'], r['feature'])}: {r['value']} (normal max {r['normal_max']})"
        severity = "high" if score >= self.high_severity_excess else "medium"
        return {
            "rule_id": "ML-ANOMALY", "rule_name": "Anomalous behaviour (ML)",
            "description": "This source is behaving far outside its learned normal baseline.",
            "severity": severity, "category": "anomaly", "mitre": [], "confidence": 0.6,
            "response": [], "source": "ml", "cooldown": 900.0, "references": [],
            "group": {"src_ip": event.get("src_ip")}, "group_key": str(event.get("src_ip")),
            "count": 1, "events": [event],
            "evidence": {"anomaly_score": round(score, 2), "threshold": detector.margin, "peer_group": group,
                         "reasons": reasons},
        }

    def get_status(self) -> Dict[str, Any]:
        d = self.detector
        return {
            "enabled": self.enabled, "ready": d is not None, "training": self.training,
            "last_error": self.last_error, **self.stats,
            "model": d.metadata if d else None,
            "drift": self.drift.status(d.reference_hist, d.bin_edges) if d else None,
        }
