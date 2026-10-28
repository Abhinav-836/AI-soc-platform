"""
Model training and evaluation (behavioural baseline, see ml/anomaly/baseline.py).

  train_baseline()  fit on simulated normal traffic (default) or on a JSONL log
                    file you trust to be mostly normal
  evaluate()        replay a labelled mixed dataset (normal + injected attacks)
                    and report event-level precision/recall and the share of
                    attack scenarios with at least one anomalous event

Run from the command line:  python scripts/train_models.py [--input logs.jsonl]
"""
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import numpy as np

from src.core.logger import LoggerMixin
from src.core.paths import data_path
from src.ingestion.parsers.normalizer import LogNormalizer
from src.ml.anomaly.baseline import BaselineAnomalyDetector
from src.ml.features import FEATURES, FeatureExtractor, peer_group

MODEL_FILE = "baseline_model.joblib"


def model_path() -> Path:
    return data_path("models", MODEL_FILE)


def _normalized(events: Iterable[Dict[str, Any]], config) -> List[Dict[str, Any]]:
    normalizer = LogNormalizer(config or {})
    out = [normalizer.normalize_sync(e) for e in events]
    out = [e for e in out if e]
    out.sort(key=lambda e: e["@timestamp"])
    return out


def featurize(events: List[Dict[str, Any]]):
    fx = FeatureExtractor()
    return np.array([fx.transform(e) for e in events], dtype=float), [peer_group(e) for e in events]


class ModelTrainer(LoggerMixin):
    def __init__(self, config=None):
        self.config = config or {}
        cfg = (((self.config.get("ml", {}) if hasattr(self.config, "get") else {}) or {}).get("model", {}) or {})
        self.params = {"quantile": float(cfg.get("quantile", 0.999)), "margin": float(cfg.get("margin", 2.0))}

    def load_events(self, path: Optional[str] = None, n_normal: int = 20000, seed: int = 7) -> List[Dict[str, Any]]:
        if path:
            with open(path, "r", encoding="utf-8") as f:
                raw = [json.loads(line) if line.strip().startswith("{") else {"raw_message": line.strip()}
                       for line in f if line.strip()]
            return _normalized(raw, self.config)
        from src.simulation.traffic import generate_dataset
        return _normalized(generate_dataset(n_normal=n_normal, n_attacks=0, seed=seed), self.config)

    def train(self, events: List[Dict[str, Any]], save: bool = True) -> BaselineAnomalyDetector:
        X, groups = featurize(events)
        detector = BaselineAnomalyDetector(**self.params).fit(X, groups, FEATURES)
        if save:
            detector.save(model_path())
            self.logger.info(f"Model trained on {len(X)} events")
        return detector

    def evaluate(self, detector: BaselineAnomalyDetector, n_normal: int = 6000, n_attacks: int = 40,
                 seed: int = 99) -> Dict[str, Any]:
        """Replay labelled traffic. False positives are counted per *source*: events from a source
        that never took part in an attack (later events of an attacking host are not "false")."""
        from src.simulation.traffic import generate_dataset
        events = _normalized(generate_dataset(n_normal=n_normal, n_attacks=n_attacks, seed=seed), self.config)
        X, groups = featurize(events)
        flagged = detector.score(X, groups) > detector.margin
        truth = np.array([bool((e.get("_truth") or {}).get("malicious")) for e in events])
        attackers = {e.get("src_ip") for e, t in zip(events, truth) if t}
        fp_sources = {e.get("src_ip") for e, f in zip(events, flagged) if f and e.get("src_ip") not in attackers}
        per_type: Dict[str, Dict[str, int]] = {}
        seen: Dict[str, bool] = {}
        for e, f in zip(events, flagged):
            t = e.get("_truth") or {}
            if t.get("malicious"):
                seen[t["scenario_id"]] = seen.get(t["scenario_id"], False) or bool(f)
                per_type.setdefault(t["scenario"], {})[t["scenario_id"]] = seen[t["scenario_id"]]
        return {
            "events": len(events), "attack_scenarios": len(seen),
            "scenarios_detected": round(sum(seen.values()) / len(seen), 3) if seen else None,
            "by_scenario": {k: f"{sum(v.values())}/{len(v)}" for k, v in sorted(per_type.items())},
            "attack_event_recall": round(float(flagged[truth].mean()), 3) if truth.any() else None,
            "false_positive_sources": len(fp_sources),
        }

    def train_and_evaluate(self, path: Optional[str] = None) -> Dict[str, Any]:
        detector = self.train(self.load_events(path), save=False)
        report = self.evaluate(detector)
        detector.metadata["evaluation"] = report
        detector.metadata["trained_on"] = path or "simulated normal traffic"
        detector.save(model_path())
        return {**detector.metadata}
