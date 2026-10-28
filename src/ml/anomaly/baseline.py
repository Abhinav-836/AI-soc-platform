"""
Unsupervised behavioural-baseline anomaly detector.

For each peer group (internal vs external sources) and each feature, the
model learns from normal traffic:
    upper   = 99.9th percentile
    spread  = inter-quartile range (floored; capped at 1.0 for log-byte features)
An event's anomaly score is the largest  (value - upper) / spread  over all
features; above `margin` (default 2) it is anomalous, and the features that
exceeded their baseline are the explanation ("distinct ports from this
source: 3.4 vs normal max 1.6").

Why not Isolation Forest (the original choice): IF cannot score values
outside the range it saw in training - a point beyond the maximum is isolated
exactly like the maximum itself - and attacks are precisely "more than ever
seen". Measured on the simulator, IF flagged 0% of brute-force and DNS
tunneling scenarios at a 0.5% false-positive budget; this baseline flags all
of them with ~1 false-positive source per 6,000 events.
"""
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np

from src.core.time_utils import iso

GROUPS = ("internal", "external")


class BaselineAnomalyDetector:
    def __init__(self, quantile: float = 0.999, margin: float = 2.0, min_spread: float = 0.25):
        self.quantile = quantile
        self.margin = margin
        self.min_spread = min_spread
        self.feature_names: List[str] = []
        self.params: Dict[str, Dict[str, np.ndarray]] = {}
        self.reference_hist: List[float] = []
        self.bin_edges: List[float] = []
        self.metadata: Dict[str, Any] = {}

    @property
    def threshold(self) -> float:
        return self.margin

    def fit(self, X: np.ndarray, groups: List[str], feature_names: List[str]) -> "BaselineAnomalyDetector":
        X = np.asarray(X, dtype=float)
        groups = np.asarray(groups)
        self.feature_names = list(feature_names)
        bytes_cols = np.array(["bytes" in f for f in self.feature_names])
        for g in GROUPS:
            T = X[groups == g] if (groups == g).sum() >= 50 else X
            spread = np.maximum(np.quantile(T, 0.75, axis=0) - np.quantile(T, 0.25, axis=0), self.min_spread)
            spread = np.where(bytes_cols, np.minimum(spread, 1.0), spread)
            self.params[g] = {"upper": np.quantile(T, self.quantile, axis=0), "spread": spread,
                              "median": np.median(T, axis=0), "n": int(len(T))}
        scores = self.score(X, groups)
        edges = np.quantile(scores, np.linspace(0, 1, 11))
        edges = np.unique(edges)
        if len(edges) < 3:
            edges = np.array([scores.min() - 1, np.median(scores), scores.max() + 1])
        edges[0], edges[-1] = -np.inf, np.inf
        self.bin_edges = edges.tolist()
        hist, _ = np.histogram(scores, bins=edges)
        self.reference_hist = (hist / max(hist.sum(), 1)).tolist()
        self.metadata = {"trained_at": iso(), "samples": int(len(X)), "model": "behavioural baseline",
                         "quantile": self.quantile, "margin": self.margin,
                         "groups": {g: self.params[g]["n"] for g in GROUPS},
                         "training_flag_rate": round(float((scores > self.margin).mean()), 5)}
        return self

    def _z(self, X: np.ndarray, groups) -> np.ndarray:
        X = np.atleast_2d(np.asarray(X, dtype=float))
        groups = np.asarray(groups if not isinstance(groups, str) else [groups] * len(X))
        Z = np.zeros_like(X)
        for g in GROUPS:
            mask = groups == g
            if mask.any():
                p = self.params[g]
                Z[mask] = (X[mask] - p["upper"]) / p["spread"]
        return Z

    def score(self, X, groups) -> np.ndarray:
        return self._z(X, groups).max(axis=1)

    def explain(self, x: List[float], group: str, top_k: int = 3) -> List[Dict[str, Any]]:
        z = self._z([x], [group])[0]
        p = self.params[group]
        order = np.argsort(-z)[:top_k]
        return [{"feature": self.feature_names[i], "value": round(float(x[i]), 2),
                 "normal_max": round(float(p["upper"][i]), 2), "excess": round(float(z[i]), 1)}
                for i in order if z[i] > 0]

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.__dict__, path)

    @classmethod
    def load(cls, path: Path) -> "BaselineAnomalyDetector":
        obj = cls()
        obj.__dict__.update(joblib.load(path))
        return obj
