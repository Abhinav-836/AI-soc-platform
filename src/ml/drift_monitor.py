"""
Score drift: Population Stability Index between the anomaly-score
distribution at training time and the last N live scores.

  PSI < 0.1 stable  |  0.1-0.25 moderate  |  > 0.25 significant (retrain)
"""
from collections import deque
from typing import Any, Dict, List, Optional

import numpy as np


def psi(expected: List[float], actual: List[float], eps: float = 1e-4) -> float:
    e = np.clip(np.asarray(expected, dtype=float), eps, None)
    a = np.clip(np.asarray(actual, dtype=float), eps, None)
    return float(np.sum((a - e) * np.log(a / e)))


class DriftMonitor:
    def __init__(self, window: int = 5000, min_samples: int = 1000):
        self.scores = deque(maxlen=window)
        self.min_samples = min_samples

    def add(self, score: float):
        self.scores.append(float(score))

    def status(self, reference_hist: List[float], bin_edges: List[float]) -> Dict[str, Any]:
        if not reference_hist or len(self.scores) < self.min_samples:
            return {"psi": None, "status": "insufficient_data", "samples": len(self.scores)}
        hist, _ = np.histogram(np.asarray(self.scores), bins=np.asarray(bin_edges, dtype=float))
        value = psi(reference_hist, (hist / max(hist.sum(), 1)).tolist())
        level: Optional[str] = "stable" if value < 0.1 else "moderate" if value < 0.25 else "significant"
        return {"psi": round(value, 4), "status": level, "samples": len(self.scores)}
