"""
Feature extraction for anomaly detection.

Each event becomes a numeric vector made of (a) what the event itself looks
like and (b) how its source has behaved over the last 5 minutes. The same
extractor is used for training (events replayed in time order) and live
scoring, so the model never sees features computed differently.
"""
import math
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Tuple

from src.core.time_utils import parse_ts, utcnow
from src.detection.rules.matcher import is_private_ip

FAILURE_TYPES = {"ssh_failed", "firewall_drop", "waf_alert", "rdp_failed", "web_auth_failed"}

# behaviour of the source over the last 5 minutes + size of this event
FEATURES = [
    "src_events_5m_log", "src_failures_5m_log", "src_distinct_ports_5m_log", "src_distinct_dsts_5m_log",
    "src_bytes_out_5m_log", "src_distinct_users_5m_log", "src_distinct_queries_5m_log",
    "bytes_out_log", "query_label_max", "query_len",
]
WINDOW = 300.0


def peer_group(event: Dict[str, Any]) -> str:
    """Baselines are learned separately for internal and external sources."""
    return "internal" if is_private_ip(event.get("src_ip")) else "external"


class FeatureExtractor:
    def __init__(self, max_entities: int = 50000):
        self.windows: Dict[str, Deque[Tuple[float, Dict[str, Any]]]] = defaultdict(deque)
        self.max_entities = max_entities

    def reset(self):
        self.windows.clear()

    def transform(self, event: Dict[str, Any]) -> List[float]:
        ts = (parse_ts(event.get("@timestamp")) or utcnow()).timestamp()
        entity = str(event.get("src_ip") or event.get("hostname") or "unknown")
        window = self.windows[entity]
        window.append((ts, {"t": event.get("event_type"), "p": event.get("dst_port"), "d": event.get("dst_ip"),
                            "b": event.get("bytes_out") or 0, "u": event.get("user"), "q": event.get("query")}))
        while window and window[0][0] < ts - WINDOW:
            window.popleft()
        if len(self.windows) > self.max_entities:  # forget idle sources
            for key in [k for k, w in self.windows.items() if not w or w[-1][0] < ts - WINDOW][:1000]:
                del self.windows[key]

        items = [x for _, x in window]
        query = str(event.get("query") or "")
        return [
            math.log1p(len(items)),
            math.log1p(sum(1 for x in items if x["t"] in FAILURE_TYPES)),
            math.log1p(len({x["p"] for x in items if x["p"] is not None})),
            math.log1p(len({x["d"] for x in items if x["d"]})),
            math.log1p(sum(float(x["b"]) for x in items)),
            math.log1p(len({x["u"] for x in items if x["u"]})),
            math.log1p(len({x["q"] for x in items if x["q"]})),
            math.log1p(float(event.get("bytes_out") or 0)),
            float(max((len(x) for x in query.split(".")), default=0)) if query else 0.0,
            float(len(query)),
        ]
