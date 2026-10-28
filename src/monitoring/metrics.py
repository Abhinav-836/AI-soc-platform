"""
Platform metrics in Prometheus text format (GET /metrics).

Replaces a 390-line collector that was constructed but never started.
"""
from typing import Any, Dict, List


def _line(name: str, value: Any, labels: Dict[str, Any] = None, help_text: str = "", kind: str = "gauge"):
    out = []
    if help_text:
        out += [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"]
    label = ""
    if labels:
        label = "{" + ",".join(f'{k}="{str(v).replace(chr(34), "")}"' for k, v in labels.items()) + "}"
    out.append(f"{name}{label} {float(value or 0)}")
    return out


def prometheus(stats: Dict[str, Any]) -> str:
    ing, det, resp, ml = (stats.get(k, {}) for k in ("ingestion", "detection", "response", "ml"))
    alerts = stats.get("alerts", {})
    lines: List[str] = []
    lines += _line("soc_events_ingested_total", ing.get("events_ingested"), help_text="Events ingested",
                   kind="counter")
    lines += _line("soc_events_per_second", ing.get("events_per_second"), help_text="Ingestion rate (10s)")
    lines += _line("soc_ingest_queue_size", ing.get("queue_size"), help_text="Events waiting in the queue")
    lines += _line("soc_alerts_created_total", det.get("alerts_created"), help_text="Alerts created", kind="counter")
    lines += _line("soc_alerts_open", alerts.get("open"), help_text="Open alerts (new + investigating)")
    for sev, n in (alerts.get("open_by_severity") or {}).items():
        lines += _line("soc_alerts_open_by_severity", n, {"severity": sev})
    for source, n in (det.get("hits") or {}).items():
        lines += _line("soc_detection_hits_total", n, {"source": source})
    lat = det.get("latency_ms") or {}
    for q in ("p50", "p95", "p99"):
        if lat.get(q) is not None:
            lines += _line("soc_detection_latency_ms", lat[q], {"quantile": q})
    lines += _line("soc_ml_inferences_total", ml.get("inferences"), kind="counter")
    lines += _line("soc_ml_anomalies_total", ml.get("anomalies"), kind="counter")
    lines += _line("soc_response_pending_approval", resp.get("pending_approval"))
    return "\n".join(lines) + "\n"


class MetricsCollector:
    """Kept for backwards compatibility; metrics are computed on request now."""

    def __init__(self, config=None):
        self.config = config
