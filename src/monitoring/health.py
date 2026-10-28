"""Component health and host resource usage (GET /health)."""
import time
from typing import Any, Dict

try:
    import psutil
except ImportError:  # optional
    psutil = None

STARTED = time.time()


def system_stats() -> Dict[str, Any]:
    out: Dict[str, Any] = {"uptime_seconds": int(time.time() - STARTED)}
    if psutil:
        try:
            out.update(cpu_percent=psutil.cpu_percent(interval=None),
                       memory_percent=psutil.virtual_memory().percent,
                       process_memory_mb=round(psutil.Process().memory_info().rss / 1048576, 1))
        except Exception:
            pass
    return out


def component_health(platform) -> Dict[str, Any]:
    components = {
        "ingestion": "up" if platform.ingestion.running else "down",
        "detection": "up" if platform.detection.running else "down",
        "response": "up" if platform.response.running else "down",
        "ml": "ready" if platform.ml.detector else ("training" if platform.ml.training else "not_ready"),
        "storage": "up",
        "elasticsearch": ("connected" if platform.elastic.connected else "unavailable") if platform.elastic.enabled
        else "disabled",
    }
    degraded = any(v in ("down",) for v in components.values())
    return {"status": "degraded" if degraded else "healthy", "components": components, "system": system_stats()}


class HealthMonitor:
    """Kept for backwards compatibility."""

    def __init__(self, config=None):
        self.config = config
