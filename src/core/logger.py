"""
Logging. Console + rotating file in <data dir>/logs, plus dedicated
alerts.log / audit.log (JSON lines) used by the detection and response layers.
"""
import json
import logging
import logging.handlers
import os
import sys
from typing import Optional

from src.core.paths import data_path

_CONFIGURED = False


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "data", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def _file_handler(name: str, level: int, formatter: logging.Formatter) -> Optional[logging.Handler]:
    try:
        handler = logging.handlers.RotatingFileHandler(
            data_path("logs", name), maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    except OSError:
        return None
    handler.setLevel(level)
    handler.setFormatter(formatter)
    return handler


def setup_logging(level: Optional[str] = None) -> logging.Logger:
    """Idempotent: safe to call from the API, the CLI and tests."""
    global _CONFIGURED
    root = logging.getLogger()
    if _CONFIGURED:
        return logging.getLogger("soc")
    level_no = getattr(logging, (level or os.getenv("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    root.setLevel(level_no)
    plain = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")

    if sys.stdout is not None:  # None in a windowed (no console) desktop build
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(level_no)
        console.setFormatter(plain)
        root.addHandler(console)
    for handler in (_file_handler("app.log", logging.DEBUG, plain), _file_handler("error.log", logging.ERROR, plain)):
        if handler:
            root.addHandler(handler)

    for name, filename in (("alerts", "alerts.log"), ("audit", "audit.log")):
        special = logging.getLogger(name)
        special.propagate = False
        special.setLevel(logging.INFO)
        handler = _file_handler(filename, logging.INFO, JSONFormatter())
        if handler:
            special.addHandler(handler)

    _CONFIGURED = True
    return logging.getLogger("soc")


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def audit(action: str, **data):
    """Append-only record of response actions, approvals and config changes."""
    logging.getLogger("audit").info(action, extra={"data": {"action": action, **data}})


class LoggerMixin:
    @property
    def logger(self) -> logging.Logger:
        if not hasattr(self, "_logger"):
            self._logger = logging.getLogger(self.__class__.__module__)
        return self._logger
