"""
Logging configuration and utilities.
"""

import logging
import logging.config
import sys
from typing import Any, Dict, Optional

import yaml


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime

        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "extra"):
            log_record.update(record.extra)

        return json.dumps(log_record)


def setup_logging(
    config_path: Optional[str] = None,
    default_level: int = logging.INFO,
) -> logging.Logger:
    """
    Set up logging configuration.

    Args:
        config_path: Path to logging YAML config
        default_level: Default logging level

    Returns:
        Root logger
    """
    if config_path:
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            logging.config.dictConfig(config)
        except Exception as e:
            print(f"Failed to load logging config: {e}", file=sys.stderr)
            setup_default_logging(default_level)
    else:
        setup_default_logging(default_level)

    return logging.getLogger(__name__)


def setup_default_logging(level: int = logging.INFO):
    """Set up default logging configuration."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(formatter)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Add console handler
    root_logger.addHandler(console_handler)


class LoggerMixin:
    """Mixin to provide logger to classes."""

    @property
    def logger(self) -> logging.Logger:
        if not hasattr(self, "_logger"):
            self._logger = logging.getLogger(self.__class__.__module__)
        return self._logger

    def log_with_context(self, level: int, message: str, **kwargs):
        """Log with additional context."""
        extra = kwargs.copy()
        extra.update(getattr(self, "context", {}))

        log_record = {
            "message": message,
            "extra": extra,
        }

        self.logger.log(level, message, extra={"extra_fields": extra})


def get_logger(name: str) -> logging.Logger:
    """Get logger by name."""
    return logging.getLogger(name)