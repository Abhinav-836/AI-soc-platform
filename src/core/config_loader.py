"""
Configuration loader with validation.
"""

from pathlib import Path
from typing import Any, Dict, Optional
import os
from dotenv import load_dotenv

import yaml
from pydantic import BaseModel, ValidationError

# Load environment variables
load_dotenv()


class AppConfig(BaseModel):
    """Application configuration model."""
    name: str
    version: str
    environment: str = "development"
    debug: bool = False
    workers: int = 4
    timezone: str = "UTC"


class IngestionConfig(BaseModel):
    """Ingestion configuration model."""
    sources: Dict[str, Any]
    parsers: Dict[str, Any] = {}
    normalization: Dict[str, Any] = {}


class DetectionConfig(BaseModel):
    """Detection configuration model."""
    rules: Dict[str, Any]
    thresholds: Dict[str, Any] = {}
    scoring: Dict[str, Any] = {}


class MLConfig(BaseModel):
    """ML configuration model."""
    models: Dict[str, Any]
    features: Dict[str, Any]
    training: Dict[str, Any]
    inference: Dict[str, Any]
    drift_detection: Dict[str, Any]


class ResponseConfig(BaseModel):
    """Response configuration model."""
    playbooks: Dict[str, Any]
    providers: Dict[str, Any]
    approval: Dict[str, Any]


class ConfigLoader:
    """Configuration loader with validation."""

    def __init__(self, config_dir: str = "./config"):
        self.config_dir = Path(config_dir).resolve()
        self.configs: Dict[str, Any] = {}
        self._validate_config_dir()
        
        # Load environment variables
        self.env = {
            "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", ""),
            "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY", ""),
            "ABUSEIPDB_API_KEY": os.getenv("ABUSEIPDB_API_KEY", ""),
            "SLACK_WEBHOOK_URL": os.getenv("SLACK_WEBHOOK_URL", ""),
            "ELASTIC_HOST": os.getenv("ELASTIC_HOST", "localhost"),
            "ELASTIC_PORT": int(os.getenv("ELASTIC_PORT", "9200")),
            "ELASTIC_USER": os.getenv("ELASTIC_USER", ""),
            "ELASTIC_PASSWORD": os.getenv("ELASTIC_PASSWORD", ""),
            "KAFKA_BOOTSTRAP_SERVERS": os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            "REDIS_HOST": os.getenv("REDIS_HOST", "localhost"),
            "REDIS_PORT": int(os.getenv("REDIS_PORT", "6379")),
        }

    def _validate_config_dir(self):
        if not self.config_dir.exists():
            raise FileNotFoundError(f"Config directory not found: {self.config_dir}")
        if not self.config_dir.is_dir():
            raise NotADirectoryError(f"Config path is not a directory: {self.config_dir}")

    async def load_all(self):
        """Load all configuration files."""
        config_files = [
            ("app", "app.yaml"),
            ("ingestion", "ingestion.yaml"),
            ("detection", "detection.yaml"),
            ("ml", "ml.yaml"),
            ("response", "response.yaml"),
            ("logging", "logging.yaml"),
        ]

        for name, filename in config_files:
            self.load_config(name, filename)

    def load_config(self, name: str, filename: str) -> Dict[str, Any]:
        """Load and validate a configuration file."""
        config_path = self.config_dir / filename

        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                raw_config = yaml.safe_load(f)

            if not isinstance(raw_config, dict):
                raise ValueError(f"{filename} is empty or invalid")

            if name == "app":
                app_cfg = raw_config.get("app", raw_config)
                if not isinstance(app_cfg, dict) or not app_cfg:
                    raise ValueError("app.yaml is empty or invalid")
                config = AppConfig(**app_cfg)
                self.configs[name] = config.model_dump()

            elif name == "ingestion":
                config = IngestionConfig(**raw_config)
                self.configs[name] = config.model_dump()

            elif name == "detection":
                config = DetectionConfig(**raw_config)
                self.configs[name] = config.model_dump()

            elif name == "ml":
                config = MLConfig(**raw_config)
                self.configs[name] = config.model_dump()

            elif name == "response":
                config = ResponseConfig(**raw_config)
                self.configs[name] = config.model_dump()

            else:
                self.configs[name] = raw_config

            # Inject environment variables
            self.configs["env"] = self.env

            return self.configs[name]

        except ValidationError as e:
            raise ValueError(f"Invalid configuration in {filename}:\n{e}") from e
        except yaml.YAMLError as e:
            raise ValueError(f"YAML parsing error in {filename}:\n{e}") from e

    def get(self, name: str, default: Any = None) -> Any:
        """Get configuration by name."""
        return self.configs.get(name, default)

    def get_nested(self, *keys: str, default: Any = None) -> Any:
        """Get nested configuration value."""
        value = self.configs
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
        return value if value is not None else default

    def update(self, name: str, updates: Dict[str, Any]):
        """Update configuration in memory."""
        if name in self.configs and isinstance(self.configs[name], dict):
            self.configs[name].update(updates)
        else:
            self.configs[name] = updates