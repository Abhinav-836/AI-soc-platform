"""
Configuration loader.

* Loads config/*.yaml (app, ingestion, detection, ml, response, storage, logging)
* Substitutes ${VAR} / ${VAR:-default} from the environment (and .env)
* Deep-merges optional overrides from <data dir>/config/<name>.yaml, so the
  installed desktop app can be reconfigured without touching its files
* Missing files are treated as empty sections instead of crashing startup

The old loader validated with strict pydantic models whose required keys did
not match the shipped YAML (the README even told users to overwrite
app.yaml by hand to get past it), and silently left "${SECRET}" strings in
place because env substitution was never applied.
"""
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml

from src.core.paths import data_dir, resolve

try:  # optional
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

SECTIONS = ("app", "ingestion", "detection", "ml", "response", "storage")
_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _substitute(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.getenv(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {k: _substitute(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v) for v in value]
    return value


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class ConfigLoader:
    def __init__(self, config_dir: Union[str, Path, None] = None, overrides: Optional[Dict[str, Any]] = None):
        self.config_dir = resolve(config_dir or "config")
        if not self.config_dir.is_dir():
            raise FileNotFoundError(f"Config directory not found: {self.config_dir}")
        self.configs: Dict[str, Any] = {}
        self._overrides = overrides or {}
        self.load_sync()

    # kept for compatibility with older callers (`await config.load_all()`)
    async def load_all(self):
        self.load_sync()

    def load_sync(self):
        user_dir = data_dir() / "config"
        for name in SECTIONS:
            section = self._read(self.config_dir / f"{name}.yaml")
            if name == "app" and isinstance(section.get("app"), dict):
                section = {**section.pop("app"), **section}  # app.yaml nests under "app:"
            section = deep_merge(section, self._read(user_dir / f"{name}.yaml"))
            section = deep_merge(section, self._overrides.get(name, {}))
            self.configs[name] = _substitute(section)

    @staticmethod
    def _read(path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8-sig") as f:  # -sig: tolerate a BOM (Windows editors)
            data = yaml.safe_load(f)
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise ValueError(f"{path} must contain a YAML mapping")
        return data

    def get(self, name: str, default: Any = None) -> Any:
        return self.configs.get(name, default)

    def get_nested(self, *keys: str, default: Any = None) -> Any:
        value: Any = self.configs
        for key in keys:
            if not isinstance(value, dict):
                return default
            value = value.get(key)
        return default if value is None else value

    def update(self, name: str, updates: Dict[str, Any]):
        self.configs[name] = deep_merge(self.configs.get(name, {}), updates)
