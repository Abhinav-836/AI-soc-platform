"""
Path helpers.

Read-only resources (config, UI, default rules) resolve against the project
root, or against the PyInstaller bundle when running as the desktop app.
Writable state (database, logs, models, raw logs) lives in SOC_DATA_DIR,
which defaults to <project>/data.
"""
import os
import sys
from pathlib import Path
from typing import Union

_BUNDLE = getattr(sys, "_MEIPASS", None)
PROJECT_ROOT = Path(_BUNDLE) if _BUNDLE else Path(__file__).resolve().parents[2]


def resolve(path: Union[str, Path]) -> Path:
    """Absolute path; relative paths are anchored at the project root."""
    p = Path(path)
    return p if p.is_absolute() else PROJECT_ROOT / p


def data_dir() -> Path:
    base = os.getenv("SOC_DATA_DIR")
    path = Path(base) if base else PROJECT_ROOT / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def data_path(*parts: str) -> Path:
    """A path inside the writable data directory (parent folders are created)."""
    p = data_dir().joinpath(*parts)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def writable(path: Union[str, Path]) -> Path:
    """Relative paths go inside the data directory; absolute paths are kept."""
    p = Path(path)
    if p.is_absolute():
        return p
    # "data/raw/x" in configs means "<data dir>/raw/x"
    parts = p.parts[1:] if p.parts and p.parts[0] == "data" else p.parts
    return data_dir().joinpath(*parts)
