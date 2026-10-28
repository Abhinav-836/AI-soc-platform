import os
import sys
import tempfile
from pathlib import Path

import pytest

# Isolated data folder for the whole test session (set before importing src)
os.environ["SOC_DATA_DIR"] = tempfile.mkdtemp(prefix="soc-tests-")
os.environ.pop("SOC_API_KEY", None)
os.environ["SOC_RESPONSE_MODE"] = "dry_run"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.config_loader import ConfigLoader  # noqa: E402


@pytest.fixture(scope="session")
def config():
    return ConfigLoader()


@pytest.fixture
async def platform():
    from src.main import SOCPlatform
    p = SOCPlatform(db_path=":memory:")
    p.intel.load()
    if not p.ml.load():
        await p.ml.retrain()
    await p.detection.start()
    p.response.load_playbooks()
    yield p
    await p.detection.stop()


async def feed(platform, events):
    for e in events:
        await platform.ingestion.process(dict(e))
    return platform.store.list_alerts(500)["alerts"]
