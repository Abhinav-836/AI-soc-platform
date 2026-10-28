"""
Optional Elasticsearch mirror. When storage.elasticsearch.enabled is true,
events and alerts are also indexed into Elasticsearch (e.g. for Kibana).
SQLite stays the source of truth, so the platform keeps working if
Elasticsearch is down.

Previously this class was constructed but never connected or written to.
"""
import asyncio
from typing import Any, Dict, List, Optional

from src.core.logger import LoggerMixin

try:  # optional dependency
    from elasticsearch import AsyncElasticsearch
    from elasticsearch.helpers import async_bulk
    ELASTICSEARCH_AVAILABLE = True
except ImportError:  # pragma: no cover
    AsyncElasticsearch = None
    async_bulk = None
    ELASTICSEARCH_AVAILABLE = False


class ElasticsearchStorage(LoggerMixin):
    def __init__(self, config):
        cfg = (config.get("storage", {}) or {}).get("elasticsearch", {}) or {}
        self.enabled = bool(cfg.get("enabled", False))
        scheme = "https" if cfg.get("use_ssl") else "http"
        self.url = cfg.get("url") or f"{scheme}://{cfg.get('host', 'localhost')}:{cfg.get('port', 9200)}"
        self.auth = (cfg["username"], cfg.get("password", "")) if cfg.get("username") else None
        self.verify_certs = bool(cfg.get("verify_certs", False))
        prefix = cfg.get("index_prefix", "ai-soc")
        self.indices = {"events": f"{prefix}-events", "alerts": f"{prefix}-alerts"}
        self.client: Optional[Any] = None
        self.connected = False
        self.errors = 0
        self._buffer: List[Dict[str, Any]] = []

    async def connect(self):
        if not self.enabled:
            return
        if not ELASTICSEARCH_AVAILABLE:
            self.logger.warning("Elasticsearch enabled but the 'elasticsearch' package is not installed")
            return
        try:
            self.client = AsyncElasticsearch(self.url, basic_auth=self.auth, verify_certs=self.verify_certs,
                                             request_timeout=10)
            await self.client.info()
            self.connected = True
            self.logger.info(f"Connected to Elasticsearch at {self.url}")
        except Exception as e:
            self.logger.warning(f"Elasticsearch unavailable ({e}); continuing with SQLite only")
            self.connected = False

    async def index_alert(self, alert: Dict[str, Any]):
        if not self.connected:
            return
        try:
            await self.client.index(index=self.indices["alerts"], id=alert["id"], document=alert)
        except Exception as e:
            self.errors += 1
            self.logger.debug(f"Elasticsearch alert index failed: {e}")

    async def index_events(self, events: List[Dict[str, Any]]):
        if not self.connected or not events:
            return
        actions = [{"_index": self.indices["events"], "_id": e["event_id"],
                    "_source": {k: v for k, v in e.items() if not k.startswith("_")}} for e in events]
        try:
            await async_bulk(self.client, actions, raise_on_error=False)
        except Exception as e:
            self.errors += 1
            self.logger.debug(f"Elasticsearch bulk index failed: {e}")

    async def close(self):
        if self.client:
            try:
                await asyncio.wait_for(self.client.close(), timeout=5)
            except Exception:
                pass
        self.connected = False

    def get_stats(self) -> Dict[str, Any]:
        return {"enabled": self.enabled, "connected": self.connected, "url": self.url if self.enabled else None,
                "errors": self.errors}
