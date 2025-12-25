"""
Elasticsearch storage integration (Optional).
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json

from src.core.logger import LoggerMixin

# Make Elasticsearch optional
try:
    from elasticsearch import AsyncElasticsearch
    from elasticsearch.exceptions import NotFoundError, ConnectionError as ESConnectionError
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    AsyncElasticsearch = None
    NotFoundError = Exception
    ESConnectionError = Exception


class ElasticsearchStorage(LoggerMixin):
    """Elasticsearch-based storage for SOC data (Optional)."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.client: Optional[Any] = None
        self.connected = False
        
        # Elasticsearch configuration
        es_config = config.get("storage", {}).get("elasticsearch", {})
        self.enabled = es_config.get("enabled", False)
        self.host = es_config.get("host", "localhost")
        self.port = es_config.get("port", 9200)
        self.username = es_config.get("username")
        self.password = es_config.get("password")
        self.use_ssl = es_config.get("use_ssl", False)
        self.verify_certs = es_config.get("verify_certs", False)
        
        # Index configuration
        self.index_prefix = es_config.get("index_prefix", "ai-soc")
        self.indices = {
            "events": f"{self.index_prefix}-events",
            "alerts": f"{self.index_prefix}-alerts",
            "iocs": f"{self.index_prefix}-iocs",
            "metrics": f"{self.index_prefix}-metrics",
        }
        
        if not ELASTICSEARCH_AVAILABLE:
            self.logger.warning("Elasticsearch module not installed. Install with: pip install elasticsearch")
        
        if not self.enabled:
            self.logger.info("Elasticsearch storage disabled in config")

    async def connect(self):
        """Connect to Elasticsearch."""
        if not self.enabled:
            self.logger.info("Elasticsearch storage disabled, skipping connection")
            return
            
        if not ELASTICSEARCH_AVAILABLE:
            self.logger.warning("Elasticsearch module not available")
            return
            
        self.logger.info(f"Connecting to Elasticsearch at {self.host}:{self.port}")
        
        try:
            scheme = "https" if self.use_ssl else "http"
            hosts = [f"{scheme}://{self.host}:{self.port}"]
            
            auth = (self.username, self.password) if self.username and self.password else None
            
            self.client = AsyncElasticsearch(
                hosts=hosts,
                basic_auth=auth,
                verify_certs=self.verify_certs,
                request_timeout=30,
                max_retries=3,
                retry_on_timeout=True,
            )
            
            info = await self.client.info()
            self.connected = True
            
            self.logger.info(f"Connected to Elasticsearch {info['version']['number']}")
            
            await self._setup_indices()
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {e}")
            self.connected = False

    async def disconnect(self):
        """Disconnect from Elasticsearch."""
        if self.client and self.connected:
            await self.client.close()
            self.connected = False
            self.logger.info("Disconnected from Elasticsearch")

    async def _setup_indices(self):
        """Setup Elasticsearch indices."""
        if not self.client or not self.connected:
            return
        
        try:
            for index_name in self.indices.values():
                try:
                    exists = await self.client.indices.exists(index=index_name)
                    if not exists:
                        await self.client.indices.create(
                            index=index_name,
                            body={
                                "settings": {
                                    "number_of_shards": 1,
                                    "number_of_replicas": 0,
                                }
                            }
                        )
                        self.logger.info(f"Created index: {index_name}")
                except Exception as e:
                    self.logger.warning(f"Could not create index {index_name}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error setting up indices: {e}")

    async def save_event(self, event: Dict[str, Any]) -> Optional[str]:
        """Save event to Elasticsearch."""
        if not self.enabled or not self.connected or not self.client:
            return None
        
        try:
            if "@timestamp" not in event:
                event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
            
            response = await self.client.index(
                index=self.indices["events"],
                document=event,
                refresh=False
            )
            
            return response.get("_id")
            
        except Exception as e:
            self.logger.debug(f"Error saving event to Elasticsearch: {e}")
            return None

    async def save_events_bulk(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Save multiple events in bulk."""
        if not self.enabled or not self.connected or not self.client or not events:
            return {"success": 0, "failed": len(events) if events else 0, "errors": []}
        
        try:
            operations = []
            for event in events:
                if "@timestamp" not in event:
                    event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
                
                operations.append({"index": {"_index": self.indices["events"]}})
                operations.append(event)
            
            response = await self.client.bulk(operations=operations, refresh=False)
            
            successes = [item for item in response["items"] if item["index"].get("status") in [200, 201]]
            failures = [item for item in response["items"] if item["index"].get("status") not in [200, 201]]
            
            return {
                "success": len(successes),
                "failed": len(failures),
                "total": len(events),
                "errors": failures[:10] if failures else []
            }
            
        except Exception as e:
            self.logger.error(f"Error in bulk save: {e}")
            return {"success": 0, "failed": len(events), "errors": [str(e)]}

    async def save_alert(self, alert: Dict[str, Any]) -> Optional[str]:
        """Save alert to Elasticsearch."""
        if not self.enabled or not self.connected or not self.client:
            return None
        
        try:
            if "@timestamp" not in alert:
                alert["@timestamp"] = datetime.utcnow().isoformat() + "Z"
            
            response = await self.client.index(
                index=self.indices["alerts"],
                document=alert,
                refresh=True
            )
            
            return response.get("_id")
            
        except Exception as e:
            self.logger.error(f"Error saving alert: {e}")
            return None

    async def search_alerts(
        self,
        query: Dict[str, Any],
        size: int = 100,
        from_: int = 0,
        sort: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Search alerts in Elasticsearch."""
        if not self.enabled or not self.connected or not self.client:
            return {"alerts": [], "total": 0}
        
        try:
            if sort is None:
                sort = [{"@timestamp": {"order": "desc"}}]
            
            response = await self.client.search(
                index=self.indices["alerts"],
                query=query,
                size=size,
                from_=from_,
                sort=sort
            )
            
            hits = response.get("hits", {}).get("hits", [])
            total = response.get("hits", {}).get("total", {}).get("value", 0)
            
            alerts = []
            for hit in hits:
                alert = hit.get("_source", {})
                alert["_id"] = hit.get("_id")
                alerts.append(alert)
            
            return {
                "alerts": alerts,
                "total": total,
                "took": response.get("took", 0),
            }
            
        except Exception as e:
            self.logger.error(f"Error searching alerts: {e}")
            return {"alerts": [], "total": 0}

    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get alert by ID."""
        if not self.enabled or not self.connected or not self.client:
            return None
        
        try:
            response = await self.client.get(
                index=self.indices["alerts"],
                id=alert_id
            )
            
            if response.get("found"):
                alert = response.get("_source", {})
                alert["_id"] = response.get("_id")
                return alert
            
            return None
            
        except Exception:
            return None

    async def update_alert_status(
        self,
        alert_id: str,
        status: str,
        notes: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> bool:
        """Update alert status."""
        if not self.enabled or not self.connected or not self.client:
            return False
        
        try:
            update_body = {
                "doc": {
                    "status": status,
                    "updated_at": datetime.utcnow().isoformat() + "Z",
                }
            }
            
            if notes:
                update_body["doc"]["notes"] = notes
            if assigned_to:
                update_body["doc"]["assigned_to"] = assigned_to
            
            response = await self.client.update(
                index=self.indices["alerts"],
                id=alert_id,
                body=update_body,
                refresh=True
            )
            
            return response.get("result") in ["updated", "noop"]
            
        except Exception as e:
            self.logger.error(f"Error updating alert: {e}")
            return False

    async def health_check(self) -> Dict[str, Any]:
        """Perform Elasticsearch health check."""
        if not self.enabled:
            return {"status": "disabled", "message": "Elasticsearch storage disabled"}
        
        if not ELASTICSEARCH_AVAILABLE:
            return {"status": "unavailable", "message": "Elasticsearch module not installed"}
        
        if not self.client:
            return {"status": "disconnected", "message": "Client not initialized"}
        
        try:
            await self.client.info()
            return {"status": "healthy", "message": "Elasticsearch is accessible"}
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}

    def get_stats(self) -> Dict[str, Any]:
        """Get Elasticsearch statistics."""
        return {
            "enabled": self.enabled,
            "connected": self.connected,
            "module_available": ELASTICSEARCH_AVAILABLE,
            "indices": self.indices,
        }