"""
Elasticsearch storage integration.
"""

from typing import Dict, List, Any, Optional, Generator
from datetime import datetime, timedelta
import json

from elasticsearch import Elasticsearch, AsyncElasticsearch
from elasticsearch.exceptions import ElasticsearchException

from src.utils.logger import LoggerMixin


class ElasticsearchStorage(LoggerMixin):
    """Elasticsearch-based storage for SOC data."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.client: Optional[AsyncElasticsearch] = None
        self.connected = False
        
        # Elasticsearch configuration
        es_config = config.get("storage", {}).get("elasticsearch", {})
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
        
        # Index templates
        self.index_templates = self._create_index_templates()

    async def connect(self):
        """Connect to Elasticsearch."""
        self.logger.info(f"Connecting to Elasticsearch at {self.host}:{self.port}")
        
        try:
            # Create connection string
            scheme = "https" if self.use_ssl else "http"
            hosts = [f"{scheme}://{self.host}:{self.port}"]
            
            # Create client
            self.client = AsyncElasticsearch(
                hosts=hosts,
                basic_auth=(self.username, self.password) if self.username and self.password else None,
                verify_certs=self.verify_certs,
                request_timeout=30,
                max_retries=3,
                retry_on_timeout=True,
            )
            
            # Test connection
            info = await self.client.info()
            self.connected = True
            
            self.logger.info(f"Connected to Elasticsearch {info['version']['number']}")
            
            # Setup indices
            await self._setup_indices()
            
        except ElasticsearchException as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {e}")
            self.connected = False
            raise

    async def disconnect(self):
        """Disconnect from Elasticsearch."""
        if self.client:
            await self.client.close()
            self.connected = False
            self.logger.info("Disconnected from Elasticsearch")

    def _create_index_templates(self) -> Dict[str, Dict[str, Any]]:
        """Create index templates for SOC data."""
        return {
            "events_template": {
                "index_patterns": [f"{self.index_prefix}-events-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1,
                        "index.lifecycle.name": "ai-soc-lifecycle",
                        "index.lifecycle.rollover_alias": f"{self.index_prefix}-events",
                    },
                    "mappings": {
                        "dynamic": "strict",
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "event_type": {"type": "keyword"},
                            "source_type": {"type": "keyword"},
                            "src_ip": {"type": "ip"},
                            "dst_ip": {"type": "ip"},
                            "src_port": {"type": "integer"},
                            "dst_port": {"type": "integer"},
                            "protocol": {"type": "keyword"},
                            "user": {"type": "keyword"},
                            "hostname": {"type": "keyword"},
                            "process": {"type": "keyword"},
                            "action": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "bytes": {"type": "long"},
                            "duration": {"type": "float"},
                            "message": {"type": "text"},
                            "raw_message": {"type": "text"},
                            "tags": {"type": "keyword"},
                            "geoip": {
                                "properties": {
                                    "country_name": {"type": "keyword"},
                                    "city_name": {"type": "keyword"},
                                    "location": {"type": "geo_point"},
                                }
                            },
                            "threat": {
                                "properties": {
                                    "indicator": {"type": "keyword"},
                                    "matched_ioc": {"type": "keyword"},
                                    "confidence": {"type": "float"},
                                }
                            },
                        }
                    }
                }
            },
            "alerts_template": {
                "index_patterns": [f"{self.index_prefix}-alerts-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1,
                        "index.lifecycle.name": "ai-soc-lifecycle",
                    },
                    "mappings": {
                        "dynamic": "strict",
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "alert_id": {"type": "keyword"},
                            "rule_id": {"type": "keyword"},
                            "rule_name": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "confidence": {"type": "float"},
                            "score": {"type": "float"},
                            "status": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "description": {"type": "text"},
                            "source": {"type": "keyword"},
                            "destination": {"type": "keyword"},
                            "user": {"type": "keyword"},
                            "process": {"type": "keyword"},
                            "indicators": {"type": "nested"},
                            "response_actions": {"type": "nested"},
                            "tags": {"type": "keyword"},
                        }
                    }
                }
            }
        }

    async def _setup_indices(self):
        """Setup Elasticsearch indices and templates."""
        if not self.client:
            raise RuntimeError("Elasticsearch client not initialized")
        
        try:
            # Put index templates
            for template_name, template_body in self.index_templates.items():
                await self.client.indices.put_index_template(
                    name=template_name,
                    body=template_body
                )
                self.logger.info(f"Created index template: {template_name}")
            
            # Create ILM policy for data retention
            await self._setup_ilm_policy()
            
            # Create initial indices if they don't exist
            for index_name in self.indices.values():
                if not await self.client.indices.exists(index=index_name):
                    await self.client.indices.create(
                        index=index_name,
                        body={
                            "settings": {
                                "number_of_shards": 1,
                                "number_of_replicas": 1,
                            }
                        }
                    )
                    self.logger.info(f"Created index: {index_name}")
            
        except ElasticsearchException as e:
            self.logger.error(f"Error setting up indices: {e}")
            raise

    async def _setup_ilm_policy(self):
        """Setup Index Lifecycle Management policy."""
        if not self.client:
            return
        
        try:
            ilm_policy = {
                "policy": {
                    "phases": {
                        "hot": {
                            "min_age": "0ms",
                            "actions": {
                                "rollover": {
                                    "max_age": "1d",
                                    "max_docs": 1000000,
                                    "max_size": "5gb"
                                }
                            }
                        },
                        "warm": {
                            "min_age": "7d",
                            "actions": {
                                "forcemerge": {
                                    "max_num_segments": 1
                                },
                                "shrink": {
                                    "number_of_shards": 1
                                }
                            }
                        },
                        "delete": {
                            "min_age": "30d",
                            "actions": {
                                "delete": {}
                            }
                        }
                    }
                }
            }
            
            await self.client.ilm.put_lifecycle(
                name="ai-soc-lifecycle",
                body=ilm_policy
            )
            self.logger.info("Created ILM policy: ai-soc-lifecycle")
            
        except ElasticsearchException as e:
            self.logger.warning(f"Could not create ILM policy: {e}")

    async def save_event(self, event: Dict[str, Any]):
        """Save event to Elasticsearch."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
        try:
            # Ensure timestamp
            if "@timestamp" not in event:
                event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
            
            # Index the event
            response = await self.client.index(
                index=self.indices["events"],
                document=event,
                refresh=False  # Async indexing for performance
            )
            
            return response.get("_id")
            
        except ElasticsearchException as e:
            self.logger.error(f"Error saving event to Elasticsearch: {e}")
            raise

    async def save_events_bulk(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Save multiple events in bulk."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
        if not events:
            return {"success": 0, "failed": 0, "errors": []}
        
        try:
            # Prepare bulk operations
            operations = []
            for event in events:
                # Ensure timestamp
                if "@timestamp" not in event:
                    event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
                
                operations.append({"index": {"_index": self.indices["events"]}})
                operations.append(event)
            
            # Execute bulk request
            response = await self.client.bulk(
                operations=operations,
                refresh=False
            )
            
            # Process response
            successes = [item for item in response["items"] if item["index"]["status"] in [200, 201]]
            failures = [item for item in response["items"] if item["index"]["status"] not in [200, 201]]
            
            result = {
                "success": len(successes),
                "failed": len(failures),
                "total": len(events),
                "errors": [
                    {
                        "error": item["index"]["error"],
                        "status": item["index"]["status"]
                    }
                    for item in failures
                ] if failures else []
            }
            
            if failures:
                self.logger.warning(f"Bulk insert had {len(failures)} failures")
            
            return result
            
        except ElasticsearchException as e:
            self.logger.error(f"Error in bulk save to Elasticsearch: {e}")
            raise

    async def save_alert(self, alert: Dict[str, Any]):
        """Save alert to Elasticsearch."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
        try:
            # Ensure timestamp
            if "@timestamp" not in alert:
                alert["@timestamp"] = datetime.utcnow().isoformat() + "Z"
            
            # Index the alert
            response = await self.client.index(
                index=self.indices["alerts"],
                document=alert,
                refresh=True  # Refresh for immediate searchability
            )
            
            return response.get("_id")
            
        except ElasticsearchException as e:
            self.logger.error(f"Error saving alert to Elasticsearch: {e}")
            raise

    async def search_events(
        self,
        query: Dict[str, Any],
        size: int = 100,
        from_: int = 0,
        sort: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Search events in Elasticsearch."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
        try:
            if sort is None:
                sort = [{"@timestamp": {"order": "desc"}}]
            
            response = await self.client.search(
                index=self.indices["events"],
                body={
                    "query": query,
                    "size": size,
                    "from": from_,
                    "sort": sort,
                }
            )
            
            # Process results
            hits = response["hits"]["hits"]
            total = response["hits"]["total"]["value"]
            
            events = []
            for hit in hits:
                event = hit["_source"]
                event["_id"] = hit["_id"]
                event["_score"] = hit["_score"]
                events.append(event)
            
            return {
                "events": events,
                "total": total,
                "took": response["took"],
                "timed_out": response["timed_out"],
            }
            
        except ElasticsearchException as e:
            self.logger.error(f"Error searching events: {e}")
            raise

    async def search_alerts(
        self,
        query: Dict[str, Any],
        size: int = 100,
        from_: int = 0,
        sort: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Search alerts in Elasticsearch."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
        try:
            if sort is None:
                sort = [{"@timestamp": {"order": "desc"}}]
            
            response = await self.client.search(
                index=self.indices["alerts"],
                body={
                    "query": query,
                    "size": size,
                    "from": from_,
                    "sort": sort,
                }
            )
            
            # Process results
            hits = response["hits"]["hits"]
            total = response["hits"]["total"]["value"]
            
            alerts = []
            for hit in hits:
                alert = hit["_source"]
                alert["_id"] = hit["_id"]
                alert["_score"] = hit["_score"]
                alerts.append(alert)
            
            return {
                "alerts": alerts,
                "total": total,
                "took": response["took"],
                "timed_out": response["timed_out"],
            }
            
        except ElasticsearchException as e:
            self.logger.error(f"Error searching alerts: {e}")
            raise

    async def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Get event by ID."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
        try:
            response = await self.client.get(
                index=self.indices["events"],
                id=event_id
            )
            
            if response["found"]:
                event = response["_source"]
                event["_id"] = response["_id"]
                return event
            
            return None
            
        except ElasticsearchException as e:
            if e.status_code == 404:
                return None
            self.logger.error(f"Error getting event: {e}")
            raise

    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get alert by ID."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
        try:
            response = await self.client.get(
                index=self.indices["alerts"],
                id=alert_id
            )
            
            if response["found"]:
                alert = response["_source"]
                alert["_id"] = response["_id"]
                return alert
            
            return None
            
        except ElasticsearchException as e:
            if e.status_code == 404:
                return None
            self.logger.error(f"Error getting alert: {e}")
            raise

    async def update_alert_status(
        self,
        alert_id: str,
        status: str,
        notes: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> bool:
        """Update alert status."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
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
            
            return response["result"] in ["updated", "noop"]
            
        except ElasticsearchException as e:
            if e.status_code == 404:
                return False
            self.logger.error(f"Error updating alert: {e}")
            raise

    async def delete_event(self, event_id: str) -> bool:
        """Delete event by ID."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
        try:
            response = await self.client.delete(
                index=self.indices["events"],
                id=event_id,
                refresh=True
            )
            
            return response["result"] == "deleted"
            
        except ElasticsearchException as e:
            if e.status_code == 404:
                return False
            self.logger.error(f"Error deleting event: {e}")
            raise

    async def delete_alert(self, alert_id: str) -> bool:
        """Delete alert by ID."""
        if not self.connected or not self.client:
            raise RuntimeError("Not connected to Elasticsearch")
        
        try:
            response = await self.client.delete(
                index=self.indices["alerts"],
                id=alert_id,
                refresh=True
            )
            
            return response["result"] == "deleted"
            
        except ElasticsearchException as e:
            if e.status_code == 404:
                return False
            self.logger.error(f"Error deleting alert: {e}")
            raise

    async def get_stats(self) -> Dict[str, Any]:
        """Get Elasticsearch statistics."""
        if not self.connected or not self.client:
            return {"connected": False}
        
        try:
            # Get cluster health
            health = await self.client.cluster.health()
            
            # Get index stats
            stats = {}
            for index_name in self.indices.values():
                try:
                    index_stats = await self.client.indices.stats(index=index_name)
                    stats[index_name] = {
                        "docs_count": index_stats["indices"][index_name]["total"]["docs"]["count"],
                        "size": index_stats["indices"][index_name]["total"]["store"]["size_in_bytes"],
                    }
                except ElasticsearchException:
                    stats[index_name] = {"error": "Index not found"}
            
            return {
                "connected": True,
                "cluster_name": health["cluster_name"],
                "status": health["status"],
                "node_count": health["number_of_nodes"],
                "indices": stats,
            }
            
        except ElasticsearchException as e:
            self.logger.error(f"Error getting Elasticsearch stats: {e}")
            return {"connected": False, "error": str(e)}

    async def create_simple_query(
        self,
        field: str,
        value: Any,
        operator: str = "match",
    ) -> Dict[str, Any]:
        """Create a simple Elasticsearch query."""
        if operator == "match":
            return {"match": {field: value}}
        elif operator == "term":
            return {"term": {field: value}}
        elif operator == "range":
            return {"range": {field: value}}
        elif operator == "exists":
            return {"exists": {"field": field}}
        elif operator == "prefix":
            return {"prefix": {field: value}}
        else:
            raise ValueError(f"Unsupported operator: {operator}")

    async def create_bool_query(
        self,
        must: Optional[List[Dict[str, Any]]] = None,
        must_not: Optional[List[Dict[str, Any]]] = None,
        should: Optional[List[Dict[str, Any]]] = None,
        filter: Optional[List[Dict[str, Any]]] = None,
        minimum_should_match: int = 1,
    ) -> Dict[str, Any]:
        """Create a boolean Elasticsearch query."""
        bool_query = {}
        
        if must:
            bool_query["must"] = must
        if must_not:
            bool_query["must_not"] = must_not
        if should:
            bool_query["should"] = should
            bool_query["minimum_should_match"] = minimum_should_match
        if filter:
            bool_query["filter"] = filter
        
        return {"bool": bool_query}

    async def health_check(self) -> Dict[str, Any]:
        """Perform Elasticsearch health check."""
        if not self.client:
            return {"status": "disconnected", "message": "Client not initialized"}
        
        try:
            # Check connection
            await self.client.ping()
            
            # Check indices
            indices_status = {}
            for index_name in self.indices.values():
                exists = await self.client.indices.exists(index=index_name)
                indices_status[index_name] = "exists" if exists else "missing"
            
            return {
                "status": "healthy",
                "message": "Elasticsearch is accessible",
                "indices": indices_status,
            }
            
        except ElasticsearchException as e:
            return {
                "status": "unhealthy",
                "message": str(e),
                "error_type": type(e).__name__,
            }