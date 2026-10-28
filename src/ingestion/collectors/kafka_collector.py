"""
Kafka collector.

Fixes:
  * `from kafka.errors import NoBrokersAvailable` at import time crashed the
    whole platform on kafka-python 3.x (the class was removed) - even with
    Kafka disabled. kafka-python is now imported only when Kafka is enabled.
  * consumer.poll() is blocking; it ran directly on the event loop and froze
    the API/WebSocket for up to a second per poll. It now runs in a thread.
  * JSON messages were wrapped as raw_message dicts that no parser handled.
  * KAFKA_BOOTSTRAP_SERVERS from the environment/docker-compose was ignored.
"""
import asyncio
import json
import os
from typing import Any, Dict, Optional

from src.core.logger import LoggerMixin
from src.core.time_utils import iso


class KafkaCollector(LoggerMixin):
    def __init__(self, config):
        cfg = ((config.get("ingestion", {}) or {}).get("sources", {}) or {}).get("kafka", {}) or {}
        servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS") or cfg.get("bootstrap_servers", "localhost:9092")
        self.servers = [s.strip() for s in servers.split(",")] if isinstance(servers, str) else servers
        self.topics = cfg.get("topics", ["security-logs"])
        self.group_id = cfg.get("group_id", "ai-soc-consumer")
        self.offset_reset = cfg.get("auto_offset_reset", "latest")
        self.consumer: Optional[Any] = None
        self.running = False
        self.stats = {"messages_received": 0, "last_received": None, "errors": 0, "connected": False}

    def _connect(self):
        from kafka import KafkaConsumer  # lazy: optional dependency
        return KafkaConsumer(*self.topics, bootstrap_servers=self.servers, group_id=self.group_id,
                             auto_offset_reset=self.offset_reset, enable_auto_commit=True)

    async def start(self, queue: asyncio.Queue):
        self.running = True
        loop = asyncio.get_running_loop()
        while self.running and self.consumer is None:
            try:
                self.consumer = await loop.run_in_executor(None, self._connect)
                self.stats["connected"] = True
                self.logger.info(f"Kafka consumer subscribed to {self.topics} on {self.servers}")
            except ImportError:
                self.logger.error("Kafka source enabled but kafka-python is not installed")
                self.running = False
                return
            except Exception as e:
                self.stats["errors"] += 1
                self.logger.warning(f"Kafka not reachable ({e}); retrying in 10s")
                await asyncio.sleep(10)

        while self.running:
            try:
                batch = await loop.run_in_executor(None, lambda: self.consumer.poll(timeout_ms=1000))
            except Exception as e:
                self.stats["errors"] += 1
                self.logger.error(f"Kafka poll failed: {e}")
                await asyncio.sleep(2)
                continue
            for records in batch.values():
                for record in records:
                    await queue.put(self._to_event(record))
                    self.stats["messages_received"] += 1
                    self.stats["last_received"] = iso()

    @staticmethod
    def _to_event(record) -> Dict[str, Any]:
        raw = record.value.decode("utf-8", errors="replace") if isinstance(record.value, bytes) else record.value
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            event = dict(data)
        else:
            event = {"raw_message": str(raw)}
        event["source_type"] = "kafka"
        event.setdefault("kafka_topic", record.topic)
        return event

    async def stop(self):
        self.running = False
        if self.consumer:
            try:
                self.consumer.close()
            except Exception:
                pass

    def get_stats(self) -> Dict[str, Any]:
        return {"type": "kafka", "running": self.running, "topics": self.topics, **self.stats}
