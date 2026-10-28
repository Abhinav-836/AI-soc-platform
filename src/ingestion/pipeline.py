"""
Ingestion pipeline: collectors -> queue -> normalizer -> detection handler.

Fixes:
  * every event's @timestamp was overwritten with the processing time
  * collector failures (e.g. Kafka) cancelled the whole gather() and stopped
    file ingestion too; each collector now runs as its own task
  * events per second were never measured although the dashboard shows them
"""
import asyncio
import time
from collections import deque
from typing import Any, Awaitable, Callable, Dict, List, Optional

from src.core.logger import LoggerMixin
from src.core.time_utils import iso
from src.ingestion.collectors.file_collector import FileCollector
from src.ingestion.collectors.host_collector import HostCollector
from src.ingestion.collectors.kafka_collector import KafkaCollector
from src.ingestion.collectors.syslog_collector import SyslogCollector
from src.ingestion.parsers.normalizer import LogNormalizer

Handler = Callable[[Dict[str, Any]], Awaitable[Any]]


class IngestionPipeline(LoggerMixin):
    def __init__(self, config, event_handler: Optional[Handler] = None, queue_size: int = 20000):
        self.config = config
        self.event_handler = event_handler
        self.normalizer = LogNormalizer(config)
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self.collectors: List[Any] = []
        self.tasks: List[asyncio.Task] = []
        self.running = False
        self._recent = deque(maxlen=20000)  # processing times, for events/sec
        self.stats = {"events_ingested": 0, "events_dropped": 0, "errors": 0, "last_event": None}

        sources = (config.get("ingestion", {}) or {}).get("sources", {}) or {}
        if (sources.get("file") or {}).get("enabled"):
            self.collectors.append(FileCollector(config))
        if (sources.get("syslog") or {}).get("enabled"):
            self.collectors.append(SyslogCollector(config))
        if (sources.get("kafka") or {}).get("enabled"):
            self.collectors.append(KafkaCollector(config))
        if (sources.get("host") or {}).get("enabled"):
            self.collectors.append(HostCollector(config))

    async def start(self):
        self.running = True
        for collector in self.collectors:
            self.tasks.append(asyncio.create_task(self._run_collector(collector)))
        self.tasks.append(asyncio.create_task(self._process_queue()))
        self.logger.info(f"Ingestion started with {len(self.collectors)} collector(s)")

    async def _run_collector(self, collector):
        try:
            await collector.start(self.queue)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"{collector.__class__.__name__} stopped: {e}", exc_info=True)

    async def stop(self):
        self.running = False
        for collector in self.collectors:
            await collector.stop()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()

    async def _process_queue(self):
        while self.running:
            try:
                raw = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            try:
                await self.process(raw)
            except Exception as e:
                self.stats["errors"] += 1
                self.logger.error(f"Failed to process event: {e}", exc_info=True)

    async def process(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize one raw event and hand it to detection. Returns the normalized event."""
        event = self.normalizer.normalize_sync(raw)
        if not event:
            return None
        event["ingested_at"] = iso()
        self.stats["events_ingested"] += 1
        self.stats["last_event"] = event["ingested_at"]
        self._recent.append(time.monotonic())
        if self.event_handler:
            await self.event_handler(event)
        return event

    def submit(self, raw: Dict[str, Any]) -> bool:
        """Queue an event without waiting (simulator, high-volume API)."""
        try:
            self.queue.put_nowait(raw)
            return True
        except asyncio.QueueFull:
            self.stats["events_dropped"] += 1
            return False

    # old name used by the API
    async def ingest_raw(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return await self.process(raw)

    def events_per_second(self, window: float = 10.0) -> float:
        cutoff = time.monotonic() - window
        return round(sum(1 for t in self._recent if t >= cutoff) / window, 2)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "queue_size": self.queue.qsize(),
            "events_per_second": self.events_per_second(),
            **self.stats,
            "parser": self.normalizer.get_stats(),
            "collectors": [c.get_stats() for c in self.collectors],
        }
