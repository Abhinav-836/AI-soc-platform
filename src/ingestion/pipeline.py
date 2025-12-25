"""
Ingestion pipeline orchestrator.
"""

import asyncio
import json
from typing import Dict, List, Optional, Any
from datetime import datetime

from src.utils.logger import LoggerMixin
from src.ingestion.collectors.file_collector import FileCollector
from src.ingestion.collectors.syslog_collector import SyslogCollector
from src.ingestion.collectors.kafka_collector import KafkaCollector
from src.ingestion.parsers.normalizer import LogNormalizer


class IngestionPipeline(LoggerMixin):
    """Orchestrates log ingestion from multiple sources."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.running = False
        self.collectors: List[Any] = []
        self.normalizer = LogNormalizer(config)
        self.queue = asyncio.Queue(maxsize=10000)

    async def start(self):
        """Start the ingestion pipeline."""
        self.logger.info("Starting ingestion pipeline...")
        self.running = True

        # Initialize collectors based on config
        await self._init_collectors()

        # Start collectors
        collector_tasks = [collector.start(self.queue) for collector in self.collectors]

        # Start processor
        processor_task = asyncio.create_task(self._process_queue())

        try:
            await asyncio.gather(*collector_tasks, processor_task)
        except asyncio.CancelledError:
            self.logger.info("Ingestion pipeline cancelled")
        except Exception as e:
            self.logger.error(f"Error in ingestion pipeline: {e}", exc_info=True)
            await self.stop()

    async def stop(self):
        """Stop the ingestion pipeline."""
        self.logger.info("Stopping ingestion pipeline...")
        self.running = False

        # Stop collectors
        for collector in self.collectors:
            await collector.stop()

        # Clear queue
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except asyncio.QueueEmpty:
                break

    async def _init_collectors(self):
        """Initialize collectors based on configuration."""
        ingestion_config = self.config.get("ingestion", {})

        # File collector
        if ingestion_config.get("sources", {}).get("file", {}).get("enabled", False):
            file_collector = FileCollector(self.config)
            self.collectors.append(file_collector)
            self.logger.info("File collector initialized")

        # Syslog collector
        if ingestion_config.get("sources", {}).get("syslog", {}).get("enabled", False):
            syslog_collector = SyslogCollector(self.config)
            self.collectors.append(syslog_collector)
            self.logger.info("Syslog collector initialized")

        # Kafka collector
        if ingestion_config.get("sources", {}).get("kafka", {}).get("enabled", False):
            kafka_collector = KafkaCollector(self.config)
            self.collectors.append(kafka_collector)
            self.logger.info("Kafka collector initialized")

    async def _process_queue(self):
        """Process messages from the queue."""
        self.logger.info("Starting queue processor")

        while self.running:
            try:
                # Get message from queue with timeout
                message = await asyncio.wait_for(self.queue.get(), timeout=1.0)

                # Process message
                await self._process_message(message)

                # Mark task as done
                self.queue.task_done()

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error processing message: {e}", exc_info=True)

    async def _process_message(self, message: Dict[str, Any]):
        """Process a single message."""
        try:
            # Normalize message
            normalized = await self.normalizer.normalize(message)

            if normalized:
                # Add metadata
                normalized["@timestamp"] = datetime.utcnow().isoformat() + "Z"
                normalized["ingestion_timestamp"] = datetime.utcnow().isoformat()

                # TODO: Send to storage/detection engine
                self.logger.debug(f"Processed message: {normalized.get('event_type', 'unknown')}")

                # For now, just log
                if self.logger.isEnabledFor(10):  # DEBUG level
                    self.logger.debug(f"Normalized event: {json.dumps(normalized, indent=2)}")

        except Exception as e:
            self.logger.error(f"Error normalizing message: {e}", exc_info=True)

    async def ingest_raw(self, raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Ingest raw data directly (for API/testing).

        Args:
            raw_data: Raw log data

        Returns:
            Normalized event or None
        """
        try:
            normalized = await self.normalizer.normalize(raw_data)
            if normalized:
                normalized["@timestamp"] = datetime.utcnow().isoformat() + "Z"
                return normalized
        except Exception as e:
            self.logger.error(f"Error ingesting raw data: {e}", exc_info=True)

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get ingestion statistics."""
        return {
            "running": self.running,
            "collectors": len(self.collectors),
            "queue_size": self.queue.qsize(),
            "collector_stats": [
                collector.get_stats() for collector in self.collectors
            ],
        }