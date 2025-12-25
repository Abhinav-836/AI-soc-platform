"""
Kafka-based log collector.
"""

import asyncio
import json
from typing import Dict, Any, Optional
from datetime import datetime

from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

from src.utils.logger import LoggerMixin


class KafkaCollector(LoggerMixin):
    """Collects logs from Kafka topics."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.running = False
        self.consumer: Optional[KafkaConsumer] = None
        self.stats = {
            "messages_received": 0,
            "topics_subscribed": 0,
            "last_received": None,
            "errors": 0,
            "rebalances": 0,
        }

    async def start(self, queue: asyncio.Queue):
        """Start Kafka consumer."""
        self.logger.info("Starting Kafka collector...")
        self.running = True

        config = self.config.get("ingestion", {}).get("sources", {}).get("kafka", {})
        bootstrap_servers = config.get("bootstrap_servers", "localhost:9092")
        topics = config.get("topics", [])
        group_id = config.get("group_id", "ai-soc-consumer")
        auto_offset_reset = config.get("auto_offset_reset", "latest")

        try:
            # Create Kafka consumer
            self.consumer = KafkaConsumer(
                *topics,
                bootstrap_servers=bootstrap_servers,
                group_id=group_id,
                auto_offset_reset=auto_offset_reset,
                enable_auto_commit=True,
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                consumer_timeout_ms=1000,
            )

            self.stats["topics_subscribed"] = len(topics)
            self.logger.info(f"Subscribed to topics: {topics}")

            # Start consuming messages
            while self.running:
                await self._consume_messages(queue)

        except NoBrokersAvailable:
            self.logger.error("No Kafka brokers available")
            await self.stop()
        except Exception as e:
            self.logger.error(f"Error in Kafka collector: {e}", exc_info=True)
            await self.stop()

    async def stop(self):
        """Stop Kafka consumer."""
        self.logger.info("Stopping Kafka collector...")
        self.running = False

        if self.consumer:
            self.consumer.close()

    async def _consume_messages(self, queue: asyncio.Queue):
        """Consume messages from Kafka."""
        try:
            # Poll for messages
            raw_messages = self.consumer.poll(timeout_ms=1000)

            for topic_partition, messages in raw_messages.items():
                for message in messages:
                    await self._process_message(message, queue)

            # Handle consumer rebalance
            self._handle_rebalances()

        except Exception as e:
            self.logger.error(f"Error consuming messages: {e}", exc_info=True)
            self.stats["errors"] += 1
            await asyncio.sleep(1)

    async def _process_message(self, message, queue: asyncio.Queue):
        """Process a single Kafka message."""
        try:
            # Create log event
            event = {
                "raw_message": message.value,
                "source_type": "kafka",
                "topic": message.topic,
                "partition": message.partition,
                "offset": message.offset,
                "timestamp": message.timestamp,
                "@timestamp": datetime.utcnow().isoformat() + "Z",
            }

            # Put in queue
            await queue.put(event)

            # Update stats
            self.stats["messages_received"] += 1
            self.stats["last_received"] = datetime.utcnow().isoformat()

            self.logger.debug(f"Received Kafka message from {message.topic}:{message.partition}")

        except Exception as e:
            self.logger.error(f"Error processing Kafka message: {e}", exc_info=True)
            self.stats["errors"] += 1

    def _handle_rebalances(self):
        """Handle consumer rebalance events."""
        # Check for assignment changes
        assignment = self.consumer.assignment()
        
        # Log rebalance events (simplified - in production use proper rebalance listeners)
        if hasattr(self, '_last_assignment') and self._last_assignment != assignment:
            self.logger.info(f"Consumer rebalanced. New assignment: {assignment}")
            self.stats["rebalances"] += 1
        
        self._last_assignment = assignment

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            "type": "kafka",
            "running": self.running,
            **self.stats,
            "consumer_assignment": str(self.consumer.assignment()) if self.consumer else None,
        }