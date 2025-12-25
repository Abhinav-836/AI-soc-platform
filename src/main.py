#!/usr/bin/env python3
"""
Main entry point for AI SOC Platform.
Runs as headless service or CLI.
"""

import asyncio
import signal
import sys
from typing import Optional

from src.core.logger import setup_logging
from src.core.config_loader import ConfigLoader
from src.ingestion.pipeline import IngestionPipeline
from src.detection.detector import DetectionEngine
from src.response.executor import ResponseExecutor
from src.monitoring.health import HealthMonitor


class AISOCPlatform:
    """Main SOC platform orchestrator."""

    def __init__(self, config_path: str = "./config"):
        self.config_path = config_path
        self.logger = setup_logging()
        self.running = False

        # Components
        self.config: Optional[ConfigLoader] = None
        self.ingestion: Optional[IngestionPipeline] = None
        self.detection: Optional[DetectionEngine] = None
        self.response: Optional[ResponseExecutor] = None
        self.monitor: Optional[HealthMonitor] = None

    async def initialize(self):
        """Initialize all components."""
        self.logger.info("Initializing AI SOC Platform...")

        # Load configuration
        self.config = ConfigLoader(self.config_path)
        await self.config.load_all()

        # Initialize components
        self.ingestion = IngestionPipeline(self.config)
        self.detection = DetectionEngine(self.config)
        self.response = ResponseExecutor(self.config)
        self.monitor = HealthMonitor(self.config)

        # Set up signal handlers
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

        self.logger.info("AI SOC Platform initialized successfully")

    async def start(self):
        """Start the platform."""
        if self.running:
            self.logger.warning("Platform is already running")
            return

        self.logger.info("Starting AI SOC Platform...")
        self.running = True

        # Start components
        tasks = [
            self.ingestion.start(),
            self.detection.start(),
            self.response.start(),
            self.monitor.start(),
        ]

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            self.logger.info("Platform tasks cancelled")
        except Exception as e:
            self.logger.error(f"Error in platform: {e}", exc_info=True)
            await self.shutdown()

    async def shutdown(self, signum=None, frame=None):
        """Graceful shutdown."""
        if not self.running:
            return

        self.logger.info("Shutting down AI SOC Platform...")
        self.running = False

        # Stop components in reverse order
        if self.monitor:
            await self.monitor.stop()
        if self.response:
            await self.response.stop()
        if self.detection:
            await self.detection.stop()
        if self.ingestion:
            await self.ingestion.stop()

        self.logger.info("AI SOC Platform shutdown complete")

    async def run(self):
        """Main run loop."""
        await self.initialize()
        await self.start()

        # Keep running until shutdown
        while self.running:
            await asyncio.sleep(1)


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="AI SOC Platform")
    parser.add_argument(
        "--config",
        "-c",
        default="./config",
        help="Configuration directory path",
    )
    parser.add_argument(
        "--mode",
        "-m",
        choices=["service", "oneshot", "test"],
        default="service",
        help="Run mode",
    )

    args = parser.parse_args()

    # Create and run platform
    platform = AISOCPlatform(args.config)

    try:
        if args.mode == "service":
            asyncio.run(platform.run())
        elif args.mode == "oneshot":
            asyncio.run(platform.initialize())
            # Run single detection cycle
            asyncio.run(platform.detection.run_cycle())
        elif args.mode == "test":
            # Run self-tests
            asyncio.run(platform.initialize())
            asyncio.run(platform.monitor.run_health_check())
    except KeyboardInterrupt:
        asyncio.run(platform.shutdown())
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()