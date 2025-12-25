"""
File-based log collector.
"""

import asyncio
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from src.utils.logger import LoggerMixin


class FileCollector(LoggerMixin):
    """Collects logs from files."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.running = False
        self.watchers: Dict[str, Any] = {}
        self.stats = {
            "files_processed": 0,
            "lines_processed": 0,
            "last_processed": None,
            "errors": 0,
        }

    async def start(self, queue: asyncio.Queue):
        """Start file collection."""
        self.logger.info("Starting file collector...")
        self.running = True

        config = self.config.get("ingestion", {}).get("sources", {}).get("file", {})
        paths = config.get("paths", [])
        watch_interval = config.get("watch_interval", 1)

        for path_str in paths:
            path = Path(path_str)
            if path.exists():
                self.watchers[str(path)] = {
                    "path": path,
                    "last_position": path.stat().st_size if path.is_file() else 0,
                    "last_check": time.time(),
                }
                self.logger.info(f"Watching file: {path}")
            else:
                self.logger.warning(f"File not found: {path}")

        # Start watching files
        while self.running:
            await self._watch_files(queue)
            await asyncio.sleep(watch_interval)

    async def stop(self):
        """Stop file collection."""
        self.logger.info("Stopping file collector...")
        self.running = False
        self.watchers.clear()

    async def _watch_files(self, queue: asyncio.Queue):
        """Watch files for changes and collect new lines."""
        for file_info in self.watchers.values():
            path = file_info["path"]

            if not path.exists():
                self.logger.warning(f"File disappeared: {path}")
                continue

            try:
                current_size = path.stat().st_size

                # Check if file has grown
                if current_size > file_info["last_position"]:
                    await self._read_new_lines(
                        path, file_info["last_position"], current_size, queue
                    )
                    file_info["last_position"] = current_size
                    file_info["last_check"] = time.time()

                # Handle file rotation (size decreased)
                elif current_size < file_info["last_position"]:
                    self.logger.info(f"File rotated: {path}")
                    file_info["last_position"] = 0
                    await self._read_new_lines(path, 0, current_size, queue)
                    file_info["last_position"] = current_size

            except Exception as e:
                self.logger.error(f"Error watching file {path}: {e}", exc_info=True)
                self.stats["errors"] += 1

    async def _read_new_lines(
        self,
        path: Path,
        start_position: int,
        end_position: int,
        queue: asyncio.Queue,
    ):
        """Read new lines from file."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(start_position)
                lines = f.read(end_position - start_position)

                if lines:
                    for line in lines.strip().split("\n"):
                        if line.strip():
                            await self._process_line(line.strip(), queue)

        except Exception as e:
            self.logger.error(f"Error reading file {path}: {e}", exc_info=True)
            self.stats["errors"] += 1

    async def _process_line(self, line: str, queue: asyncio.Queue):
        """Process a single line."""
        try:
            # Create log event
            event = {
                "raw_message": line,
                "source_type": "file",
                "source_path": str(self.current_file),
                "@timestamp": datetime.utcnow().isoformat() + "Z",
            }

            # Put in queue
            await queue.put(event)

            # Update stats
            self.stats["lines_processed"] += 1
            self.stats["last_processed"] = datetime.utcnow().isoformat()

        except Exception as e:
            self.logger.error(f"Error processing line: {e}", exc_info=True)
            self.stats["errors"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            "type": "file",
            "running": self.running,
            "files_watched": len(self.watchers),
            **self.stats,
        }

    @property
    def current_file(self) -> Optional[Path]:
        """Get current file being processed."""
        if self.watchers:
            return list(self.watchers.values())[0]["path"]
        return None