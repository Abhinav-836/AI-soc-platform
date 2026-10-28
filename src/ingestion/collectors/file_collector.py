"""
File collector: tails log files (globs supported) and handles rotation.

Fixes:
  * the old collector started every file at its END, so logs that already
    existed (the README's "generate logs, then run") were never read
  * "data/raw/*.log" was treated as a literal file name and reported missing
  * every line was tagged with the first watched file, not its own file
  * a line half-written at read time was split into two broken events

Read positions are saved to <data dir>/state/file_offsets.json, so a restart
continues where it stopped instead of re-reading (and re-alerting on) old
lines. `start_from: beginning|end` applies only to files seen for the first
time.
"""
import asyncio
import glob
import json
from pathlib import Path
from typing import Any, Dict

from src.core.logger import LoggerMixin
from src.core.paths import data_path, writable
from src.core.time_utils import iso


class FileCollector(LoggerMixin):
    def __init__(self, config):
        cfg = ((config.get("ingestion", {}) or {}).get("sources", {}) or {}).get("file", {}) or {}
        self.patterns = [str(writable(p)) for p in cfg.get("paths", [])]
        self.interval = float(cfg.get("watch_interval", 1))
        self.start_from = cfg.get("start_from", "beginning")
        self.state_file = data_path("state", "file_offsets.json")
        self.offsets: Dict[str, int] = self._load_offsets()
        self.partial: Dict[str, bytes] = {}
        self.running = False
        self.stats = {"files_watched": 0, "lines_processed": 0, "last_processed": None, "errors": 0}

    def _load_offsets(self) -> Dict[str, int]:
        try:
            return {k: int(v) for k, v in json.loads(self.state_file.read_text()).items()}
        except (OSError, ValueError):
            return {}

    def _save_offsets(self):
        try:
            self.state_file.write_text(json.dumps(self.offsets))
        except OSError:
            pass

    def _files(self):
        found = []
        for pattern in self.patterns:
            found.extend(p for p in glob.glob(pattern) if Path(p).is_file())
        return sorted(set(found))

    async def start(self, queue: asyncio.Queue):
        self.running = True
        for pattern in self.patterns:
            Path(pattern).parent.mkdir(parents=True, exist_ok=True)
        self.logger.info(f"File collector watching: {', '.join(self.patterns) or '(no paths)'}")
        while self.running:
            try:
                await self.poll(queue)
            except Exception as e:  # never let one bad file stop collection
                self.stats["errors"] += 1
                self.logger.error(f"File collector error: {e}", exc_info=True)
            await asyncio.sleep(self.interval)

    async def poll(self, queue: asyncio.Queue) -> int:
        """Read new lines from every matching file. Returns number of lines queued."""
        files = self._files()
        self.stats["files_watched"] = len(files)
        total = 0
        changed = False
        for name in files:
            path = Path(name)
            size = path.stat().st_size
            if name not in self.offsets:
                self.offsets[name] = size if self.start_from == "end" else 0
                changed = True
            offset = self.offsets[name]
            if size < offset:  # truncated / rotated
                self.logger.info(f"File rotated: {name}")
                offset, self.partial[name] = 0, b""
            if size == offset:
                continue
            with open(path, "rb") as f:
                f.seek(offset)
                chunk = f.read(min(size - offset, 8 * 1024 * 1024))
            self.offsets[name] = offset + len(chunk)
            changed = True
            data = self.partial.pop(name, b"") + chunk
            lines = data.split(b"\n")
            if not data.endswith(b"\n"):
                self.partial[name] = lines.pop()  # incomplete last line: wait for the rest
            for raw in lines:
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    await queue.put({"raw_message": line, "source_type": "file", "source_path": name})
                    total += 1
        if total:
            self.stats["lines_processed"] += total
            self.stats["last_processed"] = iso()
        if changed:
            self._save_offsets()
        return total

    async def stop(self):
        self.running = False
        self._save_offsets()

    def get_stats(self) -> Dict[str, Any]:
        return {"type": "file", "running": self.running, "paths": self.patterns, **self.stats}
