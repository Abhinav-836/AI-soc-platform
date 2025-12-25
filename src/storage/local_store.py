"""
Local file-based storage for events and alerts.
"""

import json
import pickle
import gzip
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

from src.utils.logger import LoggerMixin


class LocalStorage(LoggerMixin):
    """Local file-based storage for SOC data."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.base_path = Path(config.get("storage", {}).get("local_path", "./data"))
        self.compression = config.get("storage", {}).get("compression", True)

        # Ensure directories exist
        self._ensure_directories()

    def _ensure_directories(self):
        """Ensure storage directories exist."""
        directories = [
            self.base_path / "raw",
            self.base_path / "processed",
            self.base_path / "alerts",
            self.base_path / "models",
            self.base_path / "intel",
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def save_event(self, event: Dict[str, Any], event_type: str = "raw"):
        """
        Save event to local storage.

        Args:
            event: Event data
            event_type: Type of event (raw, processed, alert)
        """
        try:
            timestamp = event.get("@timestamp", datetime.utcnow().isoformat())
            date_part = timestamp.split("T")[0]  # YYYY-MM-DD

            # Create filename
            filename = f"{event_type}_{date_part}.jsonl"
            if self.compression:
                filename += ".gz"

            filepath = self.base_path / event_type / filename

            # Write event
            self._append_to_file(filepath, event)

        except Exception as e:
            self.logger.error(f"Error saving event: {e}", exc_info=True)

    def save_events_batch(self, events: List[Dict[str, Any]], event_type: str = "raw"):
        """Save batch of events."""
        for event in events:
            self.save_event(event, event_type)

    def load_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_type: str = "raw",
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Load events from storage.

        Args:
            start_time: Start time filter
            end_time: End time filter
            event_type: Type of events to load
            limit: Maximum number of events to return

        Returns:
            List of events
        """
        events = []
        directory = self.base_path / event_type

        if not directory.exists():
            return []

        # Get relevant files
        files = self._get_relevant_files(directory, start_time, end_time)

        # Read files
        for filepath in files:
            file_events = self._read_file(filepath, start_time, end_time, limit - len(events))
            events.extend(file_events)

            if len(events) >= limit:
                break

        return events[:limit]

    def save_alert(self, alert: Dict[str, Any]):
        """Save alert to storage."""
        self.save_event(alert, "alerts")

    def load_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Load alerts from storage."""
        alerts = self.load_events(start_time, end_time, "alerts", limit)

        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]

        return alerts

    def save_model(self, model: Any, model_name: str, version: str = "latest"):
        """Save ML model to storage."""
        try:
            model_dir = self.base_path / "models" / model_name
            model_dir.mkdir(parents=True, exist_ok=True)

            filepath = model_dir / f"{version}.pkl.gz"

            with gzip.open(filepath, "wb") as f:
                pickle.dump(model, f)

            self.logger.info(f"Model saved: {model_name}/{version}")

        except Exception as e:
            self.logger.error(f"Error saving model: {e}", exc_info=True)

    def load_model(self, model_name: str, version: str = "latest") -> Optional[Any]:
        """Load ML model from storage."""
        try:
            filepath = self.base_path / "models" / model_name / f"{version}.pkl.gz"

            if not filepath.exists():
                return None

            with gzip.open(filepath, "rb") as f:
                model = pickle.load(f)

            self.logger.info(f"Model loaded: {model_name}/{version}")
            return model

        except Exception as e:
            self.logger.error(f"Error loading model: {e}", exc_info=True)
            return None

    def save_intel(self, iocs: List[Dict[str, Any]], feed_name: str):
        """Save threat intelligence data."""
        try:
            intel_dir = self.base_path / "intel"
            intel_dir.mkdir(parents=True, exist_ok=True)

            filepath = intel_dir / f"{feed_name}.json"

            data = {
                "feed_name": feed_name,
                "timestamp": datetime.utcnow().isoformat(),
                "iocs": iocs,
            }

            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Error saving intel: {e}", exc_info=True)

    def load_intel(self, feed_name: str) -> Optional[List[Dict[str, Any]]]:
        """Load threat intelligence data."""
        try:
            filepath = self.base_path / "intel" / f"{feed_name}.json"

            if not filepath.exists():
                return None

            with open(filepath, "r") as f:
                data = json.load(f)

            return data.get("iocs", [])

        except Exception as e:
            self.logger.error(f"Error loading intel: {e}", exc_info=True)
            return None

    def cleanup_old_data(self, retention_days: int = 30):
        """Clean up old data files."""
        retention_date = datetime.utcnow() - timedelta(days=retention_days)

        for event_type in ["raw", "processed", "alerts"]:
            directory = self.base_path / event_type

            if not directory.exists():
                continue

            for filepath in directory.iterdir():
                if filepath.is_file():
                    # Extract date from filename
                    try:
                        date_str = filepath.name.split("_")[1].split(".")[0]
                        file_date = datetime.strptime(date_str, "%Y-%m-%d")

                        if file_date < retention_date:
                            filepath.unlink()
                            self.logger.debug(f"Deleted old file: {filepath}")

                    except (ValueError, IndexError):
                        # Could not parse date, skip
                        pass

    def _append_to_file(self, filepath: Path, data: Dict[str, Any]):
        """Append data to file (JSONL format)."""
        line = json.dumps(data) + "\n"

        if self.compression and str(filepath).endswith(".gz"):
            with gzip.open(filepath, "at", encoding="utf-8") as f:
                f.write(line)
        else:
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(line)

    def _get_relevant_files(
        self,
        directory: Path,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> List[Path]:
        """Get files relevant to time range."""
        files = []

        for filepath in directory.iterdir():
            if filepath.is_file():
                # Extract date from filename
                try:
                    date_str = filepath.name.split("_")[1].split(".")[0]
                    file_date = datetime.strptime(date_str, "%Y-%m-%d")

                    # Check if file is in time range
                    if start_time and file_date.date() < start_time.date():
                        continue
                    if end_time and file_date.date() > end_time.date():
                        continue

                    files.append(filepath)

                except (ValueError, IndexError):
                    # Could not parse date, include file
                    files.append(filepath)

        # Sort by modification time (newest first)
        files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        return files

    def _read_file(
        self,
        filepath: Path,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        limit: int,
    ) -> List[Dict[str, Any]]:
        """Read events from file."""
        events = []

        try:
            # Open file (compressed or regular)
            if str(filepath).endswith(".gz"):
                open_func = gzip.open
                mode = "rt"
            else:
                open_func = open
                mode = "r"

            with open_func(filepath, mode, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue

                    try:
                        event = json.loads(line)

                        # Filter by time
                        event_time_str = event.get("@timestamp", "")
                        if event_time_str:
                            event_time = datetime.fromisoformat(
                                event_time_str.replace("Z", "+00:00")
                            )

                            if start_time and event_time < start_time:
                                continue
                            if end_time and event_time > end_time:
                                continue

                        events.append(event)

                        if len(events) >= limit:
                            break

                    except json.JSONDecodeError:
                        self.logger.warning(f"Invalid JSON in file: {filepath}")

        except Exception as e:
            self.logger.error(f"Error reading file {filepath}: {e}", exc_info=True)

        return events

    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        stats = {
            "base_path": str(self.base_path),
            "compression": self.compression,
            "directories": {},
        }

        for event_type in ["raw", "processed", "alerts", "models", "intel"]:
            directory = self.base_path / event_type

            if directory.exists():
                files = list(directory.iterdir())
                stats["directories"][event_type] = {
                    "file_count": len(files),
                    "files": [f.name for f in files[:10]],  # First 10 files
                }

        return stats