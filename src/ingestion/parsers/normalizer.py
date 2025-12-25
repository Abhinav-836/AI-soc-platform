"""
Log normalization and parsing.
"""

import re
import json
from datetime import datetime
from typing import Dict, Any, Optional, List
from ipaddress import ip_address

from src.utils.logger import LoggerMixin


class LogNormalizer(LoggerMixin):
    """Normalizes logs from various formats."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.parsers = self._init_parsers()

    def _init_parsers(self) -> List:
        """Initialize parsers based on configuration."""
        parsers = []

        config = self.config.get("ingestion", {}).get("parsers", {})

        # JSON parser
        if config.get("json", {}).get("enabled", False):
            parsers.append(JSONParser(config["json"]))

        # CEF parser
        if config.get("cef", {}).get("enabled", False):
            parsers.append(CEFParser(config["cef"]))

        # Regex parsers
        if config.get("regex", {}).get("patterns", {}):
            parsers.append(RegexParser(config["regex"]))

        return parsers

    async def normalize(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a raw log event.

        Args:
            raw_event: Raw log event

        Returns:
            Normalized event or None
        """
        normalized = None

        # Try each parser until one succeeds
        for parser in self.parsers:
            try:
                normalized = parser.parse(raw_event)
                if normalized:
                    break
            except Exception as e:
                self.logger.debug(f"Parser {parser.__class__.__name__} failed: {e}")

        # If no parser succeeded, create basic event
        if not normalized:
            normalized = self._create_basic_event(raw_event)

        # Apply normalization rules
        normalized = self._apply_normalization(normalized)

        return normalized

    def _create_basic_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Create a basic normalized event from raw data."""
        return {
            "event_type": "unknown",
            "raw_message": raw_event.get("raw_message", ""),
            "source_type": raw_event.get("source_type", "unknown"),
            "source_path": raw_event.get("source_path"),
            "source_address": raw_event.get("source_address"),
            "@timestamp": raw_event.get("@timestamp", datetime.utcnow().isoformat()),
            "original_event": raw_event,
        }

    def _apply_normalization(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Apply normalization rules to event."""
        config = self.config.get("ingestion", {}).get("normalization", {})

        # Normalize timestamp
        event = self._normalize_timestamp(event, config.get("timestamp_formats", []))

        # Normalize IP addresses
        ip_fields = config.get("ip_fields", [])
        for field in ip_fields:
            if field in event:
                event[field] = self._normalize_ip(event[field])

        # Add metadata
        event["normalized"] = True
        event["normalization_timestamp"] = datetime.utcnow().isoformat()

        return event

    def _normalize_timestamp(
        self, event: Dict[str, Any], formats: List[str]
    ) -> Dict[str, Any]:
        """Normalize timestamp field."""
        if "@timestamp" in event and isinstance(event["@timestamp"], str):
            timestamp_str = event["@timestamp"]

            # Try parsing with provided formats
            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp_str, fmt)
                    event["@timestamp"] = dt.isoformat() + "Z"
                    return event
                except ValueError:
                    continue

            # Try ISO format
            try:
                dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                event["@timestamp"] = dt.isoformat() + "Z"
            except ValueError:
                # Keep original timestamp
                pass

        return event

    def _normalize_ip(self, ip_str: str) -> str:
        """Normalize IP address."""
        try:
            ip = ip_address(ip_str)
            return str(ip)
        except ValueError:
            return ip_str


class JSONParser:
    """Parses JSON-formatted logs."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timestamp_field = config.get("timestamp_field", "@timestamp")
        self.message_field = config.get("message_field", "message")

    def parse(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse JSON log."""
        raw_message = raw_event.get("raw_message", "")

        if not raw_message.strip().startswith("{"):
            return None

        try:
            data = json.loads(raw_message)

            # Create normalized event
            event = {
                "event_type": "json_log",
                **data,
                "raw_message": raw_message,
            }

            # Extract timestamp if available
            if self.timestamp_field in data:
                event["@timestamp"] = data[self.timestamp_field]

            # Extract message if available
            if self.message_field in data:
                event["message"] = data[self.message_field]

            return event

        except json.JSONDecodeError:
            return None


class CEFParser:
    """Parses CEF (Common Event Format) logs."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.version = config.get("version", 0)
        self.vendor_fields = config.get("vendor_fields", {})

        # CEF regex pattern
        self.pattern = re.compile(
            r"CEF:(?P<version>\d+)\|(?P<device_vendor>[^|]*)\|"
            r"(?P<device_product>[^|]*)\|(?P<device_version>[^|]*)\|"
            r"(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|"
            r"(?P<severity>[^|]*)\|(?P<extension>.*)"
        )

        # Extension field regex
        self.ext_pattern = re.compile(r"(\w+)=((?:[^=\\]+\\.?)*)")

    def parse(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse CEF log."""
        raw_message = raw_event.get("raw_message", "")

        match = self.pattern.match(raw_message)
        if not match:
            return None

        try:
            event = {
                "event_type": "cef_log",
                "cef_version": match.group("version"),
                "device_vendor": match.group("device_vendor"),
                "device_product": match.group("device_product"),
                "device_version": match.group("device_version"),
                "signature_id": match.group("signature_id"),
                "name": match.group("name"),
                "severity": match.group("severity"),
                "raw_message": raw_message,
            }

            # Parse extension fields
            extensions = self._parse_extensions(match.group("extension"))
            event.update(extensions)

            return event

        except Exception:
            return None

    def _parse_extensions(self, extension_str: str) -> Dict[str, Any]:
        """Parse CEF extension fields."""
        extensions = {}

        # Split by space but handle escaped spaces
        parts = []
        current = []
        escape = False

        for char in extension_str:
            if char == "\\" and not escape:
                escape = True
            elif char == " " and not escape:
                if current:
                    parts.append("".join(current))
                    current = []
            else:
                current.append(char)
                escape = False

        if current:
            parts.append("".join(current))

        # Parse key-value pairs
        for part in parts:
            match = self.ext_pattern.match(part)
            if match:
                key = match.group(1)
                value = match.group(2).replace("\\", "")
                extensions[key] = value

        return extensions


class RegexParser:
    """Parses logs using regex patterns."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.patterns = self._compile_patterns(config.get("patterns", {}))

    def _compile_patterns(self, patterns: Dict[str, str]) -> Dict[str, re.Pattern]:
        """Compile regex patterns."""
        compiled = {}
        for name, pattern in patterns.items():
            try:
                compiled[name] = re.compile(pattern)
            except re.error as e:
                print(f"Invalid regex pattern {name}: {e}")
        return compiled

    def parse(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse log using regex patterns."""
        raw_message = raw_event.get("raw_message", "")

        for pattern_name, pattern in self.patterns.items():
            match = pattern.match(raw_message)
            if match:
                event = {
                    "event_type": pattern_name,
                    "raw_message": raw_message,
                    **match.groupdict(),
                }
                return event

        return None