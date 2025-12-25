"""
Threat intelligence feed management.
"""

import asyncio
import json
import aiohttp
import aiofiles
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from src.utils.logger import LoggerMixin


class ThreatIntelFeed(LoggerMixin):
    """Base class for threat intelligence feeds."""

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__()
        self.name = name
        self.config = config
        self.enabled = config.get("enabled", True)
        self.url = config.get("url", "")
        self.update_interval = config.get("update_interval", 3600)
        self.last_update: Optional[datetime] = None
        self.data: List[Dict[str, Any]] = []
        self.stats = {
            "updates": 0,
            "iocs_fetched": 0,
            "errors": 0,
        }

    async def update(self) -> bool:
        """Update feed data."""
        if not self.enabled or not self.url:
            self.logger.warning(f"Feed {self.name} is disabled or has no URL")
            return False

        try:
            self.logger.info(f"Updating threat intel feed: {self.name}")

            # Fetch data
            new_data = await self._fetch_data()

            # Process data
            processed_data = await self._process_data(new_data)

            # Update stored data
            self.data = processed_data
            self.last_update = datetime.utcnow()
            self.stats["updates"] += 1
            self.stats["iocs_fetched"] += len(processed_data)

            self.logger.info(
                f"Feed {self.name} updated with {len(processed_data)} IOCs"
            )
            return True

        except Exception as e:
            self.logger.error(f"Error updating feed {self.name}: {e}", exc_info=True)
            self.stats["errors"] += 1
            return False

    async def _fetch_data(self) -> Any:
        """Fetch raw data from feed URL."""
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url) as response:
                response.raise_for_status()
                content_type = response.headers.get("Content-Type", "")

                if "application/json" in content_type:
                    return await response.json()
                elif "text/plain" in content_type:
                    return await response.text()
                else:
                    return await response.read()

    async def _process_data(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Process raw feed data into structured IOCs."""
        raise NotImplementedError

    def get_iocs(self, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get IOCs from feed, optionally filtered by type."""
        if ioc_type:
            return [ioc for ioc in self.data if ioc.get("type") == ioc_type]
        return self.data.copy()

    def search_iocs(self, query: str) -> List[Dict[str, Any]]:
        """Search IOCs by value or metadata."""
        results = []
        query_lower = query.lower()

        for ioc in self.data:
            value = str(ioc.get("value", "")).lower()
            if query_lower in value:
                results.append(ioc)
                continue

            # Search in metadata
            for key, val in ioc.get("metadata", {}).items():
                if query_lower in str(val).lower():
                    results.append(ioc)
                    break

        return results

    def should_update(self) -> bool:
        """Check if feed should be updated."""
        if not self.last_update:
            return True

        next_update = self.last_update + timedelta(seconds=self.update_interval)
        return datetime.utcnow() >= next_update

    def get_stats(self) -> Dict[str, Any]:
        """Get feed statistics."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "ioc_count": len(self.data),
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "next_update": (
                (self.last_update + timedelta(seconds=self.update_interval)).isoformat()
                if self.last_update
                else None
            ),
            **self.stats,
        }


class AbuseIPDBFeed(ThreatIntelFeed):
    """AbuseIPDB threat feed."""

    async def _fetch_data(self) -> Any:
        """Fetch data from AbuseIPDB API."""
        api_key = self.config.get("api_key")
        if not api_key:
            raise ValueError("AbuseIPDB API key not configured")

        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                response.raise_for_status()
                return await response.json()

    async def _process_data(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Process AbuseIPDB blacklist data."""
        iocs = []

        if isinstance(raw_data, dict) and "data" in raw_data:
            for item in raw_data["data"]:
                ioc = {
                    "type": "ip",
                    "value": item.get("ipAddress", ""),
                    "first_seen": item.get("reportedAt"),
                    "last_seen": item.get("lastReportedAt"),
                    "reports": item.get("totalReports", 0),
                    "abuse_score": item.get("abuseConfidenceScore", 0),
                    "country": item.get("countryCode"),
                    "isp": item.get("isp"),
                    "domain": item.get("domain"),
                    "feed": self.name,
                    "metadata": {
                        "categories": item.get("categories", []),
                        "is_whitelisted": item.get("isWhitelisted", False),
                        "is_tor": item.get("isTor", False),
                    },
                }
                iocs.append(ioc)

        return iocs


class VirusTotalFeed(ThreatIntelFeed):
    """VirusTotal threat feed."""

    async def _fetch_data(self) -> Any:
        """Fetch data from VirusTotal API."""
        api_key = self.config.get("api_key")
        if not api_key:
            raise ValueError("VirusTotal API key not configured")

        # Note: VT doesn't have a direct feed API for free tier
        # This would need to be implemented based on available endpoints
        raise NotImplementedError("VirusTotal feed not fully implemented")

    async def _process_data(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Process VirusTotal data."""
        # Implementation depends on VT API response format
        return []


class FileBasedFeed(ThreatIntelFeed):
    """Feed that reads from local files."""

    async def _fetch_data(self) -> Any:
        """Read data from local file."""
        file_path = self.config.get("file_path")
        if not file_path:
            raise ValueError("File path not configured")

        async with aiofiles.open(file_path, "r") as f:
            content = await f.read()
            return content

    async def _process_data(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Process file-based feed data."""
        iocs = []
        lines = raw_data.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse IOC based on format
            ioc = self._parse_ioc_line(line)
            if ioc:
                ioc["feed"] = self.name
                iocs.append(ioc)

        return iocs

    def _parse_ioc_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single IOC line."""
        # Simple parsing - can be extended based on feed format
        parts = line.split()

        if len(parts) >= 1:
            value = parts[0]

            # Determine IOC type
            if self._is_ip(value):
                ioc_type = "ip"
            elif self._is_domain(value):
                ioc_type = "domain"
            elif self._is_hash(value):
                ioc_type = "hash"
            elif self._is_url(value):
                ioc_type = "url"
            else:
                ioc_type = "unknown"

            ioc = {
                "type": ioc_type,
                "value": value,
                "metadata": {
                    "source_line": line,
                },
            }

            # Add additional metadata from line parts
            if len(parts) > 1:
                ioc["metadata"]["description"] = " ".join(parts[1:])

            return ioc

        return None

    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _is_domain(self, value: str) -> bool:
        """Check if value is a domain."""
        # Simple domain check
        import re
        domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(domain_pattern, value))

    def _is_hash(self, value: str) -> bool:
        """Check if value is a hash."""
        # MD5, SHA1, SHA256 patterns
        import re
        hash_patterns = [
            r"^[a-fA-F0-9]{32}$",  # MD5
            r"^[a-fA-F0-9]{40}$",  # SHA1
            r"^[a-fA-F0-9]{64}$",  # SHA256
        ]

        for pattern in hash_patterns:
            if re.match(pattern, value):
                return True
        return False

    def _is_url(self, value: str) -> bool:
        """Check if value is a URL."""
        import re
        url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
        return bool(re.match(url_pattern, value, re.IGNORECASE))


class ThreatIntelManager(LoggerMixin):
    """Manages multiple threat intelligence feeds."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.feeds: Dict[str, ThreatIntelFeed] = {}
        self.running = False
        self.update_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start threat intelligence manager."""
        self.logger.info("Starting threat intelligence manager...")
        self.running = True

        # Initialize feeds
        await self._init_feeds()

        # Start periodic updates
        self.update_task = asyncio.create_task(self._update_loop())

    async def stop(self):
        """Stop threat intelligence manager."""
        self.logger.info("Stopping threat intelligence manager...")
        self.running = False

        if self.update_task:
            self.update_task.cancel()
            try:
                await self.update_task
            except asyncio.CancelledError:
                pass

    async def _init_feeds(self):
        """Initialize feeds from configuration."""
        intel_config = self.config.get("response", {}).get("providers", {}).get("enrichment", {})

        # AbuseIPDB feed
        if intel_config.get("abuseipdb", {}).get("enabled", False):
            feed = AbuseIPDBFeed("abuseipdb", intel_config["abuseipdb"])
            self.feeds["abuseipdb"] = feed
            self.logger.info("Initialized AbuseIPDB feed")

        # VirusTotal feed
        if intel_config.get("virustotal", {}).get("enabled", False):
            feed = VirusTotalFeed("virustotal", intel_config["virustotal"])
            self.feeds["virustotal"] = feed
            self.logger.info("Initialized VirusTotal feed")

        # File-based feeds
        file_feeds = self.config.get("intel", {}).get("file_feeds", [])
        for feed_config in file_feeds:
            if feed_config.get("enabled", False):
                feed_name = feed_config.get("name", f"file_feed_{len(self.feeds)}")
                feed = FileBasedFeed(feed_name, feed_config)
                self.feeds[feed_name] = feed
                self.logger.info(f"Initialized file-based feed: {feed_name}")

    async def _update_loop(self):
        """Periodic feed update loop."""
        self.logger.info("Starting feed update loop")

        while self.running:
            try:
                # Update feeds that need updating
                for feed in self.feeds.values():
                    if feed.should_update():
                        await feed.update()

                # Sleep before next update cycle
                await asyncio.sleep(60)  # Check every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in feed update loop: {e}", exc_info=True)
                await asyncio.sleep(300)  # Sleep longer on error

    async def update_all_feeds(self):
        """Update all feeds immediately."""
        self.logger.info("Updating all threat intelligence feeds")

        tasks = [feed.update() for feed in self.feeds.values()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = sum(1 for r in results if r is True)
        failed = sum(1 for r in results if isinstance(r, Exception))

        self.logger.info(f"Feed update complete: {successful} successful, {failed} failed")
        return successful, failed

    def get_iocs(
        self,
        feed_name: Optional[str] = None,
        ioc_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get IOCs from feeds."""
        iocs = []

        if feed_name:
            if feed_name in self.feeds:
                iocs = self.feeds[feed_name].get_iocs(ioc_type)
        else:
            for feed in self.feeds.values():
                iocs.extend(feed.get_iocs(ioc_type))

        return iocs

    def search_iocs(self, query: str, feed_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search IOCs across feeds."""
        results = []

        if feed_name:
            if feed_name in self.feeds:
                results = self.feeds[feed_name].search_iocs(query)
        else:
            for feed in self.feeds.values():
                results.extend(feed.search_iocs(query))

        return results

    def match_ioc(self, value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Find IOCs matching a specific value."""
        matches = []

        for feed in self.feeds.values():
            feed_iocs = feed.get_iocs(ioc_type)
            for ioc in feed_iocs:
                if ioc.get("value") == value:
                    matches.append(ioc)

        return matches

    def get_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        feed_stats = {}
        total_iocs = 0

        for feed_name, feed in self.feeds.items():
            stats = feed.get_stats()
            feed_stats[feed_name] = stats
            total_iocs += stats.get("ioc_count", 0)

        return {
            "running": self.running,
            "feed_count": len(self.feeds),
            "total_iocs": total_iocs,
            "feeds": feed_stats,
        }