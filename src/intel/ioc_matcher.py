"""
IOC (Indicator of Compromise) matching engine.
"""

import re
import ipaddress
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime

from src.core.logger import LoggerMixin


class IOCMatcher(LoggerMixin):
    """Matches events against IOCs (Indicators of Compromise)."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.iocs: Dict[str, List[Dict[str, Any]]] = {}
        self.compiled_patterns: Dict[str, Any] = {}
        self.stats = {
            "iocs_loaded": 0,
            "matches_found": 0,
            "events_processed": 0,
            "last_match": None,
        }

    async def load_iocs(self, iocs: List[Dict[str, Any]], source: str = "unknown"):
        """Load IOCs into matcher."""
        self.logger.info(f"Loading IOCs from {source}...")

        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            if ioc_type not in self.iocs:
                self.iocs[ioc_type] = []

            self.iocs[ioc_type].append({
                **ioc,
                "source": source,
                "loaded_at": datetime.utcnow().isoformat(),
            })

            self.stats["iocs_loaded"] += 1

        # Compile patterns for faster matching
        await self._compile_patterns()

        self.logger.info(f"Loaded {len(iocs)} IOCs from {source}")

    async def _compile_patterns(self):
        """Compile regex patterns for IOC matching."""
        if "regex" in self.iocs:
            for ioc in self.iocs["regex"]:
                pattern = ioc.get("value", "")
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    ioc["compiled_pattern"] = compiled
                except re.error as e:
                    self.logger.error(f"Invalid regex pattern: {pattern} - {e}")

    async def match_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Match event against loaded IOCs.

        Args:
            event: Event to match

        Returns:
            List of matching IOCs
        """
        self.stats["events_processed"] += 1

        matches = []

        # Check each IOC type
        for ioc_type, ioc_list in self.iocs.items():
            for ioc in ioc_list:
                match_result = await self._check_ioc_match(event, ioc, ioc_type)
                if match_result["matched"]:
                    matches.append(match_result)

        if matches:
            self.stats["matches_found"] += len(matches)
            self.stats["last_match"] = datetime.utcnow().isoformat()

            self.logger.info(f"Found {len(matches)} IOC matches for event")

        return matches

    async def _check_ioc_match(
        self, event: Dict[str, Any], ioc: Dict[str, Any], ioc_type: str
    ) -> Dict[str, Any]:
        """Check if event matches a specific IOC."""
        ioc_value = ioc.get("value", "")
        result = {
            "matched": False,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "match_details": {},
            "confidence": ioc.get("confidence", 0.5),
        }

        try:
            if ioc_type == "ip":
                match_result = await self._match_ip(event, ioc_value)
            elif ioc_type == "domain":
                match_result = await self._match_domain(event, ioc_value)
            elif ioc_type == "hash":
                match_result = await self._match_hash(event, ioc_value)
            elif ioc_type == "url":
                match_result = await self._match_url(event, ioc_value)
            elif ioc_type == "regex":
                match_result = await self._match_regex(event, ioc)
            elif ioc_type == "cidr":
                match_result = await self._match_cidr(event, ioc_value)
            else:
                match_result = {"matched": False}

            if match_result["matched"]:
                result["matched"] = True
                result["match_details"] = match_result.get("details", {})
                result["confidence"] = match_result.get("confidence", result["confidence"])

        except Exception as e:
            self.logger.error(f"Error matching IOC: {e}", exc_info=True)
            result["error"] = str(e)

        return result

    async def _match_ip(self, event: Dict[str, Any], ioc_ip: str) -> Dict[str, Any]:
        """Match IP address IOC."""
        # Check common IP fields
        ip_fields = ["src_ip", "dst_ip", "client_ip", "server_ip", "source_ip", "destination_ip"]
        
        for field in ip_fields:
            event_ip = event.get(field)
            if event_ip and str(event_ip) == ioc_ip:
                return {
                    "matched": True,
                    "details": {
                        "field": field,
                        "event_value": event_ip,
                        "ioc_value": ioc_ip,
                    },
                    "confidence": 0.9,
                }

        return {"matched": False}

    async def _match_domain(self, event: Dict[str, Any], ioc_domain: str) -> Dict[str, Any]:
        """Match domain IOC."""
        # Check common domain fields
        domain_fields = ["domain", "hostname", "url", "referrer", "user_agent"]
        
        for field in domain_fields:
            event_value = event.get(field, "")
            if isinstance(event_value, str) and ioc_domain.lower() in event_value.lower():
                return {
                    "matched": True,
                    "details": {
                        "field": field,
                        "event_value": event_value,
                        "ioc_value": ioc_domain,
                        "match_type": "substring",
                    },
                    "confidence": 0.7,
                }

        # Check for exact match in specific fields
        exact_fields = ["domain", "hostname"]
        for field in exact_fields:
            event_value = event.get(field)
            if event_value and event_value.lower() == ioc_domain.lower():
                return {
                    "matched": True,
                    "details": {
                        "field": field,
                        "event_value": event_value,
                        "ioc_value": ioc_domain,
                        "match_type": "exact",
                    },
                    "confidence": 0.9,
                }

        return {"matched": False}

    async def _match_hash(self, event: Dict[str, Any], ioc_hash: str) -> Dict[str, Any]:
        """Match hash IOC."""
        # Check common hash fields
        hash_fields = ["hash", "md5", "sha1", "sha256", "file_hash", "process_hash"]
        
        for field in hash_fields:
            event_hash = event.get(field)
            if event_hash and event_hash.lower() == ioc_hash.lower():
                return {
                    "matched": True,
                    "details": {
                        "field": field,
                        "event_value": event_hash,
                        "ioc_value": ioc_hash,
                    },
                    "confidence": 1.0,  # Hash matches are very confident
                }

        return {"matched": False}

    async def _match_url(self, event: Dict[str, Any], ioc_url: str) -> Dict[str, Any]:
        """Match URL IOC."""
        # Check URL fields
        url_fields = ["url", "uri", "request", "referrer"]
        
        ioc_url_lower = ioc_url.lower()
        
        for field in url_fields:
            event_value = event.get(field, "")
            if isinstance(event_value, str) and ioc_url_lower in event_value.lower():
                return {
                    "matched": True,
                    "details": {
                        "field": field,
                        "event_value": event_value,
                        "ioc_value": ioc_url,
                        "match_type": "substring",
                    },
                    "confidence": 0.8,
                }

        return {"matched": False}

    async def _match_regex(self, event: Dict[str, Any], ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Match regex IOC."""
        compiled_pattern = ioc.get("compiled_pattern")
        if not compiled_pattern:
            return {"matched": False}

        # Check all string fields in event
        for key, value in event.items():
            if isinstance(value, str):
                match = compiled_pattern.search(value)
                if match:
                    return {
                        "matched": True,
                        "details": {
                            "field": key,
                            "event_value": value,
                            "pattern": ioc.get("value"),
                            "match_groups": match.groups(),
                        },
                        "confidence": ioc.get("confidence", 0.6),
                    }

        return {"matched": False}

    async def _match_cidr(self, event: Dict[str, Any], ioc_cidr: str) -> Dict[str, Any]:
        """Match CIDR range IOC."""
        try:
            network = ipaddress.ip_network(ioc_cidr, strict=False)
            
            # Check IP fields
            ip_fields = ["src_ip", "dst_ip", "client_ip", "server_ip"]
            
            for field in ip_fields:
                event_ip = event.get(field)
                if event_ip:
                    try:
                        ip = ipaddress.ip_address(str(event_ip))
                        if ip in network:
                            return {
                                "matched": True,
                                "details": {
                                    "field": field,
                                    "event_value": event_ip,
                                    "ioc_value": ioc_cidr,
                                    "network": str(network),
                                },
                                "confidence": 0.85,
                            }
                    except ValueError:
                        continue

        except ValueError as e:
            self.logger.error(f"Invalid CIDR: {ioc_cidr} - {e}")

        return {"matched": False}

    async def batch_match(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Match multiple events against IOCs."""
        start_time = datetime.utcnow()
        
        all_matches = []
        matched_events = 0

        for event in events:
            matches = await self.match_event(event)
            if matches:
                all_matches.append({
                    "event": event,
                    "matches": matches,
                })
                matched_events += 1

        processing_time = (datetime.utcnow() - start_time).total_seconds()

        return {
            "total_events": len(events),
            "matched_events": matched_events,
            "total_matches": len(all_matches),
            "match_rate": matched_events / len(events) if events else 0,
            "processing_time_seconds": processing_time,
            "matches": all_matches,
            "timestamp": start_time.isoformat(),
        }

    async def search_iocs(self, query: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search IOCs by value or metadata."""
        results = []
        query_lower = query.lower()

        for type_name, ioc_list in self.iocs.items():
            if ioc_type and type_name != ioc_type:
                continue

            for ioc in ioc_list:
                # Search in value
                if query_lower in str(ioc.get("value", "")).lower():
                    results.append(ioc)
                    continue

                # Search in metadata
                metadata = ioc.get("metadata", {})
                for key, value in metadata.items():
                    if query_lower in str(value).lower():
                        results.append(ioc)
                        break

                # Search in tags
                tags = ioc.get("tags", [])
                for tag in tags:
                    if query_lower in str(tag).lower():
                        results.append(ioc)
                        break

        return results

    def get_ioc_stats(self) -> Dict[str, Any]:
        """Get IOC statistics."""
        type_counts = {ioc_type: len(iocs) for ioc_type, iocs in self.iocs.items()}
        total_iocs = sum(type_counts.values())

        return {
            "total_iocs": total_iocs,
            "type_counts": type_counts,
            **self.stats,
        }

    def get_iocs_by_type(self, ioc_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get IOCs by type."""
        return self.iocs.get(ioc_type, [])[:limit]

    def clear_iocs(self, source: Optional[str] = None):
        """Clear IOCs, optionally by source."""
        if source:
            for ioc_type in list(self.iocs.keys()):
                self.iocs[ioc_type] = [
                    ioc for ioc in self.iocs[ioc_type]
                    if ioc.get("source") != source
                ]
        else:
            self.iocs.clear()
            self.compiled_patterns.clear()

        self.logger.info(f"Cleared IOCs {f'from source {source}' if source else 'completely'}")