"""
Indicator-of-compromise matching: IPs, CIDR ranges, domains (including
sub-domains of a listed domain), file hashes and URLs.

Previously this module existed but nothing called it, so known-bad
indicators in events were never flagged.
"""
import ipaddress
import re
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")

IP_FIELDS = ("src_ip", "dst_ip")
DOMAIN_FIELDS = ("query", "domain", "dst_host")
HASH_FIELDS = ("file_hash",)


def classify(value: str) -> Optional[str]:
    """Guess the IOC type of a raw value."""
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    try:
        if "/" in v:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
    except ValueError:
        pass
    if HASH_RE.match(v):
        return "hash"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if DOMAIN_RE.match(v.lower()):
        return "domain"
    return None


class IOCMatcher:
    def __init__(self):
        self._lock = threading.RLock()
        self.ips: Dict[str, Dict[str, Any]] = {}
        self.networks: List[tuple] = []
        self.domains: Dict[str, Dict[str, Any]] = {}
        self.hashes: Dict[str, Dict[str, Any]] = {}
        self.urls: Dict[str, Dict[str, Any]] = {}
        self.hit_count = 0

    def add(self, ioc_type: str, value: str, source: str = "manual", confidence: float = 0.8,
            description: str = "", tags: Optional[List[str]] = None) -> bool:
        ioc_type = (ioc_type or classify(value) or "").lower()
        value = value.strip()
        info = {"type": ioc_type, "value": value, "source": source, "confidence": float(confidence),
                "description": description, "tags": tags or []}
        with self._lock:
            if ioc_type == "ip":
                try:
                    value = str(ipaddress.ip_address(value))
                except ValueError:
                    return False
                info["value"] = value
                self.ips[value] = info
            elif ioc_type == "cidr":
                try:
                    net = ipaddress.ip_network(value, strict=False)
                except ValueError:
                    return False
                info["value"] = str(net)
                self.networks = [n for n in self.networks if n[0] != net] + [(net, info)]
            elif ioc_type == "domain":
                info["value"] = value = value.lower().strip(".")
                self.domains[value] = info
            elif ioc_type == "hash":
                info["value"] = value = value.lower()
                self.hashes[value] = info
            elif ioc_type == "url":
                self.urls[value.lower()] = info
            else:
                return False
        return True

    def remove(self, ioc_type: str, value: str) -> bool:
        value = value.strip().lower()
        with self._lock:
            table = {"ip": self.ips, "domain": self.domains, "hash": self.hashes, "url": self.urls}.get(ioc_type)
            if table is not None:
                return table.pop(value, None) is not None
            if ioc_type == "cidr":
                before = len(self.networks)
                self.networks = [n for n in self.networks if n[1]["value"] != value]
                return len(self.networks) != before
        return False

    def clear_source(self, source: str):
        with self._lock:
            for table in (self.ips, self.domains, self.hashes, self.urls):
                for key in [k for k, v in table.items() if v["source"] == source]:
                    del table[key]
            self.networks = [n for n in self.networks if n[1]["source"] != source]

    # --------------------------------------------------------------- lookup
    def lookup_ip(self, value: Any) -> Optional[Dict[str, Any]]:
        if not value:
            return None
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            return None
        hit = self.ips.get(str(ip))
        if hit:
            return hit
        for net, info in self.networks:
            if ip.version == net.version and ip in net:
                return info
        return None

    def lookup_domain(self, value: Any) -> Optional[Dict[str, Any]]:
        if not value:
            return None
        host = str(value).lower().strip(".")
        parts = host.split(".")
        for i in range(len(parts) - 1):  # evil.com matches a.b.evil.com
            hit = self.domains.get(".".join(parts[i:]))
            if hit:
                return hit
        return None

    def lookup(self, value: str) -> Optional[Dict[str, Any]]:
        kind = classify(value)
        if kind == "ip":
            return self.lookup_ip(value)
        if kind == "domain":
            return self.lookup_domain(value)
        if kind == "hash":
            return self.hashes.get(value.lower())
        if kind == "url":
            return self.urls.get(value.lower()) or self.lookup_domain(urlparse(value).hostname)
        return None

    def match_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits = []
        with self._lock:
            for field in IP_FIELDS:
                info = self.lookup_ip(event.get(field))
                if info:
                    hits.append({**info, "field": field, "matched": event.get(field)})
            for field in DOMAIN_FIELDS:
                info = self.lookup_domain(event.get(field))
                if info:
                    hits.append({**info, "field": field, "matched": event.get(field)})
            for field in HASH_FIELDS:
                value = event.get(field)
                info = self.hashes.get(str(value).lower()) if value else None
                if info:
                    hits.append({**info, "field": field, "matched": value})
            url = event.get("url")
            if url:
                info = self.urls.get(str(url).lower())
                host = urlparse(str(url)).hostname if "://" in str(url) else None
                info = info or (self.lookup_domain(host) if host else None)
                if info:
                    hits.append({**info, "field": "url", "matched": url})
        self.hit_count += len(hits)
        return hits

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [*self.ips.values(), *(i for _, i in self.networks), *self.domains.values(),
                    *self.hashes.values(), *self.urls.values()]

    def counts(self) -> Dict[str, int]:
        return {"ip": len(self.ips), "cidr": len(self.networks), "domain": len(self.domains),
                "hash": len(self.hashes), "url": len(self.urls)}
