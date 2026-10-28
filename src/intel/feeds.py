"""
Threat-intelligence manager.

Sources (all merged into one IOCMatcher used on every event):
  1. bundled / local files: config/intel/*.csv|*.txt and <data dir>/intel/*
     CSV columns: type,value,source,confidence,description  (type may be blank)
  2. IOCs added by analysts (stored in SQLite, survive restarts)
  3. optional online feeds (abuse.ch Feodo Tracker IPs, URLhaus domains...),
     refreshed in the background - disabled by default
  4. on-demand reputation lookups via AbuseIPDB / VirusTotal when API keys are
     set (Threat Intel -> Lookup)

Previously ThreatIntelManager was imported by the API but never created, so the
Threat Intel tab was always empty and no event was ever checked against an IOC.
"""
import asyncio
import csv
import io
from typing import Any, Dict, List, Optional

from src.core.logger import LoggerMixin, audit
from src.core.paths import data_dir, resolve
from src.core.time_utils import iso
from src.intel.ioc_matcher import IOCMatcher, classify
from src.storage.cache import TTLCache


class ThreatIntelManager(LoggerMixin):
    def __init__(self, config, store=None):
        self.cfg = ((config.get("detection", {}) or {}).get("intel", {}) or {})
        self.enabled = bool(self.cfg.get("enabled", True))
        self.store = store
        self.matcher = IOCMatcher()
        self.cache = TTLCache(ttl_seconds=6 * 3600)
        self.feeds: List[Dict[str, Any]] = [dict(f) for f in self.cfg.get("feeds", []) or []]
        self.refresh_interval = float(self.cfg.get("refresh_interval", 6 * 3600))
        self.abuseipdb_key = ((self.cfg.get("abuseipdb") or {}).get("api_key") or "").strip()
        self.virustotal_key = ((self.cfg.get("virustotal") or {}).get("api_key") or "").strip()
        self._task: Optional[asyncio.Task] = None
        self.stats = {"files_loaded": 0, "file_iocs": 0, "feed_iocs": 0, "manual_iocs": 0, "last_refresh": None}

    # ------------------------------------------------------------ loading
    def load(self):
        if not self.enabled:
            return
        dirs = [resolve(p) for p in (self.cfg.get("files") or ["config/intel"])] + [data_dir() / "intel"]
        for directory in dirs:
            for path in sorted(directory.glob("*")) if directory.is_dir() else []:
                if path.suffix.lower() in (".csv", ".txt"):
                    count = self._load_text(path.read_text(encoding="utf-8-sig", errors="replace"),
                                            source=f"file:{path.name}", csv_mode=path.suffix.lower() == ".csv")
                    self.stats["files_loaded"] += 1
                    self.stats["file_iocs"] += count
        if self.store:
            for row in self.store.list_iocs():
                if self.matcher.add(row["type"], row["value"], row.get("source") or "analyst",
                                    row.get("confidence") or 0.8, row.get("description") or ""):
                    self.stats["manual_iocs"] += 1
        self.logger.info(f"Threat intel loaded: {self.matcher.counts()}")

    def _load_text(self, text: str, source: str, csv_mode: bool, default_type: Optional[str] = None,
                   confidence: float = 0.8, hostfile: bool = False) -> int:
        count = 0
        if csv_mode:
            for row in csv.DictReader(io.StringIO(text)):
                value = (row.get("value") or "").strip()
                if not value or value.startswith("#"):
                    continue
                if self.matcher.add(row.get("type") or classify(value) or "", value, row.get("source") or source,
                                    float(row.get("confidence") or confidence), row.get("description") or ""):
                    count += 1
            return count
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if hostfile:  # "127.0.0.1\tbad.example"
                parts = line.split()
                if len(parts) < 2:
                    continue
                line = parts[1]
            value = line.split(",")[0].strip()
            if self.matcher.add(default_type or classify(value) or "", value, source, confidence):
                count += 1
        return count

    # ------------------------------------------------------------ feeds
    async def start(self):
        if not self.enabled or not any(f.get("enabled") for f in self.feeds):
            return
        self._task = asyncio.create_task(self._refresh_loop())

    async def stop(self):
        if self._task:
            self._task.cancel()

    async def _refresh_loop(self):
        while True:
            await self.refresh_feeds()
            await asyncio.sleep(self.refresh_interval)

    async def refresh_feeds(self) -> Dict[str, Any]:
        results = {}
        try:
            import aiohttp
        except ImportError:
            return {"error": "aiohttp not installed"}
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for feed in self.feeds:
                if not feed.get("enabled"):
                    continue
                name = feed.get("name", feed.get("url"))
                try:
                    headers = {"Auth-Key": feed["auth_key"]} if feed.get("auth_key") else {}
                    async with session.get(feed["url"], headers=headers) as resp:
                        resp.raise_for_status()
                        text = await resp.text()
                    self.matcher.clear_source(f"feed:{name}")
                    count = self._load_text(text, f"feed:{name}", csv_mode=feed.get("format") == "csv",
                                            default_type=feed.get("type"),
                                            confidence=float(feed.get("confidence", 0.8)),
                                            hostfile=feed.get("format") == "hostfile")
                    feed.update(last_update=iso(), last_count=count, last_error=None)
                    results[name] = count
                except Exception as e:
                    feed.update(last_error=str(e))
                    results[name] = f"error: {e}"
                    self.logger.warning(f"Intel feed {name} failed: {e}")
        self.stats["feed_iocs"] = sum(f.get("last_count", 0) for f in self.feeds if f.get("enabled"))
        self.stats["last_refresh"] = iso()
        return results

    # ------------------------------------------------------------ analyst actions
    def add_ioc(self, value: str, ioc_type: Optional[str] = None, confidence: float = 0.8,
                description: str = "", source: str = "analyst") -> Dict[str, Any]:
        ioc_type = (ioc_type or classify(value) or "").lower()
        if not self.matcher.add(ioc_type, value, source, confidence, description):
            raise ValueError(f"'{value}' is not a valid {ioc_type or 'IOC'}")
        stored = self.matcher.lookup(value) or {"type": ioc_type, "value": value}
        if self.store:
            self.store.add_ioc(stored["type"], stored["value"], source, confidence, description)
        audit("ioc_added", value=stored["value"], type=stored["type"], source=source)
        return stored

    def remove_ioc(self, ioc_type: str, value: str) -> bool:
        removed = self.matcher.remove(ioc_type, value)
        if self.store:
            removed = self.store.remove_ioc(ioc_type, value.lower()) or removed
        if removed:
            audit("ioc_removed", value=value, type=ioc_type)
        return removed

    def match_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        return self.matcher.match_event(event) if self.enabled else []

    def get_iocs(self, ioc_type: Optional[str] = None, search: Optional[str] = None, limit: int = 500):
        iocs = self.matcher.all()
        if ioc_type:
            iocs = [i for i in iocs if i["type"] == ioc_type]
        if search:
            s = search.lower()
            iocs = [i for i in iocs if s in i["value"].lower() or s in (i.get("description") or "").lower()]
        return {"iocs": iocs[:limit], "total": len(iocs)}

    async def lookup(self, value: str) -> Dict[str, Any]:
        """Local IOC match plus optional online reputation."""
        value = value.strip()
        kind = classify(value)
        result: Dict[str, Any] = {"value": value, "type": kind, "local": self.matcher.lookup(value), "online": {}}
        cached = self.cache.get(f"lookup:{value}")
        if cached is not None:
            result["online"] = cached
            return result
        online = {}
        try:
            import aiohttp
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                if kind == "ip" and self.abuseipdb_key:
                    async with session.get("https://api.abuseipdb.com/api/v2/check",
                                           params={"ipAddress": value, "maxAgeInDays": "90"},
                                           headers={"Key": self.abuseipdb_key, "Accept": "application/json"}) as r:
                        data = (await r.json()).get("data", {})
                        online["abuseipdb"] = {k: data.get(k) for k in (
                            "abuseConfidenceScore", "totalReports", "countryCode", "isp", "usageType", "isTor")}
                if kind in ("ip", "domain", "hash") and self.virustotal_key:
                    path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[kind]
                    async with session.get(f"https://www.virustotal.com/api/v3/{path}/{value}",
                                           headers={"x-apikey": self.virustotal_key}) as r:
                        if r.status == 200:
                            attrs = (await r.json()).get("data", {}).get("attributes", {})
                            online["virustotal"] = {"last_analysis_stats": attrs.get("last_analysis_stats"),
                                                    "reputation": attrs.get("reputation")}
                        else:
                            online["virustotal"] = {"status": r.status}
        except Exception as e:
            online["error"] = str(e)
        if not online and not (self.abuseipdb_key or self.virustotal_key):
            online["note"] = "Set ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY for online reputation lookups"
        self.cache.set(f"lookup:{value}", online)
        result["online"] = online
        return result

    def get_stats(self) -> Dict[str, Any]:
        return {"enabled": self.enabled, "counts": self.matcher.counts(), "total": len(self.matcher.all()),
                "hits": self.matcher.hit_count,
                "feeds": [{k: f.get(k) for k in ("name", "enabled", "url", "last_update", "last_count", "last_error")}
                          for f in self.feeds],
                "online_lookups": {"abuseipdb": bool(self.abuseipdb_key), "virustotal": bool(self.virustotal_key)},
                **self.stats}
