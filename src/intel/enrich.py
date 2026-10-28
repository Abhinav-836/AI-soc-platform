"""
Event enrichment: adds context analysts and rules can use.

  src_scope / dst_scope   internal | external
  direction               inbound | outbound | internal | external
  asset                   name/criticality of a known asset (config: detection.assets)
  intel                   IOC hits for any field of the event
"""
from typing import Any, Dict, List

from src.detection.rules.matcher import is_private_ip
from src.intel.ioc_matcher import IOCMatcher


class EventEnricher:
    def __init__(self, config, matcher: IOCMatcher = None):
        assets = ((config.get("detection", {}) or {}).get("assets", {}) or {})
        self.assets: Dict[str, Dict[str, Any]] = {}
        for item in assets.get("hosts", []) or []:
            for key in (item.get("ip"), item.get("hostname")):
                if key:
                    self.assets[str(key).lower()] = item
        self.matcher = matcher

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        src, dst = event.get("src_ip"), event.get("dst_ip")
        if src:
            event["src_scope"] = "internal" if is_private_ip(src) else "external"
        if dst:
            event["dst_scope"] = "internal" if is_private_ip(dst) else "external"
        if src and dst:
            s, d = event["src_scope"], event["dst_scope"]
            event["direction"] = {("external", "internal"): "inbound", ("internal", "external"): "outbound",
                                  ("internal", "internal"): "internal"}.get((s, d), "external")
        for key in (dst, event.get("hostname"), src):
            asset = self.assets.get(str(key).lower()) if key else None
            if asset:
                event["asset"] = {"name": asset.get("name") or asset.get("hostname"),
                                  "criticality": asset.get("criticality", "medium")}
                break
        return event

    def intel_hits(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        return self.matcher.match_event(event) if self.matcher else []
