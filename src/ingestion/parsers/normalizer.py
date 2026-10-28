"""
Log parsing and normalization.

Accepts either a structured event (dict from the API, Kafka, simulator) or
{"raw_message": "<line>"} from files/syslog, and produces one flat event with
consistent field names:

  @timestamp  event_id  event_type  src_ip  dst_ip  src_port  dst_port
  protocol  user  hostname  process_name  process_path  command_line
  parent_process  file_hash  query  url  http_method  status_code
  bytes_in  bytes_out  action  message  source_type

Raw lines are tried as JSON, CEF, then built-in patterns for sshd, sudo,
useradd, iptables/UFW and Apache/Nginx access logs (plus any extra regexes
from ingestion.yaml).

Old behaviour this fixes:
  * structured events posted to /api/v1/ingest became event_type "unknown"
    (only a "raw_message" string was ever parsed)
  * the original @timestamp was overwritten with the ingestion time, so
    replayed or late logs landed in the wrong time windows
  * the configured rename (src_ip -> source_ip) renamed the very field the
    rules and correlator group on
"""
import json
import re
import uuid
from typing import Any, Dict, List, Optional

from src.core.logger import LoggerMixin
from src.core.time_utils import iso, parse_ts

ALIASES = {
    "src_ip": ("source_ip", "client_ip", "srcip", "src", "sourceip", "remote_addr", "SourceIp"),
    "dst_ip": ("dest_ip", "destination_ip", "dstip", "dst", "server_ip", "DestinationIp"),
    "src_port": ("source_port", "spt", "sport", "SourcePort"),
    "dst_port": ("dest_port", "destination_port", "dpt", "dport", "DestinationPort"),
    "user": ("username", "user_name", "account", "suser", "duser", "User"),
    "hostname": ("host", "host_name", "computer", "computer_name", "dvchost"),
    "process_name": ("process", "proc", "exe"),
    "process_path": ("image", "Image", "process_path"),
    "command_line": ("cmdline", "commandline", "command", "CommandLine"),
    "parent_process": ("parent", "parent_image", "ParentImage", "parent_process_name"),
    "file_hash": ("hash", "sha256", "sha1", "md5", "fileHash"),
    "query": ("qname", "dns_query", "QueryName"),
    "url": ("uri", "request", "request_url", "path"),
    "http_method": ("method", "requestMethod"),
    "status_code": ("http_status", "response_code"),
    "bytes_out": ("bytes_sent", "out_bytes", "sent_bytes", "out"),
    "bytes_in": ("bytes_received", "in_bytes", "received_bytes", "in"),
    "@timestamp": ("timestamp", "time", "ts", "eventtime", "event_time", "rt", "date"),
    "message": ("msg",),
}
INT_FIELDS = ("src_port", "dst_port", "status_code", "bytes_in", "bytes_out")

_SYSLOG_HEADER = re.compile(
    r"^(?:<\d+>)?(?:\d\s)?(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|"
    r"(?:\d{4}-\d{2}-\d{2}T\S+))\s+(?P<hostname>\S+)\s+(?P<program>[\w\-./]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")

BUILTIN_PATTERNS = [
    ("ssh_failed", r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[0-9a-fA-F.:]+)"
                   r"(?: port (?P<src_port>\d+))?"),
    ("ssh_failed", r"Invalid user (?P<user>\S+) from (?P<src_ip>[0-9a-fA-F.:]+)"),
    ("ssh_accepted", r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from "
                     r"(?P<src_ip>[0-9a-fA-F.:]+)(?: port (?P<src_port>\d+))?"),
    ("sudo_command", r"sudo:\s+(?P<user>\S+) : .*?COMMAND=(?P<command_line>.+)$"),
    ("user_created", r"useradd\[\d+\]: new user: name=(?P<new_user>[^,\s]+)"),
    ("firewall_drop", r"(?:UFW BLOCK|IPTABLES|DROP|BLOCK).*?SRC=(?P<src_ip>\S+) DST=(?P<dst_ip>\S+)"
                      r"(?:.*?PROTO=(?P<protocol>\S+))?(?:.*?SPT=(?P<src_port>\d+))?(?:.*?DPT=(?P<dst_port>\d+))?"),
    ("http_request", r'^(?P<src_ip>[0-9a-fA-F.:]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<http_method>[A-Z]+) '
                     r'(?P<url>\S+)[^"]*" (?P<status_code>\d{3}) (?P<bytes_out>\d+|-)'
                     r'(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'),
]

_CEF = re.compile(r"CEF:(?P<version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<dversion>[^|]*)\|"
                  r"(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<ext>.*)$")
_CEF_KV = re.compile(r"(\w+)=((?:\\=|[^=])*?)(?=\s+\w+=|\s*$)")


def new_event_id() -> str:
    return uuid.uuid4().hex[:16]


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


class LogNormalizer(LoggerMixin):
    def __init__(self, config):
        parsers = (config.get("ingestion", {}) or {}).get("parsers", {}) or {}
        extra = ((parsers.get("regex") or {}).get("patterns") or {}) if (parsers.get("regex") or {}).get(
            "enabled", True) else {}
        self.patterns: List[tuple] = []
        for event_type, pattern in [*extra.items(), *BUILTIN_PATTERNS]:
            try:
                self.patterns.append((event_type, re.compile(pattern)))
            except re.error as e:
                self.logger.warning(f"Invalid regex for {event_type}: {e}")
        self.json_enabled = (parsers.get("json") or {}).get("enabled", True)
        self.cef_enabled = (parsers.get("cef") or {}).get("enabled", True)
        self.stats = {"parsed": 0, "json": 0, "cef": 0, "regex": 0, "structured": 0, "unparsed": 0}

    # ------------------------------------------------------------------ API
    async def normalize(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return self.normalize_sync(raw)

    def normalize_sync(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(raw, dict):
            return None
        meta = {k: raw[k] for k in ("source_type", "source_path", "source_address", "_truth", "_ingested_at")
                if k in raw}
        message = raw.get("raw_message")

        if isinstance(message, str) and message.strip() and "event_type" not in raw:
            event = self._parse_line(message.strip())
            event["raw_message"] = message.strip()
            if raw.get("@timestamp") and "@timestamp" not in event:
                event["@timestamp"] = raw["@timestamp"]
        else:
            event = {k: v for k, v in raw.items() if k not in meta}
            self.stats["structured"] += 1

        event.update(meta)
        return self._finalize(event)

    # -------------------------------------------------------------- parsing
    def _parse_line(self, line: str) -> Dict[str, Any]:
        if self.json_enabled and line.startswith("{"):
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    self.stats["json"] += 1
                    return data
            except json.JSONDecodeError:
                pass

        if self.cef_enabled and "CEF:" in line:
            cef = self._parse_cef(line[line.index("CEF:"):])
            if cef:
                self.stats["cef"] += 1
                return cef

        header = _SYSLOG_HEADER.match(line)
        body = header.group("msg") if header else line
        for event_type, pattern in self.patterns:
            m = pattern.search(body) or (pattern.search(line) if header else None)
            if m:
                event = {k: v for k, v in m.groupdict().items() if v not in (None, "-")}
                event["event_type"] = event_type
                if "ts" in event:
                    event["@timestamp"] = event.pop("ts")
                if header:
                    event.setdefault("hostname", header.group("hostname"))
                    event.setdefault("@timestamp", header.group("ts"))
                    event["program"] = header.group("program")
                self.stats["regex"] += 1
                return event

        self.stats["unparsed"] += 1
        event = {"event_type": "log", "message": body}
        if header:
            event.update(hostname=header.group("hostname"), program=header.group("program"),
                         **{"@timestamp": header.group("ts")})
        return event

    @staticmethod
    def _parse_cef(text: str) -> Optional[Dict[str, Any]]:
        m = _CEF.match(text)
        if not m:
            return None
        event = {
            "event_type": "cef_" + (m.group("signature_id") or "event").lower().replace(" ", "_"),
            "vendor": m.group("vendor"), "product": m.group("product"), "signature_id": m.group("signature_id"),
            "name": m.group("name"), "cef_severity": m.group("severity"),
        }
        for key, value in _CEF_KV.findall(m.group("ext")):
            event[key] = value.replace("\\=", "=").strip()
        # common CEF keys -> our names
        for cef_key, ours in (("src", "src_ip"), ("dst", "dst_ip"), ("spt", "src_port"), ("dpt", "dst_port"),
                              ("suser", "user"), ("dhost", "hostname"), ("request", "url"), ("act", "action"),
                              ("out", "bytes_out"), ("in", "bytes_in"), ("fileHash", "file_hash")):
            if cef_key in event and ours not in event:
                event[ours] = event.pop(cef_key)
        return event

    # -------------------------------------------------------------- shaping
    def _finalize(self, event: Dict[str, Any]) -> Dict[str, Any]:
        for target, names in ALIASES.items():
            if target not in event:
                for name in names:
                    if name in event and event[name] not in (None, ""):
                        event[target] = event.pop(name)
                        break

        for field in INT_FIELDS:
            if field in event:
                value = _to_int(event[field])
                if value is None:
                    event.pop(field)
                else:
                    event[field] = value
        for field in ("src_ip", "dst_ip"):
            if isinstance(event.get(field), str):
                event[field] = event[field].strip().strip("[]")
        if isinstance(event.get("process_path"), str) and not event.get("process_name"):
            event["process_name"] = re.split(r"[\\/]", event["process_path"])[-1]
        if isinstance(event.get("process_name"), str):
            event["process_name"] = event["process_name"].strip()
        if isinstance(event.get("query"), str):
            event["query"] = event["query"].strip(".").lower()

        event["event_type"] = str(event.get("event_type") or self._infer_type(event)).lower()
        ts = parse_ts(event.get("@timestamp"))
        event["@timestamp"] = iso(ts) if ts else iso()
        event["event_id"] = str(event.get("event_id") or new_event_id())
        event.setdefault("source_type", "api")
        self.stats["parsed"] += 1
        return event

    @staticmethod
    def _infer_type(event: Dict[str, Any]) -> str:
        if "url" in event or "http_method" in event:
            return "http_request"
        if "query" in event:
            return "dns_query"
        if "command_line" in event or "process_name" in event:
            return "process_execution"
        if "dst_port" in event or "bytes_out" in event:
            return "network_connection"
        return "unknown"

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)
