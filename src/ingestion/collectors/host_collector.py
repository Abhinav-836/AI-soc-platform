"""
Host monitor: real telemetry from the machine the platform runs on.

Every few seconds it records
  * new outbound/inbound network connections (remote IP/port + owning process)
  * new listening ports
  * newly started processes (name, path, parent, user)
using psutil (Windows, Linux, macOS). These are real events - remote IPs are
checked against threat intel, processes against rules and Sigma - so the
dashboard shows live data from your own PC without any log shipping.

Command lines are NOT collected by default (they can contain passwords or
tokens); enable include_cmdline in ingestion.yaml if you want them.
"""
import asyncio
import os
import socket
import time
from typing import Any, Dict, Optional, Set, Tuple

from src.core.logger import LoggerMixin
from src.core.time_utils import iso

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def _primary_ip() -> str:
    """Local address used for outbound traffic (no packets are sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class HostCollector(LoggerMixin):
    def __init__(self, config):
        cfg = ((config.get("ingestion", {}) or {}).get("sources", {}) or {}).get("host", {}) or {}
        self.interval = max(float(cfg.get("interval", 5)), 1.0)
        self.collect_connections = bool(cfg.get("connections", True))
        self.collect_processes = bool(cfg.get("processes", True))
        self.include_cmdline = bool(cfg.get("include_cmdline", False))
        self.hostname = socket.gethostname()
        self.local_ip = _primary_ip()
        self.running = False
        self._seen_conns: Dict[Tuple, float] = {}
        self._seen_listen: Set[Tuple] = set()
        self._seen_pids: Dict[int, float] = {}
        self._names: Dict[int, Tuple[str, Optional[str]]] = {}
        self._first = True
        self.stats = {"connections": 0, "listening": 0, "processes": 0, "errors": 0, "last_poll": None,
                      "connections_available": True, "hostname": self.hostname}

    async def start(self, queue: asyncio.Queue):
        if psutil is None:
            self.logger.warning("Host monitor needs psutil (pip install psutil)")
            return
        self.running = True
        loop = asyncio.get_running_loop()
        self.logger.info(f"Host monitor watching {self.hostname} ({self.local_ip}) every {self.interval:.0f}s")
        while self.running:
            try:
                events = await loop.run_in_executor(None, self.poll)
                for e in events:
                    try:
                        queue.put_nowait(e)
                    except asyncio.QueueFull:
                        break
            except Exception as e:
                self.stats["errors"] += 1
                self.logger.debug(f"Host monitor poll failed: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        self.running = False

    # ------------------------------------------------------------------ polling
    def _proc(self, pid: Optional[int]) -> Tuple[Optional[str], Optional[str]]:
        if not pid:
            return None, None
        if pid not in self._names:
            try:
                p = psutil.Process(pid)
                self._names[pid] = (p.name(), p.exe() if hasattr(p, "exe") else None)
            except (psutil.Error, OSError):
                self._names[pid] = (None, None)
        return self._names[pid]

    def _base(self, event_type: str) -> Dict[str, Any]:
        return {"event_type": event_type, "hostname": self.hostname, "source_type": "host", "@timestamp": iso()}

    def poll(self):
        events = []
        now = time.time()
        if self.collect_connections and self.stats["connections_available"]:
            try:
                conns = psutil.net_connections(kind="inet")
            except (psutil.AccessDenied, PermissionError):
                self.stats["connections_available"] = False  # macOS without root
                self.logger.warning("Host monitor: no permission to list network connections")
                conns = []
            for c in conns:
                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                if c.status == psutil.CONN_LISTEN and c.laddr:
                    key = (c.laddr.ip, c.laddr.port, proto)
                    if key not in self._seen_listen:
                        self._seen_listen.add(key)
                        if not self._first:  # only report ports opened after start-up
                            name, path = self._proc(c.pid)
                            events.append({**self._base("listening_port"), "src_ip": self.local_ip,
                                           "local_port": c.laddr.port, "protocol": proto,
                                           "process_name": name, "process_path": path})
                            self.stats["listening"] += 1
                    continue
                if not c.raddr or c.raddr.ip in ("127.0.0.1", "::1") or c.raddr.ip.startswith("127."):
                    continue
                if proto == "tcp" and c.status not in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT):
                    continue
                key = (c.pid, c.raddr.ip, c.raddr.port)
                if now - self._seen_conns.get(key, 0) < 600:  # report each flow at most every 10 min
                    continue
                self._seen_conns[key] = now
                name, path = self._proc(c.pid)
                local = c.laddr.ip if c.laddr and c.laddr.ip not in ("0.0.0.0", "::") else self.local_ip
                events.append({**self._base("network_connection"), "src_ip": local,
                               "src_port": c.laddr.port if c.laddr else None, "dst_ip": c.raddr.ip,
                               "dst_port": c.raddr.port, "protocol": proto, "action": "allow",
                               "process_name": name, "process_path": path,
                               "connection_state": str(c.status).lower()})
                self.stats["connections"] += 1
            self._seen_conns = {k: v for k, v in self._seen_conns.items() if now - v < 3600}

        if self.collect_processes:
            attrs = ["pid", "ppid", "name", "exe", "username", "create_time"] + (["cmdline"] if self.include_cmdline else [])
            current = {}
            for p in psutil.process_iter(attrs):
                info = p.info
                current[info["pid"]] = info.get("create_time") or 0
                if self._first or info["pid"] in self._seen_pids:
                    continue
                parent, _ = self._proc(info.get("ppid"))
                event = {**self._base("process_execution"), "src_ip": self.local_ip,
                         "process_name": info.get("name"), "process_path": info.get("exe"),
                         "parent_process": parent, "user": (info.get("username") or "").split("\\")[-1] or None,
                         "pid": info["pid"]}
                if self.include_cmdline and info.get("cmdline"):
                    event["command_line"] = " ".join(info["cmdline"])[:1000]
                events.append(event)
                self.stats["processes"] += 1
            self._seen_pids = current
            self._names = {pid: v for pid, v in self._names.items() if pid in current}

        self._first = False
        self.stats["last_poll"] = iso()
        return events

    def get_stats(self) -> Dict[str, Any]:
        return {"type": "host", "running": self.running, "interval": self.interval, "local_ip": self.local_ip,
                "pid": os.getpid(), **self.stats}
