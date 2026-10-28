"""
Syslog collector (UDP and/or TCP).

Rewritten with asyncio's DatagramProtocol: the old loop used
loop.sock_recvfrom on a raw socket, which isn't available on Windows'
default event loop before Python 3.11, and it stamped events with the
event-loop clock (seconds since boot) instead of a real time.

Default port is 5514 so it runs without root/admin; point devices at it or
forward from rsyslog (e.g. `*.* @127.0.0.1:5514`).
"""
import asyncio
from typing import Any, Dict, Optional

from src.core.logger import LoggerMixin
from src.core.time_utils import iso


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: "SyslogCollector", queue: asyncio.Queue):
        self.collector = collector
        self.queue = queue

    def datagram_received(self, data: bytes, addr):
        self.collector.enqueue(data, addr, self.queue)


class SyslogCollector(LoggerMixin):
    def __init__(self, config):
        cfg = ((config.get("ingestion", {}) or {}).get("sources", {}) or {}).get("syslog", {}) or {}
        self.host = cfg.get("host", "127.0.0.1")
        self.port = int(cfg.get("port", 5514))
        self.protocol = str(cfg.get("protocol", "udp")).lower()
        self.running = False
        self.transport: Optional[asyncio.BaseTransport] = None
        self.server: Optional[asyncio.AbstractServer] = None
        self.stats = {"messages_received": 0, "last_received": None, "errors": 0, "dropped": 0}

    def enqueue(self, data: bytes, addr, queue: asyncio.Queue):
        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                queue.put_nowait({"raw_message": line, "source_type": "syslog",
                                  "source_address": f"{addr[0]}:{addr[1]}" if addr else None})
                self.stats["messages_received"] += 1
                self.stats["last_received"] = iso()
            except asyncio.QueueFull:
                self.stats["dropped"] += 1

    async def start(self, queue: asyncio.Queue):
        loop = asyncio.get_running_loop()
        self.running = True
        try:
            if self.protocol in ("udp", "both"):
                self.transport, _ = await loop.create_datagram_endpoint(
                    lambda: _UDPProtocol(self, queue), local_addr=(self.host, self.port))
                self.logger.info(f"Syslog UDP listening on {self.host}:{self.port}")
            if self.protocol in ("tcp", "both"):
                self.server = await asyncio.start_server(
                    lambda r, w: self._tcp_client(r, w, queue), self.host, self.port)
                self.logger.info(f"Syslog TCP listening on {self.host}:{self.port}")
        except OSError as e:
            self.stats["errors"] += 1
            self.logger.error(f"Syslog collector could not bind {self.host}:{self.port}: {e}")
            self.running = False
            return
        while self.running:
            await asyncio.sleep(1)

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, queue):
        addr = writer.get_extra_info("peername")
        try:
            while self.running:
                line = await reader.readline()
                if not line:
                    break
                self.enqueue(line, addr, queue)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def stop(self):
        self.running = False
        if self.transport:
            self.transport.close()
        if self.server:
            self.server.close()

    def get_stats(self) -> Dict[str, Any]:
        return {"type": "syslog", "running": self.running, "listen": f"{self.protocol}://{self.host}:{self.port}",
                **self.stats}
