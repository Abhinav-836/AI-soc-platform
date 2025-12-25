"""
Syslog collector using asyncio.
"""

import asyncio
import socket
from typing import Dict, Any, Optional

from src.core.logger import LoggerMixin


class SyslogCollector(LoggerMixin):
    """Collects logs via Syslog protocol."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.running = False
        self.server: Optional[asyncio.Server] = None
        self.stats = {
            "messages_received": 0,
            "connections": 0,
            "last_received": None,
            "errors": 0,
        }

    async def start(self, queue: asyncio.Queue):
        """Start Syslog server."""
        self.logger.info("Starting Syslog collector...")

        config = self.config.get("ingestion", {}).get("sources", {}).get("syslog", {})
        host = config.get("host", "0.0.0.0")
        port = config.get("port", 514)
        protocol = config.get("protocol", "udp").lower()
        backlog = config.get("backlog", 100)

        self.running = True

        try:
            if protocol == "udp":
                await self._start_udp_server(host, port, queue)
            elif protocol == "tcp":
                await self._start_tcp_server(host, port, backlog, queue)
            else:
                raise ValueError(f"Unsupported protocol: {protocol}")

        except Exception as e:
            self.logger.error(f"Failed to start Syslog server: {e}", exc_info=True)
            await self.stop()

    async def stop(self):
        """Stop Syslog server."""
        self.logger.info("Stopping Syslog collector...")
        self.running = False

        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _start_udp_server(self, host: str, port: int, queue: asyncio.Queue):
        """Start UDP Syslog server."""
        self.logger.info(f"Starting UDP Syslog server on {host}:{port}")

        loop = asyncio.get_event_loop()

        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))

        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(sock, 65536)
                await self._process_datagram(data, addr, queue)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error receiving UDP data: {e}", exc_info=True)
                self.stats["errors"] += 1

        sock.close()

    async def _start_tcp_server(
        self, host: str, port: int, backlog: int, queue: asyncio.Queue
    ):
        """Start TCP Syslog server."""
        self.logger.info(f"Starting TCP Syslog server on {host}:{port}")

        self.server = await asyncio.start_server(
            lambda r, w: self._handle_tcp_client(r, w, queue),
            host,
            port,
            backlog=backlog,
        )

        async with self.server:
            await self.server.serve_forever()

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, queue: asyncio.Queue
    ):
        """Handle TCP client connection."""
        addr = writer.get_extra_info("peername")
        self.logger.debug(f"New TCP connection from {addr}")
        self.stats["connections"] += 1

        try:
            while self.running:
                try:
                    data = await asyncio.wait_for(reader.read(65536), timeout=30.0)
                    if not data:
                        break

                    await self._process_datagram(data, addr, queue)

                except asyncio.TimeoutError:
                    self.logger.debug(f"Connection timeout from {addr}")
                    break
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Error processing TCP data: {e}", exc_info=True)
                    self.stats["errors"] += 1
                    break

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

            self.logger.debug(f"TCP connection closed from {addr}")

    async def _process_datagram(self, data: bytes, addr: tuple, queue: asyncio.Queue):
        """Process a Syslog datagram."""
        try:
            message = data.decode("utf-8", errors="replace").strip()

            if message:
                # Create log event
                event = {
                    "raw_message": message,
                    "source_type": "syslog",
                    "source_address": f"{addr[0]}:{addr[1]}",
                    "@timestamp": asyncio.get_event_loop().time(),
                }

                # Put in queue
                await queue.put(event)

                # Update stats
                self.stats["messages_received"] += 1
                self.stats["last_received"] = asyncio.get_event_loop().time()

                self.logger.debug(f"Received Syslog message from {addr}: {message[:100]}...")

        except Exception as e:
            self.logger.error(f"Error processing Syslog datagram: {e}", exc_info=True)
            self.stats["errors"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            "type": "syslog",
            "running": self.running,
            **self.stats,
        }