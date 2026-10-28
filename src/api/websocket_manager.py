"""
WebSocket fan-out.

Each client gets its own bounded queue and writer task, so one slow browser
can't stall detection or other clients. Live events are rate-limited
(default 20/s per client); alerts, responses and stats are always delivered.

The old manager let clients "subscribe" by mutating a shared dict directly
from the endpoint, never removed those extra subscriptions on disconnect,
and swallowed close errors with bare `except:`.
"""
import asyncio
import time
from typing import Any, Dict, Optional

from fastapi import WebSocket

from src.core.logger import LoggerMixin
from src.core.time_utils import iso


class _Client:
    def __init__(self, ws: WebSocket, channels: set):
        self.ws = ws
        self.channels = channels
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.task: Optional[asyncio.Task] = None
        self.window_start = time.monotonic()
        self.events_in_window = 0
        self.dropped = 0


class WebSocketManager(LoggerMixin):
    def __init__(self, max_events_per_second: int = 20):
        self.clients: Dict[int, _Client] = {}
        self.max_eps = max_events_per_second
        self.running = True
        self.messages_sent = 0

    async def connect(self, ws: WebSocket, channels: Optional[set] = None) -> _Client:
        await ws.accept()
        client = _Client(ws, channels or {"all"})
        client.task = asyncio.create_task(self._writer(client))
        self.clients[id(ws)] = client
        await client.queue.put({"type": "connection", "status": "connected", "timestamp": iso()})
        return client

    def disconnect(self, ws: WebSocket):
        client = self.clients.pop(id(ws), None)
        if client and client.task:
            client.task.cancel()

    async def _writer(self, client: _Client):
        try:
            while True:
                message = await client.queue.get()
                await client.ws.send_json(message)
                self.messages_sent += 1
        except asyncio.CancelledError:
            pass
        except Exception:
            self.clients.pop(id(client.ws), None)

    def broadcast(self, message: Dict[str, Any], channel: str = "all"):
        """Non-blocking. channel: event | alert | response | stats | simulation."""
        message.setdefault("timestamp", iso())
        now = time.monotonic()
        for client in list(self.clients.values()):
            if "all" not in client.channels and channel not in client.channels:
                continue
            if channel == "event":
                if now - client.window_start >= 1:
                    client.window_start, client.events_in_window = now, 0
                if client.events_in_window >= self.max_eps:
                    client.dropped += 1
                    continue
                client.events_in_window += 1
            try:
                client.queue.put_nowait(message)
            except asyncio.QueueFull:
                client.dropped += 1

    async def stop(self):
        self.running = False
        for client in list(self.clients.values()):
            if client.task:
                client.task.cancel()
            try:
                await client.ws.close()
            except Exception:
                pass
        self.clients.clear()

    def get_connection_count(self) -> int:
        return len(self.clients)

    def get_stats(self) -> Dict[str, Any]:
        return {"connections": len(self.clients), "messages_sent": self.messages_sent,
                "dropped": sum(c.dropped for c in self.clients.values()), "max_events_per_second": self.max_eps}
