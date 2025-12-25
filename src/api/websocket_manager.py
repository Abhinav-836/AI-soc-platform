"""
WebSocket Manager for real-time communication.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from enum import Enum

from src.core.logger import LoggerMixin


class EventType(str, Enum):
    """WebSocket event types."""
    ALERT = "alert"
    EVENT = "event"
    STATS = "stats"
    HEALTH = "health"
    INTEL = "intel"
    RESPONSE = "response"
    SYSTEM = "system"


class WebSocketManager(LoggerMixin):
    """Manage WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: Dict[str, Set[Any]] = {}
        self.connection_metadata: Dict[Any, Dict[str, Any]] = {}
        self.event_handlers: Dict[EventType, List] = {}
        self.broadcast_queue = asyncio.Queue()
        self.running = False
        
    async def start(self):
        """Start WebSocket manager."""
        self.running = True
        asyncio.create_task(self._broadcast_worker())
        self.logger.info("WebSocket manager started")
    
    async def stop(self):
        """Stop WebSocket manager."""
        self.running = False
        for channel in self.active_connections.values():
            for conn in channel:
                try:
                    await conn.close()
                except:
                    pass
        self.active_connections.clear()
        self.logger.info("WebSocket manager stopped")
    
    async def connect(self, websocket, channel: str = "default", metadata: Dict[str, Any] = None):
        """Accept a WebSocket connection."""
        await websocket.accept()
        
        if channel not in self.active_connections:
            self.active_connections[channel] = set()
        
        self.active_connections[channel].add(websocket)
        self.connection_metadata[websocket] = metadata or {
            "channel": channel,
            "connected_at": datetime.utcnow().isoformat(),
        }
        
        self.logger.info(f"WebSocket connected to channel '{channel}': {websocket.client}")
        
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connection",
            "status": "connected",
            "channel": channel,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def disconnect(self, websocket, channel: str = None):
        """Remove a WebSocket connection."""
        if channel:
            if channel in self.active_connections and websocket in self.active_connections[channel]:
                self.active_connections[channel].remove(websocket)
        else:
            # Find and remove from any channel
            for ch, conns in self.active_connections.items():
                if websocket in conns:
                    conns.remove(websocket)
                    break
        
        if websocket in self.connection_metadata:
            del self.connection_metadata[websocket]
        
        self.logger.info(f"WebSocket disconnected")
    
    async def broadcast(self, message: Dict[str, Any], channel: str = None, event_type: str = None):
        """Broadcast message to all or specific channel."""
        if event_type:
            message["event_type"] = event_type
        
        message["timestamp"] = datetime.utcnow().isoformat()
        
        # Add to queue for processing
        await self.broadcast_queue.put({
            "message": message,
            "channel": channel
        })
    
    async def _broadcast_worker(self):
        """Worker to broadcast messages."""
        while self.running:
            try:
                item = await self.broadcast_queue.get()
                message = item["message"]
                channel = item["channel"]
                
                if channel and channel in self.active_connections:
                    connections = self.active_connections[channel]
                elif not channel:
                    # Broadcast to all channels
                    connections = set()
                    for conns in self.active_connections.values():
                        connections.update(conns)
                else:
                    connections = set()
                
                # Send to all connections
                disconnected = []
                for conn in connections:
                    try:
                        await conn.send_json(message)
                    except Exception as e:
                        self.logger.debug(f"Failed to send to WebSocket: {e}")
                        disconnected.append(conn)
                
                # Clean up disconnected
                for conn in disconnected:
                    self.disconnect(conn)
                
                self.broadcast_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in broadcast worker: {e}", exc_info=True)
                await asyncio.sleep(0.1)
    
    async def send_personal(self, message: Dict[str, Any], websocket):
        """Send message to specific client."""
        try:
            await websocket.send_json(message)
            return True
        except Exception as e:
            self.logger.debug(f"Failed to send personal message: {e}")
            return False
    
    def get_connection_count(self) -> int:
        """Get total number of active connections."""
        return sum(len(conns) for conns in self.active_connections.values())
    
    def get_channels(self) -> List[str]:
        """Get list of active channels."""
        return list(self.active_connections.keys())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket manager statistics."""
        return {
            "total_connections": self.get_connection_count(),
            "channels": {
                channel: len(conns) 
                for channel, conns in self.active_connections.items()
            },
            "queue_size": self.broadcast_queue.qsize(),
            "running": self.running,
        }