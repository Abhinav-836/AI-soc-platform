"""
FastAPI application for AI SOC Platform API with real-time WebSocket support.
"""

import logging
from fastapi import FastAPI, HTTPException, Query, Body, Path, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from typing import List, Dict, Any, Optional
from pathlib import Path
import uvicorn
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

from src.core.logger import LoggerMixin
from src.core.config_loader import ConfigLoader
from src.api.websocket_manager import WebSocketManager, EventType
from src.ingestion.pipeline import IngestionPipeline
from src.detection.detector import DetectionEngine
from src.response.executor import ResponseExecutor
from src.ml.inference import MLInferenceEngine
from src.intel.feeds import ThreatIntelManager
from src.monitoring.metrics import MetricsCollector
from src.storage.elastic import ElasticsearchStorage


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger = logging.getLogger(__name__)
    logger.info("Starting AI SOC Platform API...")
    
    yield
    
    logger.info("Shutting down AI SOC Platform API...")


class SOCAPI(LoggerMixin):
    """SOC Platform REST API with WebSocket support."""
    
    def __init__(self, config_path: str = "./config"):
        super().__init__()
        self.config_path = config_path
        self.config: Optional[ConfigLoader] = None
        self.ws_manager = WebSocketManager()
        
        # Initialize components
        self.ingestion = None
        self.detection = None
        self.response = None
        self.ml_engine = None
        self.intel_manager = None
        self.metrics_collector = None
        self.elastic_storage = None
        
        self.app = FastAPI(
            title="AI SOC Platform API",
            description="AI-powered Security Operations Center with Real-time capabilities",
            version="1.0.0",
            docs_url="/api/docs",
            redoc_url="/api/redoc",
            lifespan=lifespan
        )
        
        # Mount static files for UI - points to src/ui
        ui_path = Path(__file__).parent.parent / "ui"
        if ui_path.exists():
            self.app.mount("/ui", StaticFiles(directory=str(ui_path), html=True), name="ui")
            self.logger.info(f"UI mounted from {ui_path}")
        else:
            self.logger.warning(f"UI directory not found at {ui_path}")
        
        self._setup_middleware()
        self._setup_routes()
        self._setup_websocket_routes()
        
        # Store components in app state
        self.app.state.config = self.config
        self.app.state.ws_manager = self.ws_manager
    
    def _setup_middleware(self):
        """Setup API middleware."""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        self.app.add_middleware(GZipMiddleware, minimum_size=1000)
        
        @self.app.middleware("http")
        async def log_requests(request, call_next):
            start_time = datetime.utcnow()
            response = await call_next(request)
            process_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.2f}ms")
            response.headers["X-Process-Time"] = str(process_time)
            return response
    
    def _setup_routes(self):
        """Setup API routes."""
        
        @self.app.get("/")
        async def root():
            return {
                "name": "AI SOC Platform API",
                "version": "1.0.0",
                "status": "operational",
                "features": ["rest-api", "websocket", "real-time", "ml-detection"],
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "websocket_connections": self.ws_manager.get_connection_count() if self.ws_manager else 0,
                "components": {
                    "api": "running",
                    "websocket": "running" if self.ws_manager and self.ws_manager.running else "stopped",
                }
            }
        
        @self.app.get("/api/v1/stats")
        async def get_stats():
            """Get real-time platform statistics."""
            stats = {
                "timestamp": datetime.utcnow().isoformat(),
                "websocket": self.ws_manager.get_stats() if self.ws_manager else {},
                "alerts": self.detection.get_stats() if self.detection else {},
                "ingestion": self.ingestion.get_stats() if self.ingestion else {},
                "response": self.response.get_stats() if self.response else {},
            }
            return stats
        
        @self.app.get("/api/v1/alerts")
        async def get_alerts(
            limit: int = Query(100, ge=1, le=1000),
            offset: int = Query(0, ge=0),
            severity: Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
            status: Optional[str] = Query(None, regex="^(new|investigating|contained|resolved|false_positive)$"),
        ):
            """Get alerts with filtering."""
            if not self.detection:
                return {"alerts": [], "total": 0}
            
            alerts = self.detection.get_alerts(limit=limit + offset, severity=severity)
            
            if status:
                alerts = [a for a in alerts if a.get("status", "new") == status]
            
            return {
                "alerts": alerts[offset:offset+limit],
                "total": len(alerts),
                "limit": limit,
                "offset": offset,
            }
        
        @self.app.get("/api/v1/alerts/{alert_id}")
        async def get_alert(alert_id: str):
            """Get specific alert by ID."""
            if not self.detection:
                raise HTTPException(status_code=503, detail="Detection engine unavailable")
            
            alerts = self.detection.get_alerts(limit=1000)
            for alert in alerts:
                if alert.get("alert_id") == alert_id:
                    return alert
            
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        
        @self.app.post("/api/v1/alerts/{alert_id}/status")
        async def update_alert_status(
            alert_id: str,
            body: Dict[str, Any] = Body(...)
        ):
            """Update alert status."""
            new_status = body.get("status")
            if not new_status:
                raise HTTPException(status_code=400, detail="Status required")
            
            if self.ws_manager:
                await self.ws_manager.broadcast({
                    "type": "alert_status_update",
                    "alert_id": alert_id,
                    "status": new_status,
                    "updated_by": body.get("updated_by", "api"),
                }, channel="alerts", event_type="alert")
            
            return {
                "alert_id": alert_id,
                "status": new_status,
                "updated": True,
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.post("/api/v1/playbooks/{playbook_name}/execute")
        async def execute_playbook(
            playbook_name: str,
            context: Dict[str, Any] = Body(...),
            require_approval: bool = Query(True),
        ):
            """Execute a response playbook."""
            if not self.response:
                raise HTTPException(status_code=503, detail="Response executor unavailable")
            
            result = await self.response.execute_playbook(playbook_name, context, require_approval)
            
            if self.ws_manager:
                await self.ws_manager.broadcast({
                    "type": "playbook_execution",
                    "playbook": playbook_name,
                    "success": result.get("success", False),
                    "timestamp": datetime.utcnow().isoformat(),
                }, channel="responses", event_type="response")
            
            return result
        
        @self.app.post("/api/v1/ingest")
        async def ingest_event(event: Dict[str, Any] = Body(...)):
            """Ingest a single event."""
            if not self.ingestion:
                raise HTTPException(status_code=503, detail="Ingestion pipeline unavailable")
            
            normalized = await self.ingestion.ingest_raw(event)
            
            if normalized:
                if self.ws_manager:
                    await self.ws_manager.broadcast({
                        "type": "new_event",
                        "event": normalized,
                    }, channel="events", event_type="event")
                
                return normalized
            
            raise HTTPException(status_code=400, detail="Failed to process event")
        
        @self.app.get("/api/v1/events")
        async def get_events(
            limit: int = Query(100, ge=1, le=1000),
            offset: int = Query(0, ge=0),
            event_type: Optional[str] = Query(None),
        ):
            """Get recent events."""
            return {"events": [], "total": 0}
        
        @self.app.get("/api/v1/intel/iocs")
        async def get_iocs(
            ioc_type: Optional[str] = None,
            limit: int = Query(100, ge=1, le=1000),
        ):
            """Get threat intelligence IOCs."""
            if not self.intel_manager:
                return {"iocs": [], "total": 0}
            
            iocs = self.intel_manager.get_iocs()
            if ioc_type:
                iocs = [i for i in iocs if i.get("type") == ioc_type]
            
            return {
                "iocs": iocs[:limit],
                "total": len(iocs),
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.get("/api/v1/system/stats")
        async def get_system_stats():
            """Get system statistics."""
            return {
                "platform": {
                    "status": "running",
                },
                "websocket": self.ws_manager.get_stats() if self.ws_manager else {},
                "components": {
                    "ingestion": self.ingestion.running if self.ingestion else False,
                    "detection": self.detection.running if self.detection else False,
                    "response": self.response.running if self.response else False,
                },
                "timestamp": datetime.utcnow().isoformat(),
            }
    
    def _setup_websocket_routes(self):
        """Setup WebSocket routes for real-time communication."""
        
        @self.app.websocket("/ws/{channel}")
        async def websocket_endpoint(websocket: WebSocket, channel: str):
            """WebSocket endpoint for real-time updates."""
            if not self.ws_manager:
                await websocket.close()
                return
            
            await self.ws_manager.connect(websocket, channel, {
                "channel": channel,
                "client": str(websocket.client),
            })
            
            try:
                while True:
                    data = await websocket.receive_json()
                    msg_type = data.get("type", "unknown")
                    
                    if msg_type == "ping":
                        await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
                    
                    elif msg_type == "subscribe":
                        sub_channel = data.get("channel")
                        if sub_channel and sub_channel != channel:
                            if sub_channel not in self.ws_manager.active_connections:
                                self.ws_manager.active_connections[sub_channel] = set()
                            self.ws_manager.active_connections[sub_channel].add(websocket)
                            await websocket.send_json({
                                "type": "subscribed",
                                "channel": sub_channel,
                                "timestamp": datetime.utcnow().isoformat()
                            })
                    
                    elif msg_type == "get_stats":
                        await websocket.send_json({
                            "type": "stats",
                            "data": {
                                "alerts": self.detection.get_stats() if self.detection else {},
                                "ingestion": self.ingestion.get_stats() if self.ingestion else {},
                                "websocket": self.ws_manager.get_stats() if self.ws_manager else {},
                            },
                            "timestamp": datetime.utcnow().isoformat()
                        })
                    
            except WebSocketDisconnect:
                self.ws_manager.disconnect(websocket, channel)
            except Exception as e:
                self.logger.error(f"WebSocket error: {e}", exc_info=True)
                self.ws_manager.disconnect(websocket, channel)
        
        @self.app.websocket("/ws")
        async def websocket_default(websocket: WebSocket):
            """Default WebSocket endpoint."""
            await websocket_endpoint(websocket, "default")
    
    async def initialize(self):
        """Initialize the API and components."""
        self.logger.info("Initializing SOC API...")
        
        # Load configuration
        self.config = ConfigLoader(self.config_path)
        await self.config.load_all()
        
        # Initialize WebSocket manager
        await self.ws_manager.start()
        
        # Initialize components with event handler
        async def event_handler(event):
            """Handle incoming events."""
            if self.detection:
                await self.detection.add_event(event)
        
        self.ingestion = IngestionPipeline(self.config, event_handler)
        self.detection = DetectionEngine(self.config, ws_manager=self.ws_manager)
        self.response = ResponseExecutor(self.config)
        self.metrics_collector = MetricsCollector(self.config)
        self.elastic_storage = ElasticsearchStorage(self.config)
        
        # Update app state
        self.app.state.ingestion = self.ingestion
        self.app.state.detection = self.detection
        self.app.state.response = self.response
        self.app.state.ws_manager = self.ws_manager
        
        self.logger.info("SOC API initialized")
    
    async def start_background_tasks(self):
        """Start background tasks for real-time updates."""
        async def alert_broadcaster():
            """Broadcast new alerts in real-time."""
            last_alert_count = 0
            while True:
                if self.detection and self.detection.running:
                    current_alerts = len(self.detection.alerts)
                    if current_alerts > last_alert_count:
                        new_alerts = self.detection.alerts[last_alert_count:]
                        for alert in new_alerts:
                            if self.ws_manager:
                                await self.ws_manager.broadcast({
                                    "type": "new_alert",
                                    "alert": alert,
                                }, channel="alerts", event_type="alert")
                        last_alert_count = current_alerts
                await asyncio.sleep(1)
        
        async def stats_broadcaster():
            """Broadcast stats periodically."""
            while True:
                await asyncio.sleep(5)
                if self.detection and self.ingestion and self.ws_manager:
                    stats = {
                        "type": "stats_update",
                        "data": {
                            "alerts": self.detection.get_stats(),
                            "ingestion": self.ingestion.get_stats(),
                            "response": self.response.get_stats() if self.response else {},
                            "websocket": self.ws_manager.get_stats(),
                        }
                    }
                    await self.ws_manager.broadcast(stats, channel="stats", event_type="stats")
        
        asyncio.create_task(alert_broadcaster())
        asyncio.create_task(stats_broadcaster())
    
    async def start(self, host: str = "127.0.0.1", port: int = 8080):
        """Start the API server."""
        self.logger.info(f"Starting SOC API on {host}:{port}")
        
        # Start background tasks
        await self.start_background_tasks()
        
        # Start ingestion and detection
        if self.ingestion:
            asyncio.create_task(self.ingestion.start())
        if self.detection:
            asyncio.create_task(self.detection.start())
        if self.response:
            asyncio.create_task(self.response.start())
        
        config = uvicorn.Config(
            app=self.app,
            host=host,
            port=port,
            log_level="info",
            access_log=True,
            ws_ping_interval=20,
            ws_ping_timeout=30,
        )
        
        server = uvicorn.Server(config)
        
        try:
            await server.serve()
        except asyncio.CancelledError:
            self.logger.info("API server stopped")
        except Exception as e:
            self.logger.error(f"Error starting API server: {e}")
            raise
    
    async def stop(self):
        """Stop the API server."""
        self.logger.info("Stopping SOC API...")
        if self.ws_manager:
            await self.ws_manager.stop()
        if self.ingestion:
            await self.ingestion.stop()
        if self.detection:
            await self.detection.stop()
        if self.response:
            await self.response.stop()


def create_api_app(config_path: str = "./config") -> FastAPI:
    """Create and configure FastAPI application."""
    soc_api = SOCAPI(config_path)
    return soc_api.app


async def main():
    """Main entry point for API server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AI SOC Platform API Server")
    parser.add_argument("--config", "-c", default="./config", help="Configuration directory path")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Port to bind to")
    
    args = parser.parse_args()
    
    soc_api = SOCAPI(args.config)
    await soc_api.initialize()
    await soc_api.start(args.host, args.port)


if __name__ == "__main__":
    asyncio.run(main())