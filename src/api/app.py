"""
FastAPI application for AI SOC Platform API.
"""

from fastapi import FastAPI, HTTPException, Depends, Query, Body, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List, Dict, Any, Optional
import uvicorn
import asyncio
from datetime import datetime, timedelta

from src.utils.logger import LoggerMixin
from src.utils.config_loader import ConfigLoader


class SOCAPI(LoggerMixin):
    """SOC Platform REST API."""
    
    def __init__(self, config_path: str = "./config"):
        super().__init__()
        self.config_path = config_path
        self.config: Optional[ConfigLoader] = None
        self.app = FastAPI(
            title="AI SOC Platform API",
            description="REST API for AI-powered Security Operations Center",
            version="0.1.0",
            docs_url="/api/docs",
            redoc_url="/api/redoc",
        )
        
        # Setup middleware
        self._setup_middleware()
        
        # Setup routes
        self._setup_routes()
        
        # Security
        self.security = HTTPBearer()
    
    def _setup_middleware(self):
        """Setup API middleware."""
        # CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # In production, specify exact origins
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Request logging middleware
        @self.app.middleware("http")
        async def log_requests(request, call_next):
            start_time = datetime.utcnow()
            
            response = await call_next(request)
            
            process_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            self.logger.info(
                f"{request.method} {request.url.path} "
                f"Status: {response.status_code} "
                f"Duration: {process_time:.2f}ms"
            )
            
            return response
    
    def _setup_routes(self):
        """Setup API routes."""
        
        @self.app.get("/")
        async def root():
            """API root endpoint."""
            return {
                "name": "AI SOC Platform API",
                "version": "0.1.0",
                "status": "operational",
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "uptime": "TODO",  # Would calculate actual uptime
            }
        
        @self.app.get("/api/v1/alerts")
        async def get_alerts(
            limit: int = Query(100, ge=1, le=1000),
            offset: int = Query(0, ge=0),
            severity: Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
            status: Optional[str] = Query(None, regex="^(new|in_progress|resolved|false_positive)$"),
            start_time: Optional[str] = Query(None, description="ISO format timestamp"),
            end_time: Optional[str] = Query(None, description="ISO format timestamp"),
        ):
            """Get alerts with filtering."""
            # TODO: Implement actual alert retrieval
            return {
                "alerts": [],
                "total": 0,
                "limit": limit,
                "offset": offset,
                "filters": {
                    "severity": severity,
                    "status": status,
                    "start_time": start_time,
                    "end_time": end_time,
                },
            }
        
        @self.app.get("/api/v1/alerts/{alert_id}")
        async def get_alert(alert_id: str = Path(..., description="Alert ID")):
            """Get specific alert by ID."""
            # TODO: Implement actual alert retrieval
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        
        @self.app.post("/api/v1/alerts/{alert_id}/status")
        async def update_alert_status(
            alert_id: str = Path(..., description="Alert ID"),
            status_update: Dict[str, Any] = Body(...),
        ):
            """Update alert status."""
            # TODO: Implement status update
            return {
                "alert_id": alert_id,
                "status_updated": True,
                "new_status": status_update.get("status"),
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.get("/api/v1/events")
        async def get_events(
            limit: int = Query(100, ge=1, le=1000),
            offset: int = Query(0, ge=0),
            event_type: Optional[str] = Query(None),
            source_type: Optional[str] = Query(None),
            start_time: Optional[str] = Query(None, description="ISO format timestamp"),
            end_time: Optional[str] = Query(None, description="ISO format timestamp"),
        ):
            """Get events with filtering."""
            # TODO: Implement actual event retrieval
            return {
                "events": [],
                "total": 0,
                "limit": limit,
                "offset": offset,
                "filters": {
                    "event_type": event_type,
                    "source_type": source_type,
                    "start_time": start_time,
                    "end_time": end_time,
                },
            }
        
        @self.app.get("/api/v1/metrics")
        async def get_metrics(
            metric_type: Optional[str] = Query(None, description="Type of metrics to retrieve"),
            time_range: str = Query("1h", regex="^(1h|24h|7d|30d)$"),
        ):
            """Get platform metrics."""
            # TODO: Implement metrics retrieval
            return {
                "metrics": {},
                "time_range": time_range,
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.get("/api/v1/playbooks")
        async def get_playbooks():
            """Get available response playbooks."""
            # TODO: Implement playbook listing
            return {
                "playbooks": [],
                "total": 0,
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.post("/api/v1/playbooks/{playbook_name}/execute")
        async def execute_playbook(
            playbook_name: str = Path(..., description="Playbook name"),
            context: Dict[str, Any] = Body(...),
            require_approval: bool = Query(True),
        ):
            """Execute a response playbook."""
            # TODO: Implement playbook execution
            return {
                "playbook": playbook_name,
                "executed": True,
                "results": [],
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.get("/api/v1/intel/iocs")
        async def get_iocs(
            ioc_type: Optional[str] = Query(None, description="Type of IOCs to retrieve"),
            limit: int = Query(100, ge=1, le=1000),
            offset: int = Query(0, ge=0),
        ):
            """Get threat intelligence IOCs."""
            # TODO: Implement IOC retrieval
            return {
                "iocs": [],
                "total": 0,
                "limit": limit,
                "offset": offset,
                "filters": {
                    "ioc_type": ioc_type,
                },
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.post("/api/v1/intel/iocs/search")
        async def search_iocs(
            query: Dict[str, Any] = Body(...),
        ):
            """Search IOCs."""
            # TODO: Implement IOC search
            return {
                "results": [],
                "query": query,
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.get("/api/v1/rules")
        async def get_rules(
            enabled: Optional[bool] = Query(None),
            severity: Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
            category: Optional[str] = Query(None),
        ):
            """Get detection rules."""
            # TODO: Implement rule retrieval
            return {
                "rules": [],
                "total": 0,
                "filters": {
                    "enabled": enabled,
                    "severity": severity,
                    "category": category,
                },
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.post("/api/v1/rules")
        async def create_rule(
            rule: Dict[str, Any] = Body(...),
        ):
            """Create a new detection rule."""
            # TODO: Implement rule creation
            return {
                "rule_id": "RULE-001",
                "created": True,
                "rule": rule,
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.get("/api/v1/system/stats")
        async def get_system_stats():
            """Get system statistics."""
            # TODO: Implement system stats
            return {
                "platform": {
                    "status": "running",
                    "uptime": "0 days, 0:00:00",
                },
                "components": {},
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        @self.app.post("/api/v1/system/actions")
        async def system_action(
            action: Dict[str, Any] = Body(...),
        ):
            """Perform system actions (start/stop/restart)."""
            action_type = action.get("action")
            
            if action_type == "restart":
                # TODO: Implement restart
                return {
                    "action": "restart",
                    "status": "scheduled",
                    "message": "Restart scheduled",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            elif action_type == "shutdown":
                # TODO: Implement shutdown
                return {
                    "action": "shutdown",
                    "status": "scheduled",
                    "message": "Shutdown scheduled",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unknown action: {action_type}"
                )
    
    async def initialize(self):
        """Initialize the API."""
        self.logger.info("Initializing SOC API...")
        
        # Load configuration
        self.config = ConfigLoader(self.config_path)
        await self.config.load_all()
        
        self.logger.info("SOC API initialized")
    
    async def start(self, host: str = "0.0.0.0", port: int = 8080):
        """Start the API server."""
        self.logger.info(f"Starting SOC API on {host}:{port}")
        
        config = uvicorn.Config(
            app=self.app,
            host=host,
            port=port,
            log_level="info",
            access_log=True,
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
        # Uvicorn handles shutdown via signals


def create_api_app(config_path: str = "./config") -> FastAPI:
    """
    Create and configure FastAPI application.
    
    Args:
        config_path: Path to configuration directory
    
    Returns:
        Configured FastAPI application
    """
    soc_api = SOCAPI(config_path)
    return soc_api.app


async def main():
    """Main entry point for API server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AI SOC Platform API Server")
    parser.add_argument(
        "--config",
        "-c",
        default="./config",
        help="Configuration directory path",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=8080,
        help="Port to bind to",
    )
    
    args = parser.parse_args()
    
    # Create and start API
    soc_api = SOCAPI(args.config)
    await soc_api.initialize()
    await soc_api.start(args.host, args.port)


if __name__ == "__main__":
    asyncio.run(main())