"""
REST API + WebSocket + dashboard.

Security defaults (the old API was open to any site via CORS "*", had no
authentication, and let callers skip playbook approval):
  * listens on 127.0.0.1 unless configured otherwise
  * optional API key (SOC_API_KEY / server.api_key): X-API-Key header on
    /api/* and /metrics, ?api_key= on the WebSocket
  * CORS limited to the dashboard's own origin by default
  * response approval is enforced server-side from config only
"""
import asyncio
import hmac
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Union

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.core.logger import audit, setup_logging
from src.core.paths import resolve
from src.core.time_utils import iso
from src.monitoring.health import component_health
from src.monitoring.metrics import prometheus
from src.response.executor import ResponseError
from src.storage.local_store import ALERT_STATUSES, since_minutes

MAX_BATCH = 1000


# ------------------------------------------------------------------ models
class AlertUpdate(BaseModel):
    status: Optional[str] = Field(None, description=" | ".join(ALERT_STATUSES))
    assignee: Optional[str] = Field(None, max_length=64)
    note: Optional[str] = Field(None, max_length=2000)


class RuleUpdate(BaseModel):
    enabled: bool


class IOCCreate(BaseModel):
    value: str = Field(..., min_length=3, max_length=512)
    type: Optional[str] = Field(None, pattern="^(ip|cidr|domain|hash|url)$")
    confidence: float = Field(0.8, ge=0, le=1)
    description: str = Field("", max_length=500)


class ResponseCreate(BaseModel):
    playbook: str
    alert_id: Optional[str] = None
    target: Dict[str, str] = Field(default_factory=dict, description="src_ip / hostname / user overrides")


class Decision(BaseModel):
    reason: str = Field("", max_length=500)


class SimulationStart(BaseModel):
    rate: float = Field(5, ge=0.5, le=200)
    attack_interval: float = Field(45, ge=5, le=3600)


class Inject(BaseModel):
    scenario: Optional[str] = None


class Retrain(BaseModel):
    source: str = Field("simulated", pattern="^(simulated|recent)$")


# ------------------------------------------------------------------ app
# All route handlers are `async def`: they run on the event loop, which the
# simulator, WebSocket queues and detector state require (sync handlers run in
# a thread pool, where asyncio.create_task / Queue.put_nowait are unsafe).
def create_app(config_dir: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None,
               db_path: Optional[str] = None, simulate: Optional[bool] = None) -> FastAPI:
    from src.main import VERSION, SOCPlatform

    setup_logging()
    platform = SOCPlatform(config_dir, overrides, db_path)
    server_cfg = platform.config.get("app", {}).get("server", {}) or {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await platform.start(simulate)
        yield
        await platform.stop()

    app = FastAPI(title="AI SOC Platform API", version=VERSION, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json",
                  description="Ingestion, detection (rules, Sigma, threat intel, ML, attack chains), "
                              "alert triage and approval-gated response.")
    app.state.platform = platform
    origins = server_cfg.get("cors_origins") or ["http://localhost:8080", "http://127.0.0.1:8080"]
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["X-API-Key", "Content-Type",
                                                                                         "X-Analyst"])

    def api_key() -> str:
        import os
        return (os.getenv("SOC_API_KEY") or str(server_cfg.get("api_key") or "")).strip()

    def require_key(x_api_key: Optional[str] = Header(None)):
        key = api_key()
        if key and not (x_api_key and hmac.compare_digest(x_api_key, key)):
            raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")

    def analyst(x_analyst: Optional[str] = Header(None)) -> str:
        return (x_analyst or "analyst")[:64]

    secured = [Depends(require_key)]

    # ---------------------------------------------------------- basics
    @app.get("/", include_in_schema=False)
    async def index():
        return RedirectResponse("/ui/")

    @app.get("/health")
    async def health():
        return {**component_health(platform), "version": VERSION, "timestamp": iso(),
                "auth_required": bool(api_key()), "response_mode": platform.response.mode}

    @app.get("/metrics", dependencies=secured, response_class=PlainTextResponse)
    async def metrics():
        return prometheus(platform.stats(light=True))

    @app.get("/api/v1/stats", dependencies=secured)
    async def stats():
        return platform.stats()

    # ---------------------------------------------------------- alerts
    @app.get("/api/v1/alerts", dependencies=secured)
    async def list_alerts(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
                    status: Optional[str] = None, search: Optional[str] = Query(None, max_length=200),
                    open_only: bool = False):
        if status and status not in ALERT_STATUSES:
            raise HTTPException(422, f"status must be one of {ALERT_STATUSES}")
        result = platform.store.list_alerts(limit, offset, severity, status, search, open_only)
        return {**result, "limit": limit, "offset": offset}

    @app.get("/api/v1/alerts/{alert_id}", dependencies=secured)
    async def get_alert(alert_id: str):
        alert = platform.store.get_alert(alert_id)
        if not alert:
            raise HTTPException(404, f"Alert {alert_id} not found")
        alert["responses"] = [platform.store.get_response(r) for r in alert.get("response_ids", [])]
        return alert

    @app.patch("/api/v1/alerts/{alert_id}", dependencies=secured)
    async def update_alert(alert_id: str, body: AlertUpdate, who: str = Depends(analyst)):
        alert = platform.store.get_alert(alert_id)
        if not alert:
            raise HTTPException(404, f"Alert {alert_id} not found")
        if body.status:
            if body.status not in ALERT_STATUSES:
                raise HTTPException(422, f"status must be one of {ALERT_STATUSES}")
            alert["status"] = body.status
            alert.setdefault("history", []).append({"at": iso(), "by": who, "status": body.status})
        if body.assignee is not None:
            alert["assignee"] = body.assignee or None
        if body.note:
            alert.setdefault("notes", []).append({"at": iso(), "by": who, "text": body.note})
        alert["updated_at"] = iso()
        platform.store.save_alert(alert)
        audit("alert_updated", alert_id=alert_id, by=who, status=body.status, assignee=body.assignee,
              note=bool(body.note))
        platform.ws.broadcast({"type": "alert_update", "alert": alert}, "alert")
        return alert

    # old endpoint kept for existing clients
    @app.post("/api/v1/alerts/{alert_id}/status", dependencies=secured, include_in_schema=False)
    async def update_alert_status_legacy(alert_id: str, body: Dict[str, Any] = Body(...), who: str = Depends(analyst)):
        return await update_alert(alert_id, AlertUpdate(status=body.get("status")), who)

    # ---------------------------------------------------------- events
    @app.get("/api/v1/events", dependencies=secured)
    async def list_events(limit: int = Query(100, ge=1, le=1000), event_type: Optional[str] = None,
                    ip: Optional[str] = None, search: Optional[str] = Query(None, max_length=200),
                    flagged_only: bool = False):
        events = platform.store.recent_events(limit, event_type, ip, search, flagged_only)
        return {"events": events, "total": len(events)}

    @app.post("/api/v1/ingest", dependencies=secured)
    async def ingest(payload: Union[List[Dict[str, Any]], Dict[str, Any]] = Body(...)):
        """One event, a list of events, or {"events": [...]}. Structured JSON or {"raw_message": "<log line>"}."""
        items = payload.get("events") if isinstance(payload, dict) and isinstance(payload.get("events"), list) \
            else (payload if isinstance(payload, list) else [payload])
        if len(items) > MAX_BATCH:
            raise HTTPException(413, f"at most {MAX_BATCH} events per request")
        accepted, alert_ids = [], set()
        for raw in items:
            if not isinstance(raw, dict):
                raise HTTPException(422, "each event must be a JSON object")
            raw = {k: v for k, v in raw.items() if not k.startswith("_")}  # clients can't forge ground truth
            before = platform.detection.stats["alerts_created"] + platform.detection.stats["alerts_updated"]
            event = await platform.ingestion.process(raw)
            if event:
                accepted.append(event["event_id"])
                if platform.detection.stats["alerts_created"] + platform.detection.stats["alerts_updated"] > before:
                    alert_ids.update(a["id"] for a in platform.store.list_alerts(5)["alerts"]
                                     if event["event_id"] in a.get("event_ids", []))
        return {"accepted": len(accepted), "event_ids": accepted, "alert_ids": sorted(alert_ids)}

    @app.get("/api/v1/entities/{value}", dependencies=secured)
    async def entity(value: str, limit: int = Query(200, ge=1, le=1000)):
        """Everything known about an IP address, host name or user: events, alerts, intel, block status."""
        value = value.strip()
        if not value or len(value) > 255:
            raise HTTPException(422, "invalid entity")
        info = platform.store.entity(value, limit)
        info["intel"] = platform.intel.matcher.lookup(value)
        info["blocked"] = next((b for b in platform.store.list_blocks() if b["ip"] == value), None)
        info["open_alerts"] = sum(1 for a in info["alerts"] if a.get("status") in ("new", "investigating"))
        return info

    @app.get("/api/v1/sources", dependencies=secured)
    async def sources():
        """Where data is coming from: collectors, simulation, and events per source in the last hour."""
        return {"collectors": platform.ingestion.get_stats()["collectors"],
                "events_by_source_1h": platform.store.event_counts(since_minutes(60), by="source"),
                "event_volume": platform.store.event_volume(since_minutes(60)),
                "simulation": platform.simulator.status(),
                "ingest_url": "/api/v1/ingest"}

    # ---------------------------------------------------------- rules
    @app.get("/api/v1/rules", dependencies=secured)
    async def rules():
        return {"rules": platform.detection.rule_engine.get_rules_summary(),
                "chains": platform.detection.correlation_engine.get_stats()["chains"],
                "stats": platform.detection.rule_engine.get_stats()}

    @app.patch("/api/v1/rules/{rule_id}", dependencies=secured)
    async def update_rule(rule_id: str, body: RuleUpdate, who: str = Depends(analyst)):
        if not platform.detection.rule_engine.enable_rule(rule_id, body.enabled):
            raise HTTPException(404, f"Rule {rule_id} not found")
        audit("rule_toggled", rule_id=rule_id, enabled=body.enabled, by=who)
        return platform.detection.rule_engine.get_rule(rule_id).summary()

    @app.post("/api/v1/rules/reload", dependencies=secured)
    async def reload_rules(who: str = Depends(analyst)):
        platform.detection.rule_engine.load_rules()
        audit("rules_reloaded", by=who)
        return platform.detection.rule_engine.get_stats()

    # ---------------------------------------------------------- threat intel
    @app.get("/api/v1/intel/iocs", dependencies=secured)
    async def iocs(ioc_type: Optional[str] = Query(None, alias="type"), search: Optional[str] = None,
             limit: int = Query(500, ge=1, le=5000)):
        return {**platform.intel.get_iocs(ioc_type, search, limit), "stats": platform.intel.get_stats()}

    @app.post("/api/v1/intel/iocs", dependencies=secured)
    async def add_ioc(body: IOCCreate, who: str = Depends(analyst)):
        try:
            return platform.intel.add_ioc(body.value, body.type, body.confidence, body.description,
                                          source=f"analyst:{who}")
        except ValueError as e:
            raise HTTPException(422, str(e))

    @app.delete("/api/v1/intel/iocs/{ioc_type}/{value:path}", dependencies=secured)
    async def delete_ioc(ioc_type: str, value: str):
        if not platform.intel.remove_ioc(ioc_type, value):
            raise HTTPException(404, "IOC not found")
        return {"deleted": True}

    @app.get("/api/v1/intel/lookup", dependencies=secured)
    async def lookup(value: str = Query(..., min_length=3, max_length=512)):
        return await platform.intel.lookup(value)

    @app.post("/api/v1/intel/refresh", dependencies=secured)
    async def refresh_feeds():
        return await platform.intel.refresh_feeds()

    # ---------------------------------------------------------- response
    @app.get("/api/v1/playbooks", dependencies=secured)
    async def playbooks():
        return {"playbooks": platform.response.list_playbooks(), "mode": platform.response.mode}

    @app.get("/api/v1/responses", dependencies=secured)
    async def responses(status: Optional[str] = None, limit: int = Query(100, ge=1, le=500)):
        return {"responses": platform.store.list_responses(status, limit), "mode": platform.response.mode}

    @app.post("/api/v1/responses", dependencies=secured)
    async def create_response(body: ResponseCreate, who: str = Depends(analyst)):
        try:
            return await platform.response.request(body.playbook, body.alert_id, body.target, requested_by=who)
        except ResponseError as e:
            raise HTTPException(422, str(e))

    @app.post("/api/v1/playbooks/{playbook}/execute", dependencies=secured, include_in_schema=False)
    async def execute_playbook_legacy(playbook: str, context: Dict[str, Any] = Body(default={}),
                                      who: str = Depends(analyst)):
        """Old endpoint: approval can no longer be skipped by the caller."""
        target = {k: str(v) for k, v in context.items() if k in ("src_ip", "hostname", "user") and v}
        if context.get("ip"):
            target["src_ip"] = str(context["ip"])
        try:
            return await platform.response.request(playbook, context.get("alert_id"), target, requested_by=who)
        except ResponseError as e:
            raise HTTPException(422, str(e))

    @app.post("/api/v1/responses/{response_id}/approve", dependencies=secured)
    async def approve(response_id: str, who: str = Depends(analyst)):
        try:
            return await platform.response.approve(response_id, who)
        except ResponseError as e:
            raise HTTPException(409 if "not pending" in str(e) else 404, str(e))

    @app.post("/api/v1/responses/{response_id}/reject", dependencies=secured)
    async def reject(response_id: str, body: Decision = Body(default=Decision()), who: str = Depends(analyst)):
        try:
            return await platform.response.reject(response_id, who, body.reason)
        except ResponseError as e:
            raise HTTPException(409 if "not pending" in str(e) else 404, str(e))

    @app.get("/api/v1/blocked", dependencies=secured)
    async def blocked():
        return {"blocked": platform.store.list_blocks(), "mode": platform.response.mode,
                "backend": platform.response.firewall.backend}

    @app.delete("/api/v1/blocked/{ip}", dependencies=secured)
    async def unblock(ip: str, who: str = Depends(analyst)):
        try:
            return await platform.response.unblock(ip, who)
        except ValueError as e:
            raise HTTPException(422, str(e))

    # ---------------------------------------------------------- ML
    @app.get("/api/v1/ml", dependencies=secured)
    async def ml_status():
        return platform.ml.get_status()

    @app.post("/api/v1/ml/retrain", dependencies=secured)
    async def ml_retrain(body: Retrain = Body(default=Retrain()), who: str = Depends(analyst)):
        if platform.ml.training:
            raise HTTPException(409, "training already running")
        events = None
        if body.source == "recent":
            events = [e for e in platform.store.recent_events(20000) if not e.get("flagged")]
            if len(events) < 1000:
                raise HTTPException(422, f"need at least 1000 un-flagged stored events, have {len(events)}")
            events.sort(key=lambda e: e["@timestamp"])
        audit("ml_retrain_requested", by=who, source=body.source)
        asyncio.create_task(platform.ml.retrain(events=events))
        return {"status": "training", "source": body.source}

    # ---------------------------------------------------------- simulation
    @app.get("/api/v1/simulation", dependencies=secured)
    async def simulation():
        return platform.simulator.status()

    @app.post("/api/v1/simulation/start", dependencies=secured)
    async def simulation_start(body: SimulationStart = Body(default=SimulationStart())):
        platform.simulator.start(body.rate, body.attack_interval)
        return platform.simulator.status()

    @app.post("/api/v1/simulation/stop", dependencies=secured)
    async def simulation_stop():
        await platform.simulator.stop()
        return platform.simulator.status()

    @app.post("/api/v1/simulation/inject", dependencies=secured)
    async def simulation_inject(body: Inject = Body(default=Inject())):
        try:
            return platform.simulator.inject(body.scenario or None)
        except ValueError as e:
            raise HTTPException(422, str(e))

    @app.post("/api/v1/simulation/reset", dependencies=secured)
    async def simulation_reset():
        platform.simulator.reset_scorecard()
        return platform.simulator.status()

    @app.post("/api/v1/admin/clear", dependencies=secured)
    async def clear_data(who: str = Depends(analyst)):
        """Delete stored events, alerts and responses (IOCs and blocks are kept)."""
        platform.store.reset()
        platform.simulator.reset_scorecard()
        platform.detection._active.clear()
        audit("data_cleared", by=who)
        return {"cleared": True}

    # ---------------------------------------------------------- websocket
    async def ws_handler(websocket: WebSocket, channel: str = "all"):
        key = api_key()
        given = websocket.query_params.get("api_key") or websocket.headers.get("x-api-key") or ""
        if key and not hmac.compare_digest(given, key):
            await websocket.close(code=1008)
            return
        await platform.ws.connect(websocket, {channel})
        try:
            while True:
                msg = await websocket.receive_json()
                if isinstance(msg, dict) and msg.get("type") == "ping":
                    client = platform.ws.clients.get(id(websocket))
                    if client:
                        client.queue.put_nowait({"type": "pong", "timestamp": iso()})
        except (WebSocketDisconnect, RuntimeError):
            pass
        except Exception:
            pass
        finally:
            platform.ws.disconnect(websocket)

    @app.websocket("/ws")
    async def ws_all(websocket: WebSocket):
        await ws_handler(websocket, "all")

    @app.websocket("/ws/{channel}")
    async def ws_channel(websocket: WebSocket, channel: str):
        await ws_handler(websocket, channel if channel in ("event", "alert", "response", "stats", "simulation")
                         else "all")

    ui = resolve("src/ui")
    if ui.is_dir():
        app.mount("/ui", StaticFiles(directory=str(ui), html=True), name="ui")
    return app


def serve(config_dir: Optional[str] = None, host: Optional[str] = None, port: Optional[int] = None,
          simulate: Optional[bool] = None, app: Optional[FastAPI] = None):
    import uvicorn

    app = app or create_app(config_dir, simulate=simulate)
    server_cfg = app.state.platform.config.get("app", {}).get("server", {}) or {}
    host = host or server_cfg.get("host") or "127.0.0.1"
    port = int(port or server_cfg.get("port") or 8080)
    print(f"\n  AI SOC Platform -> http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}\n")
    uvicorn.run(app, host=host, port=port, log_level="warning", log_config=None)


# old name
def create_api_app(config_path: str = "./config") -> FastAPI:
    return create_app(config_path)
