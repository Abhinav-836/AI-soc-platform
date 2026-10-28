"""
SOAR: playbooks, approvals and safe action execution.

Flow
  alert (auto, severity >= auto_response.min_severity) or analyst (manual)
    -> response request with every action rendered from the alert's entity
    -> needs approval? (block_ip / isolate_host / disable_user by default)
         yes: status "pending_approval" until an analyst approves or rejects
         no : executed straight away
    -> mode dry_run: actions are recorded as "dry_run" (nothing changes)
       mode enforce: firewall / EDR / identity webhooks really run

What changed and why:
  * approval used to be a stub that always returned approved, and API
    callers could skip it with ?require_approval=false
  * iptables commands were shell strings built from request input
    (command injection, run with sudo) - see firewall.py
  * playbook YAML files were never loaded; email/syslog actions were TODOs
    (and `import syslog` doesn't exist on Windows)
"""
import asyncio
import re
import uuid
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional

import yaml

from src.core.logger import LoggerMixin, audit
from src.core.paths import data_dir, resolve
from src.core.time_utils import iso, utcnow
from src.response.firewall import FirewallError, FirewallManager
from src.response.notifier import NotificationManager

ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
USER_RE = re.compile(r"^[A-Za-z0-9._@\\-]{1,64}$")
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


class ResponseError(ValueError):
    pass


class ResponseExecutor(LoggerMixin):
    def __init__(self, config, store=None, intel=None):
        cfg = config.get("response", {}) or {}
        self.mode = "enforce" if str(cfg.get("mode", "dry_run")).lower() == "enforce" else "dry_run"
        self.store = store
        self.intel = intel
        self.auto = cfg.get("auto_response", {}) or {}
        self.approval_types = set((cfg.get("approval", {}) or {}).get("required_for",
                                                                       ["block_ip", "isolate_host", "disable_user"]))
        fw = cfg.get("firewall", {}) or {}
        self.block_duration = int(fw.get("block_duration", 3600))
        self.firewall = FirewallManager(fw)
        self.edr_webhook = ((cfg.get("edr") or {}).get("isolate_webhook") or "").strip()
        self.identity_webhook = ((cfg.get("identity") or {}).get("disable_webhook") or "").strip()
        self.notifier = NotificationManager(cfg.get("notifications", {}) or {})
        self.playbooks_dir = resolve(cfg.get("playbooks_dir", "config/playbooks"))
        self.playbooks: Dict[str, Dict[str, Any]] = {}
        self.listeners: List[Callable] = []
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self._recent_auto: Dict[str, float] = {}
        self.stats = {"requests": 0, "executed": 0, "dry_run": 0, "failed": 0, "rejected": 0,
                      "notifications": 0}

    # ------------------------------------------------------------ lifecycle
    def load_playbooks(self):
        self.playbooks.clear()
        for directory in (self.playbooks_dir, data_dir() / "playbooks"):
            for path in sorted(directory.glob("*.y*ml")) if directory.is_dir() else []:
                try:
                    pb = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
                    if not pb.get("name") or not isinstance(pb.get("actions"), list):
                        raise ValueError("needs 'name' and a list of 'actions'")
                    self.playbooks[pb["name"]] = pb
                except Exception as e:
                    self.logger.warning(f"Playbook {path.name} skipped: {e}")
        self.logger.info(f"Loaded {len(self.playbooks)} playbooks ({self.mode} mode)")

    async def start(self):
        self.load_playbooks()
        self.running = True
        self._task = asyncio.create_task(self._expiry_loop())

    async def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()

    def add_listener(self, callback):
        self.listeners.append(callback)

    async def _emit(self, item: Dict[str, Any]):
        for cb in self.listeners:
            try:
                await cb(item)
            except Exception:
                pass

    # ------------------------------------------------------------ alerts
    async def on_alert(self, kind: str, alert: Dict[str, Any], events=None):
        """Detector listener: notifications + automatic responses for new alerts."""
        if kind != "created":
            return
        if self.notifier.should_notify(alert) and self.notifier.channels():
            asyncio.create_task(self._notify_alert(alert))
        if not self.auto.get("enabled", True):
            return
        if ORDER.get(alert.get("severity"), 0) < ORDER.get(self.auto.get("min_severity", "high"), 3):
            return
        for name in alert.get("suggested_playbooks", []):
            if name not in self.playbooks:
                continue
            try:
                ctx = self._context(alert, {})
                target_field = self.playbooks[name].get("target")
                dedup = f"{name}|{ctx.get(target_field) if target_field else alert['id']}"
                now = utcnow().timestamp()
                if self._recent_auto.get(dedup, 0) > now - 3600:
                    continue
                self._recent_auto[dedup] = now
                await self.request(name, alert_id=alert["id"], requested_by="auto")
            except ResponseError as e:
                self.logger.info(f"Auto-response {name} skipped for {alert['id']}: {e}")

    async def _notify_alert(self, alert: Dict[str, Any]):
        entity = ", ".join(f"{k}={v}" for k, v in (alert.get("entity") or {}).items() if isinstance(v, str))
        result = await self.notifier.send(f"[{alert['severity'].upper()}] {alert['rule_name']}",
                                          f"{alert.get('description', '')}\nEntity: {entity}\nScore: {alert['score']}"
                                          f"\nAlert: {alert['id']}", {"alert_id": alert["id"]})
        self.stats["notifications"] += 1
        audit("alert_notification", alert_id=alert["id"], result=result)

    # ------------------------------------------------------------ requests
    def _context(self, alert: Optional[Dict[str, Any]], overrides: Dict[str, Any]) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}
        if alert:
            ctx.update({k: v for k, v in (alert.get("entity") or {}).items() if isinstance(v, str)})
            ctx.update(alert_id=alert["id"], rule_name=alert.get("rule_name"), severity=alert.get("severity"))
            ctx["entity"] = ", ".join(f"{k}={v}" for k, v in (alert.get("entity") or {}).items()
                                      if isinstance(v, str))
        for key in ("src_ip", "dst_ip", "hostname", "user"):
            if overrides.get(key):
                ctx[key] = str(overrides[key]).strip()
        ctx.setdefault("rule_name", overrides.get("reason") or "manual response")
        ctx.setdefault("severity", "manual")
        ctx.setdefault("alert_id", "-")
        ctx.setdefault("entity", ", ".join(f"{k}={ctx[k]}" for k in ("src_ip", "hostname", "user") if ctx.get(k)))
        return ctx

    @staticmethod
    def _render(value: Any, ctx: Dict[str, Any]) -> Any:
        if isinstance(value, str):
            return _PLACEHOLDER.sub(lambda m: str(ctx.get(m.group(1), m.group(0))), value)
        if isinstance(value, dict):
            return {k: ResponseExecutor._render(v, ctx) for k, v in value.items()}
        return value

    def _validate_action(self, action: Dict[str, Any]):
        kind = action.get("type")
        if kind in ("block_ip", "unblock_ip"):
            action["ip"] = self.firewall.validate(action.get("ip", ""))  # raises FirewallError
        elif kind == "isolate_host":
            if not HOSTNAME_RE.match(str(action.get("hostname", ""))):
                raise ResponseError(f"invalid hostname {action.get('hostname')!r}")
        elif kind == "disable_user":
            if not USER_RE.match(str(action.get("user", ""))):
                raise ResponseError(f"invalid user name {action.get('user')!r}")
        elif kind == "add_ioc":
            pass
        elif kind != "notify":
            raise ResponseError(f"unknown action type {kind!r}")

    async def request(self, playbook: str, alert_id: Optional[str] = None, target: Optional[Dict[str, Any]] = None,
                      requested_by: str = "analyst") -> Dict[str, Any]:
        pb = self.playbooks.get(playbook)
        if not pb:
            raise ResponseError(f"unknown playbook {playbook!r}")
        alert = self.store.get_alert(alert_id) if (alert_id and self.store) else None
        if alert_id and not alert:
            raise ResponseError(f"alert {alert_id} not found")
        ctx = self._context(alert, target or {})
        target_field = pb.get("target")
        if target_field and not ctx.get(target_field):
            raise ResponseError(f"playbook {playbook} needs a {target_field}")

        actions = []
        for spec in pb["actions"]:
            action = self._render(dict(spec), ctx)
            try:
                self._validate_action(action)
            except (FirewallError, ResponseError) as e:
                raise ResponseError(str(e))
            actions.append({**action, "status": "planned"})

        needs_approval = any(a["type"] in self.approval_types for a in actions)
        item = {
            "id": "RSP-" + uuid.uuid4().hex[:10], "created_at": iso(), "updated_at": iso(),
            "playbook": playbook, "title": pb.get("title", playbook), "alert_id": alert_id,
            "target": {k: ctx.get(k) for k in ("src_ip", "hostname", "user") if ctx.get(k)},
            "requested_by": requested_by, "mode": self.mode, "actions": actions,
            "status": "pending_approval" if needs_approval else "running", "decided_by": None,
        }
        self.stats["requests"] += 1
        audit("response_requested", response_id=item["id"], playbook=playbook, alert_id=alert_id,
              requested_by=requested_by, target=item["target"])
        self._save(item)
        if alert and self.store:
            alert.setdefault("response_ids", []).append(item["id"])
            alert["updated_at"] = iso()
            self.store.save_alert(alert)
        if not needs_approval:
            await self._execute(item)
        else:
            await self._emit(item)
        return item

    async def approve(self, response_id: str, by: str = "analyst") -> Dict[str, Any]:
        item = self._get(response_id)
        if item["status"] != "pending_approval":
            raise ResponseError(f"{response_id} is {item['status']}, not pending approval")
        item["decided_by"] = by
        item["decided_at"] = iso()
        audit("response_approved", response_id=response_id, by=by)
        await self._execute(item)
        return item

    async def reject(self, response_id: str, by: str = "analyst", reason: str = "") -> Dict[str, Any]:
        item = self._get(response_id)
        if item["status"] != "pending_approval":
            raise ResponseError(f"{response_id} is {item['status']}, not pending approval")
        item.update(status="rejected", decided_by=by, decided_at=iso(), reason=reason, updated_at=iso())
        for a in item["actions"]:
            a["status"] = "skipped"
        self.stats["rejected"] += 1
        audit("response_rejected", response_id=response_id, by=by, reason=reason)
        self._save(item)
        await self._emit(item)
        return item

    def _get(self, response_id: str) -> Dict[str, Any]:
        item = self.store.get_response(response_id) if self.store else None
        if not item:
            raise ResponseError(f"response {response_id} not found")
        return item

    def _save(self, item: Dict[str, Any]):
        item["updated_at"] = iso()
        if self.store:
            self.store.save_response(item)

    # ------------------------------------------------------------ execution
    async def _execute(self, item: Dict[str, Any]):
        dry = item["mode"] == "dry_run"
        for action in item["actions"]:
            try:
                result = await self._run(action, item, dry)
            except Exception as e:
                result = {"status": "failed", "error": str(e)}
            action.update(result)
            audit("response_action", response_id=item["id"], type=action["type"], status=action["status"],
                  mode=item["mode"])
        statuses = {a["status"] for a in item["actions"]}
        if statuses <= {"dry_run", "done", "skipped"}:
            item["status"] = "dry_run" if "dry_run" in statuses and dry else "executed"
        else:
            item["status"] = "failed" if not statuses & {"done", "dry_run"} else "partial"
        item["executed_at"] = iso()
        self.stats["dry_run" if item["status"] == "dry_run" else
                   "executed" if item["status"] == "executed" else "failed"] += 1
        self._save(item)
        await self._emit(item)

    async def _run(self, action: Dict[str, Any], item: Dict[str, Any], dry: bool) -> Dict[str, Any]:
        kind = action["type"]
        loop = asyncio.get_running_loop()
        if kind in ("block_ip", "unblock_ip"):
            block = kind == "block_ip"
            result = await loop.run_in_executor(None, lambda: self.firewall.apply(action["ip"], block, dry))
            if block and result["status"] in ("done", "dry_run") and self.store:
                expires = iso(utcnow() + timedelta(seconds=self.block_duration)) if self.block_duration else None
                self.store.add_block(action["ip"], result["status"], item.get("title", ""), item.get("alert_id"),
                                     expires)
            if not block and self.store:
                self.store.remove_block(action["ip"])
            return result
        if kind == "add_ioc":
            if dry:
                return {"status": "dry_run", "detail": f"would add {action.get('value')} to threat intel"}
            if self.intel:
                ioc = self.intel.add_ioc(action["value"], action.get("ioc_type"), 0.9,
                                         action.get("description", ""), source="response")
                return {"status": "done", "detail": f"added {ioc['type']} {ioc['value']}"}
            return {"status": "skipped", "detail": "threat intel disabled"}
        if kind == "notify":
            if not self.notifier.channels():
                return {"status": "skipped", "detail": "no notification channel configured"}
            if dry:
                return {"status": "dry_run", "detail": f"would send: {action.get('message')}"}
            return await self.notifier.send(f"SOC response: {item.get('title')}", action.get("message", ""))
        if kind in ("isolate_host", "disable_user"):
            webhook = self.edr_webhook if kind == "isolate_host" else self.identity_webhook
            target = action.get("hostname") or action.get("user")
            if dry:
                return {"status": "dry_run", "detail": f"would {kind.replace('_', ' ')} {target}"}
            if not webhook:
                return {"status": "failed", "error": f"no webhook configured for {kind}"}
            import aiohttp
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                async with session.post(webhook, json={"action": kind, "target": target,
                                                       "response_id": item["id"]}) as r:
                    ok = r.status < 300
                    return {"status": "done" if ok else "failed", "detail": f"HTTP {r.status}"}
        return {"status": "failed", "error": f"unknown action {kind}"}

    async def unblock(self, ip: str, by: str = "analyst") -> Dict[str, Any]:
        result = await asyncio.get_running_loop().run_in_executor(
            None, lambda: self.firewall.apply(ip, block=False, dry_run=self.mode == "dry_run"))
        if self.store:
            self.store.remove_block(result["ip"])
        audit("ip_unblocked", ip=result["ip"], by=by, status=result["status"])
        return result

    async def _expiry_loop(self):
        while self.running:
            await asyncio.sleep(30)
            if not self.store:
                continue
            for ip in self.store.expired_blocks():
                try:
                    await self.unblock(ip, by="expiry")
                except Exception as e:
                    self.logger.warning(f"Unblock of {ip} failed: {e}")

    # ------------------------------------------------------------ queries
    def list_playbooks(self) -> List[Dict[str, Any]]:
        return [{"name": n, "title": p.get("title", n), "description": p.get("description", ""),
                 "target": p.get("target"), "actions": [a.get("type") for a in p["actions"]],
                 "requires_approval": any(a.get("type") in self.approval_types for a in p["actions"])}
                for n, p in self.playbooks.items()]

    def get_stats(self) -> Dict[str, Any]:
        pending = len(self.store.list_responses("pending_approval", 500)) if self.store else 0
        return {"running": self.running, "mode": self.mode, "playbooks": len(self.playbooks),
                "pending_approval": pending, "firewall_backend": self.firewall.backend,
                "approval_required_for": sorted(self.approval_types), **self.stats,
                "notifications": self.notifier.get_stats()}
