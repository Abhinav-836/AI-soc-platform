"""
Notifications: Slack, Microsoft Teams, generic webhook and e-mail.

Replaces 850 lines of provider classes that nothing ever called (alerts were
never sent anywhere).
"""
import asyncio
import smtplib
from email.message import EmailMessage
from typing import Any, Dict, List

from src.core.logger import LoggerMixin

ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class NotificationManager(LoggerMixin):
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg or {}
        self.min_severity = self.cfg.get("min_severity", "high")
        self.sent = 0
        self.failed = 0
        self.last_error = None

    def channels(self) -> List[str]:
        out = []
        for name in ("slack", "teams", "webhook", "email"):
            c = self.cfg.get(name) or {}
            if c.get("enabled") and (c.get("webhook_url") or c.get("url") or c.get("smtp_host")):
                out.append(name)
        return out

    def should_notify(self, alert: Dict[str, Any]) -> bool:
        return ORDER.get(alert.get("severity"), 0) >= ORDER.get(self.min_severity, 3)

    async def send(self, subject: str, text: str, payload: Dict[str, Any] = None) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        channels = self.channels()
        if not channels:
            return {"status": "skipped", "reason": "no notification channel configured"}
        try:
            import aiohttp
        except ImportError:  # pragma: no cover
            aiohttp = None
        if aiohttp and any(c in channels for c in ("slack", "teams", "webhook")):
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                for name in ("slack", "teams", "webhook"):
                    if name not in channels:
                        continue
                    c = self.cfg[name]
                    url = c.get("webhook_url") or c.get("url")
                    body = {"text": f"*{subject}*\n{text}"} if name in ("slack", "teams") else \
                        {"subject": subject, "text": text, **(payload or {})}
                    try:
                        async with session.post(url, json=body, headers=c.get("headers") or {}) as r:
                            results[name] = r.status
                            if r.status >= 300:
                                raise RuntimeError(f"HTTP {r.status}")
                    except Exception as e:
                        results[name] = f"error: {e}"
        if "email" in channels:
            try:
                await asyncio.get_running_loop().run_in_executor(None, self._email, subject, text)
                results["email"] = "sent"
            except Exception as e:
                results["email"] = f"error: {e}"
        errors = [v for v in results.values() if isinstance(v, str) and v.startswith("error")]
        self.sent += len(results) - len(errors)
        self.failed += len(errors)
        if errors:
            self.last_error = errors[-1]
        return {"status": "failed" if errors and len(errors) == len(results) else "done", "channels": results}

    def _email(self, subject: str, text: str):
        c = self.cfg["email"]
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = c.get("from", "soc@localhost")
        msg["To"] = ", ".join(c.get("to") or [])
        msg.set_content(text)
        with smtplib.SMTP(c["smtp_host"], int(c.get("smtp_port", 587)), timeout=15) as smtp:
            if c.get("starttls", True):
                smtp.starttls()
            if c.get("username"):
                smtp.login(c["username"], c.get("password", ""))
            smtp.send_message(msg)

    def get_stats(self) -> Dict[str, Any]:
        return {"channels": self.channels(), "min_severity": self.min_severity, "sent": self.sent,
                "failed": self.failed, "last_error": self.last_error}
