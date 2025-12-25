"""
Notification system for alerts and events.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

from src.utils.logger import LoggerMixin


class NotificationPriority(Enum):
    """Notification priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationType(Enum):
    """Notification types."""
    ALERT = "alert"
    STATUS = "status"
    HEALTH = "health"
    AUDIT = "audit"


class NotificationProvider(LoggerMixin):
    """Base class for notification providers."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        self.enabled = config.get("enabled", True)
        self.name = config.get("name", "unknown")

    async def send(
        self,
        message: str,
        title: Optional[str] = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a notification."""
        raise NotImplementedError

    async def health_check(self) -> Dict[str, Any]:
        """Check provider health."""
        return {
            "provider": self.name,
            "enabled": self.enabled,
            "status": "unknown",
            "timestamp": datetime.utcnow().isoformat(),
        }


class SlackNotificationProvider(NotificationProvider):
    """Slack notification provider."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url")
        self.default_channel = config.get("default_channel", "#soc-alerts")
        self.username = config.get("username", "AI-SOC-Bot")
        self.icon_emoji = config.get("icon_emoji", ":warning:")

    async def send(
        self,
        message: str,
        title: Optional[str] = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send notification to Slack."""
        if not self.enabled or not self.webhook_url:
            return {
                "success": False,
                "error": "Slack provider disabled or misconfigured",
            }

        try:
            import aiohttp

            # Create Slack message
            slack_message = self._create_slack_message(message, title, priority, metadata)

            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=slack_message,
                    timeout=10
                ) as response:
                    success = response.status == 200
                    response_text = await response.text()

                    return {
                        "success": success,
                        "status_code": response.status,
                        "response": response_text,
                        "provider": "slack",
                        "timestamp": datetime.utcnow().isoformat(),
                    }

        except Exception as e:
            self.logger.error(f"Error sending Slack notification: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "provider": "slack",
                "timestamp": datetime.utcnow().isoformat(),
            }

    def _create_slack_message(
        self,
        message: str,
        title: Optional[str],
        priority: NotificationPriority,
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Create Slack message structure."""
        # Color based on priority
        colors = {
            NotificationPriority.LOW: "#36a64f",      # Green
            NotificationPriority.MEDIUM: "#ffcc00",   # Yellow
            NotificationPriority.HIGH: "#ff9900",     # Orange
            NotificationPriority.CRITICAL: "#ff0000", # Red
        }

        color = colors.get(priority, "#ffcc00")

        # Create blocks
        blocks = []

        # Header block
        if title:
            blocks.append({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": title,
                    "emoji": True,
                }
            })

        # Message block
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": message,
            }
        })

        # Metadata block
        if metadata:
            fields = []
            for key, value in metadata.items():
                if key not in ["message", "title"]:  # Avoid duplication
                    fields.append({
                        "type": "mrkdwn",
                        "text": f"*{key}:*\n{value}",
                    })

            if fields:
                blocks.append({
                    "type": "section",
                    "fields": fields,
                })

        # Context block with timestamp and priority
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*Priority:* {priority.value.upper()}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Time:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                },
            ]
        })

        return {
            "channel": self.default_channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [{
                "color": color,
                "blocks": blocks,
            }],
        }

    async def health_check(self) -> Dict[str, Any]:
        """Check Slack provider health."""
        if not self.enabled or not self.webhook_url:
            return {
                "provider": "slack",
                "enabled": self.enabled,
                "status": "disabled",
                "message": "Slack provider disabled",
            }

        try:
            import aiohttp

            # Simple test message
            test_message = {
                "text": "AI SOC Platform Health Check",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Health Check*\nThis is a test message from AI SOC Platform.",
                        }
                    }
                ]
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=test_message,
                    timeout=5
                ) as response:
                    if response.status == 200:
                        return {
                            "provider": "slack",
                            "enabled": True,
                            "status": "healthy",
                            "message": "Slack webhook is accessible",
                        }
                    else:
                        return {
                            "provider": "slack",
                            "enabled": True,
                            "status": "unhealthy",
                            "message": f"Slack returned status {response.status}",
                        }

        except Exception as e:
            return {
                "provider": "slack",
                "enabled": True,
                "status": "error",
                "message": str(e),
            }


class EmailNotificationProvider(NotificationProvider):
    """Email notification provider."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.smtp_server = config.get("smtp_server")
        self.smtp_port = config.get("smtp_port", 587)
        self.username = config.get("username")
        self.password = config.get("password")
        self.from_address = config.get("from_address", "soc@example.com")
        self.use_tls = config.get("use_tls", True)

    async def send(
        self,
        message: str,
        title: Optional[str] = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
        recipients: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send email notification."""
        if not self.enabled or not self.smtp_server:
            return {
                "success": False,
                "error": "Email provider disabled or misconfigured",
            }

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            # Default recipients
            if not recipients:
                recipients = [self.from_address]

            # Create email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = title or "AI SOC Alert"
            msg['From'] = self.from_address
            msg['To'] = ', '.join(recipients)
            msg['X-Priority'] = self._get_email_priority(priority)

            # Create HTML content
            html_content = self._create_html_content(message, title, priority, metadata)
            msg.attach(MIMEText(html_content, 'html'))

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                
                if self.username and self.password:
                    server.login(self.username, self.password)
                
                server.send_message(msg)

            return {
                "success": True,
                "provider": "email",
                "recipients": recipients,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Error sending email: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "provider": "email",
                "timestamp": datetime.utcnow().isoformat(),
            }

    def _get_email_priority(self, priority: NotificationPriority) -> str:
        """Convert priority to email priority header."""
        priorities = {
            NotificationPriority.LOW: "3",
            NotificationPriority.MEDIUM: "2",
            NotificationPriority.HIGH: "1",
            NotificationPriority.CRITICAL: "1",
        }
        return priorities.get(priority, "2")

    def _create_html_content(
        self,
        message: str,
        title: Optional[str],
        priority: NotificationPriority,
        metadata: Optional[Dict[str, Any]],
    ) -> str:
        """Create HTML email content."""
        # Priority colors
        colors = {
            NotificationPriority.LOW: "#28a745",
            NotificationPriority.MEDIUM: "#ffc107",
            NotificationPriority.HIGH: "#fd7e14",
            NotificationPriority.CRITICAL: "#dc3545",
        }

        color = colors.get(priority, "#ffc107")

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 10px 20px; border-radius: 5px 5px 0 0; }}
                .content {{ background-color: #f8f9fa; padding: 20px; border-radius: 0 0 5px 5px; }}
                .priority {{ display: inline-block; padding: 3px 8px; background-color: {color}; color: white; border-radius: 3px; font-size: 12px; }}
                .metadata {{ margin-top: 20px; background-color: white; padding: 15px; border-radius: 5px; }}
                .metadata table {{ width: 100%; border-collapse: collapse; }}
                .metadata th, .metadata td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                .footer {{ margin-top: 20px; font-size: 12px; color: #6c757d; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>{title or 'AI SOC Alert'}</h2>
                </div>
                <div class="content">
                    <div class="priority">{priority.value.upper()} PRIORITY</div>
                    <p>{message}</p>
        """

        if metadata:
            html += """
                    <div class="metadata">
                        <h3>Details</h3>
                        <table>
            """
            for key, value in metadata.items():
                if key not in ["message", "title"]:
                    html += f"""
                            <tr>
                                <th>{key}</th>
                                <td>{value}</td>
                            </tr>
                    """
            html += """
                        </table>
                    </div>
            """

        html += f"""
                </div>
                <div class="footer">
                    <p>AI SOC Platform | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p>This is an automated message. Please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        return html

    async def health_check(self) -> Dict[str, Any]:
        """Check email provider health."""
        if not self.enabled or not self.smtp_server:
            return {
                "provider": "email",
                "enabled": self.enabled,
                "status": "disabled",
                "message": "Email provider disabled",
            }

        try:
            import smtplib

            # Test SMTP connection
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=5) as server:
                server.ehlo()
                if self.use_tls:
                    server.starttls()
                    server.ehlo()
                
                if self.username and self.password:
                    try:
                        server.login(self.username, self.password)
                        return {
                            "provider": "email",
                            "enabled": True,
                            "status": "healthy",
                            "message": "SMTP server is accessible",
                        }
                    except smtplib.SMTPAuthenticationError:
                        return {
                            "provider": "email",
                            "enabled": True,
                            "status": "unhealthy",
                            "message": "SMTP authentication failed",
                        }
                else:
                    return {
                        "provider": "email",
                        "enabled": True,
                        "status": "healthy",
                        "message": "SMTP server is accessible (no auth)",
                    }

        except Exception as e:
            return {
                "provider": "email",
                "enabled": True,
                "status": "error",
                "message": str(e),
            }


class WebhookNotificationProvider(NotificationProvider):
    """Generic webhook notification provider."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url")
        self.method = config.get("method", "POST")
        self.headers = config.get("headers", {"Content-Type": "application/json"})
        self.timeout = config.get("timeout", 10)

    async def send(
        self,
        message: str,
        title: Optional[str] = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send notification via webhook."""
        if not self.enabled or not self.webhook_url:
            return {
                "success": False,
                "error": "Webhook provider disabled or misconfigured",
            }

        try:
            import aiohttp

            # Create payload
            payload = {
                "message": message,
                "title": title,
                "priority": priority.value,
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": metadata or {},
            }

            # Send request
            async with aiohttp.ClientSession() as session:
                if self.method.upper() == "POST":
                    async with session.post(
                        self.webhook_url,
                        json=payload,
                        headers=self.headers,
                        timeout=self.timeout
                    ) as response:
                        success = response.status in [200, 201, 202, 204]
                        response_text = await response.text()

                        return {
                            "success": success,
                            "status_code": response.status,
                            "response": response_text,
                            "provider": "webhook",
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                else:
                    return {
                        "success": False,
                        "error": f"Unsupported HTTP method: {self.method}",
                        "provider": "webhook",
                        "timestamp": datetime.utcnow().isoformat(),
                    }

        except Exception as e:
            self.logger.error(f"Error sending webhook: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "provider": "webhook",
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def health_check(self) -> Dict[str, Any]:
        """Check webhook provider health."""
        if not self.enabled or not self.webhook_url:
            return {
                "provider": "webhook",
                "enabled": self.enabled,
                "status": "disabled",
                "message": "Webhook provider disabled",
            }

        try:
            import aiohttp

            # Send test request
            test_payload = {
                "test": True,
                "message": "Health check",
                "timestamp": datetime.utcnow().isoformat(),
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=test_payload,
                    headers=self.headers,
                    timeout=5
                ) as response:
                    if response.status in [200, 201, 202, 204]:
                        return {
                            "provider": "webhook",
                            "enabled": True,
                            "status": "healthy",
                            "message": "Webhook is accessible",
                        }
                    else:
                        return {
                            "provider": "webhook",
                            "enabled": True,
                            "status": "unhealthy",
                            "message": f"Webhook returned status {response.status}",
                        }

        except Exception as e:
            return {
                "provider": "webhook",
                "enabled": True,
                "status": "error",
                "message": str(e),
            }


class NotificationManager(LoggerMixin):
    """Manages multiple notification providers."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.providers: Dict[str, NotificationProvider] = {}
        self.stats = {
            "notifications_sent": 0,
            "notifications_failed": 0,
            "providers_available": 0,
            "last_notification": None,
        }

    async def initialize(self):
        """Initialize notification providers."""
        self.logger.info("Initializing notification manager...")

        # Load providers from config
        notification_config = self.config.get("response", {}).get("providers", {}).get("notification", {})

        # Slack provider
        if notification_config.get("slack", {}).get("enabled", False):
            slack_provider = SlackNotificationProvider(notification_config["slack"])
            self.providers["slack"] = slack_provider
            self.logger.info("Initialized Slack notification provider")

        # Email provider
        if notification_config.get("email", {}).get("enabled", False):
            email_provider = EmailNotificationProvider(notification_config["email"])
            self.providers["email"] = email_provider
            self.logger.info("Initialized email notification provider")

        # Webhook provider
        if notification_config.get("webhook", {}).get("enabled", False):
            webhook_provider = WebhookNotificationProvider(notification_config["webhook"])
            self.providers["webhook"] = webhook_provider
            self.logger.info("Initialized webhook notification provider")

        # Teams provider (if configured)
        if notification_config.get("teams", {}).get("enabled", False):
            # Teams provider would be similar to Slack
            self.logger.info("Teams provider configuration found (not implemented)")

        self.stats["providers_available"] = len(self.providers)
        self.logger.info(f"Notification manager initialized with {len(self.providers)} providers")

    async def send_notification(
        self,
        message: str,
        title: Optional[str] = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
        provider_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Send notification through specified providers.

        Args:
            message: Notification message
            title: Notification title
            priority: Notification priority
            metadata: Additional metadata
            provider_names: List of provider names to use (None for all)

        Returns:
            Results from all providers
        """
        self.logger.info(f"Sending notification: {title or 'No title'}")

        if not self.providers:
            return {
                "success": False,
                "error": "No notification providers available",
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Determine which providers to use
        if provider_names:
            providers_to_use = {
                name: provider for name, provider in self.providers.items()
                if name in provider_names
            }
        else:
            providers_to_use = self.providers

        if not providers_to_use:
            return {
                "success": False,
                "error": "No enabled providers found",
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Send notifications in parallel
        tasks = []
        for name, provider in providers_to_use.items():
            task = provider.send(message, title, priority, metadata)
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        provider_results = {}
        success_count = 0
        failure_count = 0

        for name, result in zip(providers_to_use.keys(), results):
            if isinstance(result, Exception):
                provider_results[name] = {
                    "success": False,
                    "error": str(result),
                }
                failure_count += 1
            else:
                provider_results[name] = result
                if result.get("success", False):
                    success_count += 1
                else:
                    failure_count += 1

        # Update statistics
        self.stats["notifications_sent"] += success_count
        self.stats["notifications_failed"] += failure_count
        self.stats["last_notification"] = datetime.utcnow().isoformat()

        overall_success = success_count > 0

        if overall_success:
            self.logger.info(f"Notification sent successfully via {success_count} provider(s)")
        else:
            self.logger.error("Notification failed for all providers")

        return {
            "success": overall_success,
            "providers": provider_results,
            "success_count": success_count,
            "failure_count": failure_count,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def send_alert_notification(
        self,
        alert: Dict[str, Any],
        provider_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send notification for an alert."""
        # Extract information from alert
        alert_id = alert.get("alert_id", "unknown")
        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity", "medium")
        description = alert.get("description", "")
        score = alert.get("score", 0)

        # Convert severity to priority
        priority_map = {
            "low": NotificationPriority.LOW,
            "medium": NotificationPriority.MEDIUM,
            "high": NotificationPriority.HIGH,
            "critical": NotificationPriority.CRITICAL,
        }
        priority = priority_map.get(severity.lower(), NotificationPriority.MEDIUM)

        # Create message
        title = f"Security Alert: {rule_name}"
        message = f"""
*Alert ID:* {alert_id}
*Rule:* {rule_name}
*Severity:* {severity.upper()}
*Score:* {score:.2f}

*Description:*
{description}

*Time:* {alert.get('timestamp', 'Unknown')}
        """.strip()

        # Create metadata
        metadata = {
            "alert_id": alert_id,
            "rule_name": rule_name,
            "severity": severity,
            "score": score,
            "category": alert.get("category", "unknown"),
            "indicators": json.dumps(alert.get("indicators", []), indent=2),
            "event_count": alert.get("event_count", 1),
            "source": alert.get("source", "unknown"),
            "destination": alert.get("destination", "unknown"),
        }

        # Send notification
        return await self.send_notification(
            message=message,
            title=title,
            priority=priority,
            metadata=metadata,
            provider_names=provider_names,
        )

    async def health_check(self) -> Dict[str, Any]:
        """Check health of all notification providers."""
        health_results = {}

        for name, provider in self.providers.items():
            try:
                health = await provider.health_check()
                health_results[name] = health
            except Exception as e:
                health_results[name] = {
                    "provider": name,
                    "status": "error",
                    "message": str(e),
                }

        # Determine overall status
        status_counts = {}
        for result in health_results.values():
            status = result.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        if status_counts.get("error", 0) > 0:
            overall_status = "error"
        elif status_counts.get("unhealthy", 0) > 0:
            overall_status = "warning"
        elif status_counts.get("healthy", 0) > 0:
            overall_status = "healthy"
        else:
            overall_status = "unknown"

        return {
            "overall_status": overall_status,
            "providers": health_results,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get notification manager statistics."""
        return {
            **self.stats,
            "providers_available": len(self.providers),
            "provider_names": list(self.providers.keys()),
        }

    def get_provider(self, name: str) -> Optional[NotificationProvider]:
        """Get a specific provider by name."""
        return self.providers.get(name)

    async def test_provider(self, name: str) -> Dict[str, Any]:
        """Test a specific provider."""
        provider = self.get_provider(name)
        if not provider:
            return {
                "success": False,
                "error": f"Provider not found: {name}",
            }

        # Send test notification
        return await provider.send(
            message="This is a test notification from AI SOC Platform.",
            title="Test Notification",
            priority=NotificationPriority.LOW,
            metadata={
                "test": True,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )