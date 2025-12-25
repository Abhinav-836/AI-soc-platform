"""
SOAR (Security Orchestration, Automation and Response) executor.
"""

import asyncio
import json
import yaml
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.core.logger import LoggerMixin


class ResponseExecutor(LoggerMixin):
    """Executes response playbooks."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.running = False
        self.playbooks: Dict[str, Dict[str, Any]] = {}
        self.action_queue = asyncio.Queue(maxsize=1000)
        self.stats = {
            "playbooks_loaded": 0,
            "actions_executed": 0,
            "actions_failed": 0,
            "last_action": None,
        }

    async def start(self):
        """Start response executor."""
        self.logger.info("Starting response executor...")
        self.running = True

        # Load playbooks
        await self._load_playbooks()

        # Start action processor
        processor_task = asyncio.create_task(self._process_actions())

        try:
            await processor_task
        except asyncio.CancelledError:
            self.logger.info("Response executor cancelled")
        except Exception as e:
            self.logger.error(f"Error in response executor: {e}", exc_info=True)
            await self.stop()

    async def stop(self):
        """Stop response executor."""
        self.logger.info("Stopping response executor...")
        self.running = False

        # Clear queue
        while not self.action_queue.empty():
            try:
                self.action_queue.get_nowait()
                self.action_queue.task_done()
            except asyncio.QueueEmpty:
                break

    async def _load_playbooks(self):
        """Load response playbooks from configuration."""
        response_config = self.config.get("response", {})
        playbook_configs = response_config.get("playbooks", {})

        for playbook_name, playbook_config in playbook_configs.items():
            if playbook_config.get("enabled", False):
                self.playbooks[playbook_name] = playbook_config
                self.stats["playbooks_loaded"] += 1
                self.logger.info(f"Loaded playbook: {playbook_name}")

    async def execute_playbook(
        self,
        playbook_name: str,
        context: Dict[str, Any],
        require_approval: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a response playbook.

        Args:
            playbook_name: Name of playbook to execute
            context: Context data for playbook execution
            require_approval: Whether to require approval

        Returns:
            Execution results
        """
        if playbook_name not in self.playbooks:
            return {
                "success": False,
                "error": f"Playbook not found: {playbook_name}",
            }

        playbook = self.playbooks[playbook_name]
        self.logger.info(f"Executing playbook: {playbook_name}")

        # Check if approval is required
        if require_approval and self._requires_approval(playbook_name):
            approval_result = await self._request_approval(playbook_name, context)
            if not approval_result.get("approved", False):
                return {
                    "success": False,
                    "error": "Playbook execution not approved",
                    "approval_result": approval_result,
                }

        # Execute actions
        results = []
        for action_config in playbook.get("actions", []):
            if action_config.get("enabled", True):
                action_result = await self._execute_action(action_config, context)
                results.append(action_result)

                # Stop execution if action failed and playbook has stop_on_failure
                if (
                    not action_result.get("success", False) and
                    playbook.get("stop_on_failure", True)
                ):
                    break

        # Determine overall success
        success = all(r.get("success", False) for r in results)

        return {
            "success": success,
            "playbook": playbook_name,
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _execute_action(
        self, action_config: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a single action."""
        action_name = action_config.get("name", "unknown")
        provider = action_config.get("provider", "unknown")

        self.logger.info(f"Executing action: {action_name} with provider: {provider}")

        try:
            # Execute based on provider
            if provider == "iptables":
                result = await self._execute_iptables_action(action_config, context)
            elif provider == "slack":
                result = await self._execute_slack_action(action_config, context)
            elif provider == "email":
                result = await self._execute_email_action(action_config, context)
            elif provider == "syslog":
                result = await self._execute_syslog_action(action_config, context)
            else:
                result = {
                    "success": False,
                    "error": f"Unknown provider: {provider}",
                }

            # Update stats
            self.stats["actions_executed"] += 1
            self.stats["last_action"] = datetime.utcnow().isoformat()

            if not result.get("success", False):
                self.stats["actions_failed"] += 1

            return {
                "action": action_name,
                "provider": provider,
                "success": result.get("success", False),
                "result": result,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Error executing action {action_name}: {e}", exc_info=True)
            self.stats["actions_failed"] += 1

            return {
                "action": action_name,
                "provider": provider,
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _execute_iptables_action(
        self, action_config: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute iptables action."""
        command_template = action_config.get("command", "")
        sudo_required = action_config.get("sudo_required", True)

        # Replace variables in command
        command = self._replace_variables(command_template, context)

        if sudo_required:
            command = f"sudo {command}"

        self.logger.info(f"Executing iptables command: {command}")

        # Execute command
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "returncode": process.returncode,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
                "command": command,
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": command,
            }

    async def _execute_slack_action(
        self, action_config: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute Slack notification action."""
        import aiohttp

        webhook_url = action_config.get("webhook_url", "")
        channel = action_config.get("channel", "#soc-alerts")
        template = action_config.get("template", "")

        if not webhook_url:
            return {
                "success": False,
                "error": "Slack webhook URL not configured",
            }

        # Create message
        message = self._create_slack_message(context, channel, template)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=message) as response:
                    success = response.status == 200
                    response_text = await response.text()

                    return {
                        "success": success,
                        "status_code": response.status,
                        "response": response_text,
                    }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    async def _execute_email_action(
        self, action_config: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute email notification action."""
        # TODO: Implement email sending
        # This would use smtplib or an async email library
        return {
            "success": False,
            "error": "Email action not implemented",
        }

    async def _execute_syslog_action(
        self, action_config: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute syslog action."""
        import syslog

        facility = action_config.get("facility", "auth")
        level = action_config.get("level", "info")
        message = action_config.get("message", "SOC action executed")

        # Replace variables in message
        formatted_message = self._replace_variables(message, context)

        try:
            # Map level to syslog priority
            priorities = {
                "emerg": syslog.LOG_EMERG,
                "alert": syslog.LOG_ALERT,
                "crit": syslog.LOG_CRIT,
                "err": syslog.LOG_ERR,
                "warning": syslog.LOG_WARNING,
                "notice": syslog.LOG_NOTICE,
                "info": syslog.LOG_INFO,
                "debug": syslog.LOG_DEBUG,
            }

            priority = priorities.get(level.lower(), syslog.LOG_INFO)

            # Log to syslog
            syslog.syslog(priority, formatted_message)

            return {
                "success": True,
                "message": formatted_message,
                "facility": facility,
                "level": level,
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    def _replace_variables(self, template: str, context: Dict[str, Any]) -> str:
        """Replace variables in template with context values."""
        result = template

        for key, value in context.items():
            placeholder = f"{{{key}}}"
            if placeholder in result:
                result = result.replace(placeholder, str(value))

        return result

    def _create_slack_message(
        self, context: Dict[str, Any], channel: str, template: str
    ) -> Dict[str, Any]:
        """Create Slack message from template and context."""
        if template:
            # Load template from file
            try:
                with open(f"templates/{template}", "r") as f:
                    template_content = f.read()
                message_text = self._replace_variables(template_content, context)
            except:
                message_text = str(context)
        else:
            # Default template
            message_text = json.dumps(context, indent=2)

        return {
            "channel": channel,
            "text": "SOC Alert - Action Executed",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*SOC Action Executed*\n{message_text}",
                    },
                },
            ],
        }

    def _requires_approval(self, playbook_name: str) -> bool:
        """Check if playbook requires approval."""
        approval_config = self.config.get("response", {}).get("approval", {})
        required_for = approval_config.get("required_for", [])

        return playbook_name in required_for

    async def _request_approval(
        self, playbook_name: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Request approval for playbook execution."""
        # TODO: Implement approval workflow
        # This could send emails, create tickets, etc.
        self.logger.info(f"Approval required for playbook: {playbook_name}")

        # For now, auto-approve
        return {
            "approved": True,
            "approver": "auto",
            "timestamp": datetime.utcnow().isoformat(),
            "playbook": playbook_name,
        }

    async def _process_actions(self):
        """Process actions from queue."""
        self.logger.info("Starting action processor")

        while self.running:
            try:
                # Get action from queue
                action = await asyncio.wait_for(self.action_queue.get(), timeout=1.0)

                # Execute action
                await self._execute_queued_action(action)

                # Mark task as done
                self.action_queue.task_done()

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error processing action: {e}", exc_info=True)

    async def _execute_queued_action(self, action: Dict[str, Any]):
        """Execute action from queue."""
        playbook_name = action.get("playbook")
        context = action.get("context", {})

        if playbook_name:
            await self.execute_playbook(playbook_name, context, require_approval=False)

    async def queue_playbook(self, playbook_name: str, context: Dict[str, Any]):
        """Queue a playbook for execution."""
        await self.action_queue.put({
            "playbook": playbook_name,
            "context": context,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def get_stats(self) -> Dict[str, Any]:
        """Get executor statistics."""
        return {
            "running": self.running,
            "playbooks_loaded": self.stats["playbooks_loaded"],
            "actions_executed": self.stats["actions_executed"],
            "actions_failed": self.stats["actions_failed"],
            "queue_size": self.action_queue.qsize(),
            "last_action": self.stats["last_action"],
        }

    def get_playbooks(self) -> List[str]:
        """Get list of available playbooks."""
        return list(self.playbooks.keys())