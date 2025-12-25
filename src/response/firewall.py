"""
Firewall integration for automated response.
"""

import subprocess
import ipaddress
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import asyncio
from src.utils.logger import LoggerMixin


class FirewallManager(LoggerMixin):
    """Manages firewall rules for automated response."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.firewall_type = self._detect_firewall_type()
        self.stats = {
            "ips_blocked": 0,
            "ips_unblocked": 0,
            "rules_added": 0,
            "rules_removed": 0,
            "errors": 0,
        }

    def _detect_firewall_type(self) -> str:
        """Detect available firewall type."""
        try:
            # Try iptables
            result = subprocess.run(
                ["which", "iptables"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return "iptables"

            # Try Windows firewall
            result = subprocess.run(
                ["powershell", "-Command", "Get-Command", "New-NetFirewallRule"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return "windows_firewall"

            # Try nftables
            result = subprocess.run(
                ["which", "nft"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return "nftables"

            # Try ufw (Ubuntu)
            result = subprocess.run(
                ["which", "ufw"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return "ufw"

        except Exception as e:
            self.logger.error(f"Error detecting firewall type: {e}")

        return "unknown"

    async def block_ip(
        self,
        ip_address: str,
        reason: str = "malicious_activity",
        duration: Optional[int] = None,
        protocol: str = "all",
        ports: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Block an IP address.

        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (None for permanent)
            protocol: Protocol to block (tcp, udp, all)
            ports: Specific ports to block (None for all ports)

        Returns:
            Block operation result
        """
        self.logger.info(f"Blocking IP: {ip_address} ({reason})")

        # Validate IP address
        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return {
                "success": False,
                "error": f"Invalid IP address: {ip_address}",
            }

        # Check if already blocked
        if ip_address in self.blocked_ips:
            return {
                "success": False,
                "error": f"IP already blocked: {ip_address}",
                "existing_block": self.blocked_ips[ip_address],
            }

        try:
            # Execute firewall command based on type
            if self.firewall_type == "iptables":
                result = await self._block_ip_iptables(ip_address, protocol, ports)
            elif self.firewall_type == "windows_firewall":
                result = await self._block_ip_windows(ip_address, protocol, ports)
            elif self.firewall_type == "nftables":
                result = await self._block_ip_nftables(ip_address, protocol, ports)
            elif self.firewall_type == "ufw":
                result = await self._block_ip_ufw(ip_address)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported firewall type: {self.firewall_type}",
                }

            if result["success"]:
                # Record the block
                block_info = {
                    "ip": ip_address,
                    "reason": reason,
                    "blocked_at": datetime.utcnow().isoformat(),
                    "expires_at": (
                        (datetime.utcnow() + timedelta(seconds=duration)).isoformat()
                        if duration
                        else None
                    ),
                    "protocol": protocol,
                    "ports": ports,
                    "firewall_type": self.firewall_type,
                }

                self.blocked_ips[ip_address] = block_info
                self.stats["ips_blocked"] += 1
                self.stats["rules_added"] += 1

                self.logger.info(f"Successfully blocked IP: {ip_address}")

                result["block_info"] = block_info

            return result

        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address}: {e}", exc_info=True)
            self.stats["errors"] += 1

            return {
                "success": False,
                "error": str(e),
                "ip": ip_address,
            }

    async def _block_ip_iptables(
        self, ip_address: str, protocol: str, ports: Optional[List[int]]
    ) -> Dict[str, Any]:
        """Block IP using iptables."""
        commands = []

        if ports:
            for port in ports:
                if protocol in ["tcp", "all"]:
                    commands.append(f"iptables -A INPUT -s {ip_address} -p tcp --dport {port} -j DROP")
                if protocol in ["udp", "all"]:
                    commands.append(f"iptables -A INPUT -s {ip_address} -p udp --dport {port} -j DROP")
        else:
            # Block all traffic from IP
            commands.append(f"iptables -A INPUT -s {ip_address} -j DROP")
            if protocol in ["tcp", "all"]:
                commands.append(f"iptables -A INPUT -s {ip_address} -p tcp -j DROP")
            if protocol in ["udp", "all"]:
                commands.append(f"iptables -A INPUT -s {ip_address} -p udp -j DROP")

        # Execute commands
        results = []
        for cmd in commands:
            try:
                process = await asyncio.create_subprocess_shell(
                    f"sudo {cmd}" if self._needs_sudo() else cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()

                results.append({
                    "command": cmd,
                    "success": process.returncode == 0,
                    "stdout": stdout.decode().strip(),
                    "stderr": stderr.decode().strip(),
                })

            except Exception as e:
                results.append({
                    "command": cmd,
                    "success": False,
                    "error": str(e),
                })

        # Check if all commands succeeded
        success = all(r["success"] for r in results)

        return {
            "success": success,
            "commands": results,
            "firewall_type": "iptables",
        }

    async def _block_ip_windows(
        self, ip_address: str, protocol: str, ports: Optional[List[int]]
    ) -> Dict[str, Any]:
        """Block IP using Windows Firewall."""
        rule_name = f"Block_{ip_address}_{int(datetime.utcnow().timestamp())}"

        # Build PowerShell command
        if ports:
            port_string = ",".join(str(p) for p in ports)
            cmd = (
                f"New-NetFirewallRule -DisplayName '{rule_name}' "
                f"-Direction Inbound -Action Block -RemoteAddress {ip_address} "
                f"-Protocol {protocol.upper()} -LocalPort {port_string}"
            )
        else:
            cmd = (
                f"New-NetFirewallRule -DisplayName '{rule_name}' "
                f"-Direction Inbound -Action Block -RemoteAddress {ip_address}"
            )

        try:
            process = await asyncio.create_subprocess_shell(
                f"powershell -Command \"{cmd}\"",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "command": cmd,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
                "rule_name": rule_name,
                "firewall_type": "windows_firewall",
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": cmd,
                "firewall_type": "windows_firewall",
            }

    async def _block_ip_nftables(
        self, ip_address: str, protocol: str, ports: Optional[List[int]]
    ) -> Dict[str, Any]:
        """Block IP using nftables."""
        # Note: nftables syntax varies by setup
        # This is a simplified example
        table = "filter"
        chain = "input"

        if ports:
            port_rules = []
            for port in ports:
                if protocol in ["tcp", "all"]:
                    port_rules.append(f"ip saddr {ip_address} tcp dport {port} drop")
                if protocol in ["udp", "all"]:
                    port_rules.append(f"ip saddr {ip_address} udp dport {port} drop")
            
            cmd = f"nft add rule {table} {chain} {' '.join(port_rules)}"
        else:
            cmd = f"nft add rule {table} {chain} ip saddr {ip_address} drop"

        try:
            process = await asyncio.create_subprocess_shell(
                f"sudo {cmd}" if self._needs_sudo() else cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "command": cmd,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
                "firewall_type": "nftables",
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": cmd,
                "firewall_type": "nftables",
            }

    async def _block_ip_ufw(self, ip_address: str) -> Dict[str, Any]:
        """Block IP using UFW (Ubuntu)."""
        cmd = f"ufw deny from {ip_address}"

        try:
            process = await asyncio.create_subprocess_shell(
                f"sudo {cmd}" if self._needs_sudo() else cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "command": cmd,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
                "firewall_type": "ufw",
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": cmd,
                "firewall_type": "ufw",
            }

    async def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Unblock an IP address."""
        self.logger.info(f"Unblocking IP: {ip_address}")

        if ip_address not in self.blocked_ips:
            return {
                "success": False,
                "error": f"IP not found in blocked list: {ip_address}",
            }

        block_info = self.blocked_ips[ip_address]
        firewall_type = block_info.get("firewall_type", self.firewall_type)

        try:
            if firewall_type == "iptables":
                result = await self._unblock_ip_iptables(ip_address, block_info)
            elif firewall_type == "windows_firewall":
                result = await self._unblock_ip_windows(ip_address, block_info)
            elif firewall_type == "nftables":
                result = await self._unblock_ip_nftables(ip_address, block_info)
            elif firewall_type == "ufw":
                result = await self._unblock_ip_ufw(ip_address)
            else:
                return {
                    "success": False,
                    "error": f"Unknown firewall type: {firewall_type}",
                }

            if result["success"]:
                # Remove from blocked list
                del self.blocked_ips[ip_address]
                self.stats["ips_unblocked"] += 1
                self.stats["rules_removed"] += 1

                self.logger.info(f"Successfully unblocked IP: {ip_address}")

            return result

        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address}: {e}", exc_info=True)
            self.stats["errors"] += 1

            return {
                "success": False,
                "error": str(e),
                "ip": ip_address,
            }

    async def _unblock_ip_iptables(self, ip_address: str, block_info: Dict[str, Any]) -> Dict[str, Any]:
        """Unblock IP using iptables."""
        # Remove the specific rule that was added
        # This is simplified - in production, you'd track the exact rule numbers
        cmd = f"iptables -D INPUT -s {ip_address} -j DROP"

        try:
            process = await asyncio.create_subprocess_shell(
                f"sudo {cmd}" if self._needs_sudo() else cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "command": cmd,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": cmd,
            }

    async def _unblock_ip_windows(self, ip_address: str, block_info: Dict[str, Any]) -> Dict[str, Any]:
        """Unblock IP using Windows Firewall."""
        rule_name = block_info.get("rule_name", f"Block_{ip_address}")

        cmd = f"Remove-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"

        try:
            process = await asyncio.create_subprocess_shell(
                f"powershell -Command \"{cmd}\"",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "command": cmd,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": cmd,
            }

    async def _unblock_ip_nftables(self, ip_address: str, block_info: Dict[str, Any]) -> Dict[str, Any]:
        """Unblock IP using nftables."""
        # This would need to track the exact handle of the rule
        # Simplified version
        cmd = f"nft delete rule filter input handle {block_info.get('rule_handle', '')}"

        try:
            process = await asyncio.create_subprocess_shell(
                f"sudo {cmd}" if self._needs_sudo() else cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "command": cmd,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": cmd,
            }

    async def _unblock_ip_ufw(self, ip_address: str) -> Dict[str, Any]:
        """Unblock IP using UFW."""
        cmd = f"ufw delete deny from {ip_address}"

        try:
            process = await asyncio.create_subprocess_shell(
                f"sudo {cmd}" if self._needs_sudo() else cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "command": cmd,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": cmd,
            }

    def _needs_sudo(self) -> bool:
        """Check if sudo is needed for firewall commands."""
        # Check configuration
        config = self.config.get("response", {}).get("providers", {}).get("firewall", {})
        
        if self.firewall_type == "iptables":
            return config.get("iptables", {}).get("sudo_required", True)
        elif self.firewall_type == "nftables":
            return config.get("nftables", {}).get("sudo_required", True)
        elif self.firewall_type == "ufw":
            return config.get("ufw", {}).get("sudo_required", True)
        
        return True  # Default to requiring sudo

    async def list_blocked_ips(self) -> List[Dict[str, Any]]:
        """List all currently blocked IPs."""
        return list(self.blocked_ips.values())

    async def cleanup_expired_blocks(self):
        """Remove expired IP blocks."""
        current_time = datetime.utcnow()
        expired_ips = []

        for ip_address, block_info in self.blocked_ips.items():
            expires_at = block_info.get("expires_at")
            if expires_at:
                try:
                    expire_time = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if current_time >= expire_time:
                        expired_ips.append(ip_address)
                except (ValueError, KeyError):
                    continue

        for ip_address in expired_ips:
            self.logger.info(f"Auto-unblocking expired IP: {ip_address}")
            await self.unblock_ip(ip_address)

    def get_stats(self) -> Dict[str, Any]:
        """Get firewall statistics."""
        return {
            "firewall_type": self.firewall_type,
            "blocked_ips_count": len(self.blocked_ips),
            **self.stats,
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform firewall health check."""
        try:
            # Test firewall connectivity
            if self.firewall_type == "iptables":
                cmd = "iptables -L -n"
            elif self.firewall_type == "windows_firewall":
                cmd = "powershell -Command \"Get-NetFirewallProfile\""
            elif self.firewall_type == "nftables":
                cmd = "nft list ruleset"
            elif self.firewall_type == "ufw":
                cmd = "ufw status"
            else:
                return {
                    "status": "unknown",
                    "message": f"Unknown firewall type: {self.firewall_type}",
                }

            process = await asyncio.create_subprocess_shell(
                f"sudo {cmd}" if self._needs_sudo() else cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                return {
                    "status": "healthy",
                    "firewall_type": self.firewall_type,
                    "message": "Firewall is accessible",
                }
            else:
                return {
                    "status": "unhealthy",
                    "firewall_type": self.firewall_type,
                    "message": stderr.decode().strip(),
                }

        except Exception as e:
            return {
                "status": "error",
                "firewall_type": self.firewall_type,
                "message": str(e),
            }