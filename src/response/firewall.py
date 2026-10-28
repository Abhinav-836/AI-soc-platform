"""
Host firewall control - safely.

The old implementation built shell strings like
    f"sudo iptables -A INPUT -s {ip_address} -j DROP"
from API input and ran them with create_subprocess_shell, so a value such as
"1.2.3.4; <anything>" would have executed <anything> as root. Now:

  * the IP is parsed with the ipaddress module - anything else is rejected
  * commands are argument lists run without a shell
  * internal / protected addresses are refused unless explicitly allowed
  * nothing runs in dry-run mode
"""
import ipaddress
import platform
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from src.core.logger import LoggerMixin
from src.detection.rules.matcher import is_private_ip

RULE_PREFIX = "AI-SOC block"


class FirewallError(ValueError):
    pass


class FirewallManager(LoggerMixin):
    def __init__(self, cfg: Optional[Dict[str, Any]] = None):
        cfg = cfg or {}
        backend = str(cfg.get("backend", "auto")).lower()
        if backend == "auto":
            if platform.system() == "Windows":
                backend = "windows"
            elif shutil.which("iptables"):
                backend = "iptables"
            else:
                backend = "none"
        self.backend = backend
        self.allow_private = bool(cfg.get("allow_private", False))
        self.protected = [ipaddress.ip_network(p, strict=False) for p in cfg.get("protected", []) or []]

    def validate(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            raise FirewallError(f"'{ip}' is not a valid IP address")
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            raise FirewallError(f"refusing to block special address {addr}")
        if is_private_ip(str(addr)) and not self.allow_private:
            raise FirewallError(f"refusing to block internal address {addr} (firewall.allow_private is false)")
        if any(addr in net for net in self.protected):
            raise FirewallError(f"{addr} is in the protected list")
        return str(addr)

    def _commands(self, ip: str, block: bool) -> List[List[str]]:
        name = f"{RULE_PREFIX} {ip}"
        if self.backend == "windows":
            if block:
                return [["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in",
                         "action=block", f"remoteip={ip}"]]
            return [["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]]
        if self.backend == "iptables":
            tool = "ip6tables" if ":" in ip else "iptables"
            flag = "-I" if block else "-D"
            return [[tool, flag, "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", name]]
        return []

    def apply(self, ip: str, block: bool = True, dry_run: bool = True) -> Dict[str, Any]:
        ip = self.validate(ip)
        commands = self._commands(ip, block)
        result = {"ip": ip, "backend": self.backend, "commands": [" ".join(c) for c in commands]}
        if dry_run:
            return {**result, "status": "dry_run"}
        if not commands:
            return {**result, "status": "failed", "error": f"no supported firewall backend ({self.backend})"}
        for cmd in commands:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20, shell=False)
            except (OSError, subprocess.TimeoutExpired) as e:
                return {**result, "status": "failed", "error": str(e)}
            if proc.returncode != 0:
                return {**result, "status": "failed", "error": (proc.stderr or proc.stdout).strip()[:500],
                        "hint": "the platform needs administrator/root rights to change the firewall"}
        return {**result, "status": "done"}
