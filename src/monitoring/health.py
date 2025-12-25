"""
Platform health monitoring and metrics.
"""

import asyncio
import psutil
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.utils.logger import LoggerMixin


class HealthMonitor(LoggerMixin):
    """Monitors platform health and metrics."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.running = False
        self.metrics: Dict[str, Any] = {}
        self.health_checks: List[Dict[str, Any]] = []
        self.start_time = time.time()

    async def start(self):
        """Start health monitoring."""
        self.logger.info("Starting health monitor...")
        self.running = True

        # Initialize health checks
        self._init_health_checks()

        # Start monitoring loop
        await self._monitoring_loop()

    async def stop(self):
        """Stop health monitoring."""
        self.logger.info("Stopping health monitor...")
        self.running = False

    def _init_health_checks(self):
        """Initialize health checks."""
        self.health_checks = [
            {
                "name": "cpu_usage",
                "description": "CPU usage",
                "check_fn": self._check_cpu_usage,
                "warning_threshold": 80,
                "critical_threshold": 95,
                "interval": 60,
                "last_check": 0,
            },
            {
                "name": "memory_usage",
                "description": "Memory usage",
                "check_fn": self._check_memory_usage,
                "warning_threshold": 85,
                "critical_threshold": 95,
                "interval": 60,
                "last_check": 0,
            },
            {
                "name": "disk_usage",
                "description": "Disk usage",
                "check_fn": self._check_disk_usage,
                "warning_threshold": 80,
                "critical_threshold": 90,
                "interval": 300,
                "last_check": 0,
            },
            {
                "name": "process_alive",
                "description": "Process availability",
                "check_fn": self._check_process_alive,
                "warning_threshold": 0,
                "critical_threshold": 0,
                "interval": 30,
                "last_check": 0,
            },
        ]

    async def _monitoring_loop(self):
        """Main monitoring loop."""
        self.logger.info("Health monitoring started")

        while self.running:
            try:
                # Run health checks
                await self._run_health_checks()

                # Collect metrics
                await self._collect_metrics()

                # Log status
                if self.logger.isEnabledFor(10):  # DEBUG level
                    self.logger.debug(f"Health status: {self.get_status()}")

                # Sleep between cycles
                await asyncio.sleep(10)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                await asyncio.sleep(30)

    async def _run_health_checks(self):
        """Run all health checks."""
        current_time = time.time()

        for check in self.health_checks:
            if current_time - check["last_check"] >= check["interval"]:
                try:
                    result = await check["check_fn"]()
                    check["last_result"] = result
                    check["last_check"] = current_time

                    # Update check status
                    value = result.get("value", 0)
                    threshold = check.get("critical_threshold", 100)

                    if value >= threshold:
                        status = "critical"
                    elif value >= check.get("warning_threshold", 80):
                        status = "warning"
                    else:
                        status = "healthy"

                    check["status"] = status
                    check["last_update"] = datetime.utcnow().isoformat()

                    # Log critical issues
                    if status == "critical":
                        self.logger.error(
                            f"Health check CRITICAL: {check['name']} - {result.get('message', '')}"
                        )
                    elif status == "warning":
                        self.logger.warning(
                            f"Health check WARNING: {check['name']} - {result.get('message', '')}"
                        )

                except Exception as e:
                    self.logger.error(f"Error in health check {check['name']}: {e}", exc_info=True)
                    check["last_result"] = {"error": str(e)}
                    check["status"] = "error"
                    check["last_check"] = current_time

    async def _collect_metrics(self):
        """Collect system and application metrics."""
        # System metrics
        self.metrics["system"] = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "boot_time": psutil.boot_time(),
            "uptime": time.time() - psutil.boot_time(),
        }

        # Process metrics
        process = psutil.Process()
        self.metrics["process"] = {
            "pid": process.pid,
            "name": process.name(),
            "cpu_percent": process.cpu_percent(),
            "memory_percent": process.memory_percent(),
            "num_threads": process.num_threads(),
            "num_fds": process.num_fds() if hasattr(process, "num_fds") else 0,
            "create_time": process.create_time(),
        }

        # Network metrics
        net_io = psutil.net_io_counters()
        self.metrics["network"] = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "errin": net_io.errin,
            "errout": net_io.errout,
            "dropin": net_io.dropin,
            "dropout": net_io.dropout,
        }

        # Platform metrics
        self.metrics["platform"] = {
            "uptime": time.time() - self.start_time,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _check_cpu_usage(self) -> Dict[str, Any]:
        """Check CPU usage."""
        cpu_percent = psutil.cpu_percent(interval=1)

        return {
            "value": cpu_percent,
            "message": f"CPU usage: {cpu_percent:.1f}%",
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage."""
        memory = psutil.virtual_memory()
        memory_percent = memory.percent

        return {
            "value": memory_percent,
            "message": f"Memory usage: {memory_percent:.1f}% ({memory.used / 1024**3:.1f}GB/{memory.total / 1024**3:.1f}GB)",
            "timestamp": datetime.utcnow().isoformat(),
            "details": {
                "total_gb": memory.total / 1024**3,
                "used_gb": memory.used / 1024**3,
                "available_gb": memory.available / 1024**3,
            },
        }

    async def _check_disk_usage(self) -> Dict[str, Any]:
        """Check disk usage."""
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent

        return {
            "value": disk_percent,
            "message": f"Disk usage: {disk_percent:.1f}% ({disk.used / 1024**3:.1f}GB/{disk.total / 1024**3:.1f}GB)",
            "timestamp": datetime.utcnow().isoformat(),
            "details": {
                "total_gb": disk.total / 1024**3,
                "used_gb": disk.used / 1024**3,
                "free_gb": disk.free / 1024**3,
            },
        }

    async def _check_process_alive(self) -> Dict[str, Any]:
        """Check if process is alive."""
        try:
            process = psutil.Process()
            status = process.status()

            return {
                "value": 0 if status in ["running", "sleeping"] else 100,
                "message": f"Process status: {status}",
                "timestamp": datetime.utcnow().isoformat(),
                "details": {
                    "status": status,
                    "pid": process.pid,
                },
            }
        except psutil.NoSuchProcess:
            return {
                "value": 100,
                "message": "Process not found",
                "timestamp": datetime.utcnow().isoformat(),
                "details": {
                    "status": "not_found",
                },
            }

    async def run_health_check(self, check_name: Optional[str] = None) -> Dict[str, Any]:
        """Run specific health check or all checks."""
        if check_name:
            for check in self.health_checks:
                if check["name"] == check_name:
                    result = await check["check_fn"]()
                    return {
                        "check": check_name,
                        "result": result,
                        "timestamp": datetime.utcnow().isoformat(),
                    }

            return {
                "check": check_name,
                "error": f"Health check not found: {check_name}",
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            results = {}
            for check in self.health_checks:
                result = await check["check_fn"]()
                results[check["name"]] = result

            return {
                "checks": results,
                "timestamp": datetime.utcnow().isoformat(),
            }

    def get_status(self) -> Dict[str, Any]:
        """Get overall health status."""
        status_counts = {
            "healthy": 0,
            "warning": 0,
            "critical": 0,
            "error": 0,
        }

        for check in self.health_checks:
            status = check.get("status", "unknown")
            if status in status_counts:
                status_counts[status] += 1

        # Determine overall status
        if status_counts["critical"] > 0:
            overall_status = "critical"
        elif status_counts["error"] > 0:
            overall_status = "error"
        elif status_counts["warning"] > 0:
            overall_status = "warning"
        else:
            overall_status = "healthy"

        return {
            "status": overall_status,
            "counts": status_counts,
            "checks": [
                {
                    "name": check["name"],
                    "description": check["description"],
                    "status": check.get("status", "unknown"),
                    "last_result": check.get("last_result", {}),
                    "last_check": check.get("last_check", 0),
                }
                for check in self.health_checks
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get collected metrics."""
        return self.metrics.copy()

    def get_platform_info(self) -> Dict[str, Any]:
        """Get platform information."""
        import platform

        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "hostname": platform.node(),
            "processor": platform.processor(),
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "uptime": time.time() - self.start_time,
        }