"""
Metrics collection and export for monitoring.
"""

import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from src.utils.logger import LoggerMixin


class MetricsCollector(LoggerMixin):
    """Collects and manages platform metrics."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.metrics: Dict[str, Any] = defaultdict(lambda: defaultdict(list))
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.start_time = time.time()

    def increment_counter(self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric."""
        key = self._create_key(name, labels)
        self.counters[key] += value

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric."""
        key = self._create_key(name, labels)
        self.gauges[key] = value

    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record a histogram value."""
        key = self._create_key(name, labels)
        self.histograms[key].append(value)
        
        # Keep only recent values
        if len(self.histograms[key]) > 1000:
            self.histograms[key] = self.histograms[key][-1000:]

    def record_timing(self, name: str, duration: float, labels: Optional[Dict[str, str]] = None):
        """Record timing metric."""
        self.record_histogram(f"{name}_duration", duration, labels)

    def _create_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        """Create metric key with labels."""
        if not labels:
            return name
        
        # Sort labels for consistent key generation
        sorted_labels = sorted(labels.items())
        label_str = ",".join(f"{k}={v}" for k, v in sorted_labels)
        return f"{name}[{label_str}]"

    def get_metrics(self) -> Dict[str, Any]:
        """Get all current metrics."""
        now = datetime.utcnow().isoformat()
        
        metrics = {
            "timestamp": now,
            "uptime_seconds": time.time() - self.start_time,
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "histograms": {},
        }
        
        # Calculate histogram statistics
        for name, values in self.histograms.items():
            if values:
                metrics["histograms"][name] = {
                    "count": len(values),
                    "min": min(values),
                    "max": max(values),
                    "mean": sum(values) / len(values),
                    "p50": self._percentile(values, 50),
                    "p95": self._percentile(values, 95),
                    "p99": self._percentile(values, 99),
                    "recent_values": values[-10:],  # Last 10 values
                }
        
        return metrics

    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile of values."""
        if not values:
            return 0.0
        
        sorted_values = sorted(values)
        index = (len(sorted_values) - 1) * percentile / 100
        lower = int(index)
        upper = lower + 1
        
        if upper >= len(sorted_values):
            return sorted_values[lower]
        
        weight = index - lower
        return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight

    def reset_counters(self):
        """Reset all counters."""
        self.counters.clear()

    def clear_histograms(self):
        """Clear all histograms."""
        self.histograms.clear()

    async def collect_system_metrics(self):
        """Collect system-level metrics."""
        import psutil
        
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        self.set_gauge("system_cpu_percent", cpu_percent)
        
        # Memory metrics
        memory = psutil.virtual_memory()
        self.set_gauge("system_memory_percent", memory.percent)
        self.set_gauge("system_memory_used_gb", memory.used / 1024**3)
        self.set_gauge("system_memory_total_gb", memory.total / 1024**3)
        
        # Disk metrics
        disk = psutil.disk_usage("/")
        self.set_gauge("system_disk_percent", disk.percent)
        self.set_gauge("system_disk_used_gb", disk.used / 1024**3)
        self.set_gauge("system_disk_total_gb", disk.total / 1024**3)
        
        # Network metrics
        net_io = psutil.net_io_counters()
        self.set_gauge("system_network_bytes_sent", net_io.bytes_sent)
        self.set_gauge("system_network_bytes_recv", net_io.bytes_recv)
        
        # Process metrics
        process = psutil.Process()
        self.set_gauge("process_cpu_percent", process.cpu_percent())
        self.set_gauge("process_memory_percent", process.memory_percent())
        self.set_gauge("process_memory_rss_gb", process.memory_info().rss / 1024**3)
        self.set_gauge("process_threads", process.num_threads())
        
        # Open files
        try:
            self.set_gauge("process_open_files", process.num_fds())
        except:
            pass

    async def collect_platform_metrics(self, platform_stats: Dict[str, Any]):
        """Collect platform-specific metrics."""
        # Ingestion metrics
        ingestion_stats = platform_stats.get("ingestion", {})
        if ingestion_stats:
            self.set_gauge("ingestion_queue_size", ingestion_stats.get("queue_size", 0))
            self.set_gauge("ingestion_collectors", ingestion_stats.get("collectors", 0))
            
            # Collector stats
            for collector in ingestion_stats.get("collector_stats", []):
                collector_type = collector.get("type", "unknown")
                self.set_gauge(f"ingestion_{collector_type}_messages", 
                             collector.get("messages_received", 0))
        
        # Detection metrics
        detection_stats = platform_stats.get("detection", {})
        if detection_stats:
            self.set_gauge("detection_events_processed", detection_stats.get("events_processed", 0))
            self.set_gauge("detection_alerts_generated", detection_stats.get("alerts_generated", 0))
            self.set_gauge("detection_rules_triggered", detection_stats.get("rules_triggered", 0))
            
            # Rule engine stats
            rule_stats = detection_stats.get("rule_engine", {})
            if rule_stats:
                self.set_gauge("detection_rules_total", rule_stats.get("total_rules", 0))
                self.set_gauge("detection_rules_enabled", rule_stats.get("enabled_rules", 0))
        
        # Response metrics
        response_stats = platform_stats.get("response", {})
        if response_stats:
            self.set_gauge("response_actions_executed", response_stats.get("actions_executed", 0))
            self.set_gauge("response_actions_failed", response_stats.get("actions_failed", 0))
            self.set_gauge("response_queue_size", response_stats.get("queue_size", 0))
        
        # ML metrics
        ml_stats = platform_stats.get("ml", {})
        if ml_stats:
            self.set_gauge("ml_inferences", ml_stats.get("inferences", 0))
            self.set_gauge("ml_anomalies_detected", ml_stats.get("anomalies_detected", 0))

    def get_metric_history(self, metric_name: str, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get metric history for the specified time period."""
        now = time.time()
        cutoff = now - (minutes * 60)
        
        history = []
        for timestamp, metrics in sorted(self.metrics.items()):
            if timestamp >= cutoff and metric_name in metrics:
                history.append({
                    "timestamp": timestamp,
                    "value": metrics[metric_name],
                })
        
        return history

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        
        # Add help and type comments (simplified)
        lines.append("# HELP ai_soc_platform_uptime Platform uptime in seconds")
        lines.append("# TYPE ai_soc_platform_uptime gauge")
        lines.append(f'ai_soc_platform_uptime {time.time() - self.start_time}')
        
        # Export counters
        for key, value in self.counters.items():
            name = self._extract_metric_name(key)
            labels = self._extract_labels(key)
            label_str = self._format_labels_prometheus(labels)
            lines.append(f'{name}_total{label_str} {value}')
        
        # Export gauges
        for key, value in self.gauges.items():
            name = self._extract_metric_name(key)
            labels = self._extract_labels(key)
            label_str = self._format_labels_prometheus(labels)
            lines.append(f'{name}{label_str} {value}')
        
        # Export histogram summaries (simplified)
        for key, values in self.histograms.items():
            if values:
                name = self._extract_metric_name(key).replace('_duration', '')
                labels = self._extract_labels(key)
                label_str = self._format_labels_prometheus(labels)
                
                count = len(values)
                total = sum(values)
                
                lines.append(f'{name}_count{label_str} {count}')
                lines.append(f'{name}_sum{label_str} {total}')
        
        return "\n".join(lines)

    def _extract_metric_name(self, key: str) -> str:
        """Extract metric name from key."""
        if '[' in key:
            return key.split('[')[0]
        return key

    def _extract_labels(self, key: str) -> Dict[str, str]:
        """Extract labels from key."""
        if '[' not in key:
            return {}
        
        label_str = key.split('[')[1].rstrip(']')
        labels = {}
        
        for part in label_str.split(','):
            if '=' in part:
                k, v = part.split('=', 1)
                labels[k.strip()] = v.strip()
        
        return labels

    def _format_labels_prometheus(self, labels: Dict[str, str]) -> str:
        """Format labels for Prometheus export."""
        if not labels:
            return ""
        
        formatted = []
        for k, v in sorted(labels.items()):
            # Escape special characters
            v_escaped = v.replace('\\', '\\\\').replace('"', '\\"')
            formatted.append(f'{k}="{v_escaped}"')
        
        return "{" + ",".join(formatted) + "}"

    async def health_check(self) -> Dict[str, Any]:
        """Perform metrics collector health check."""
        try:
            # Collect sample metrics
            await self.collect_system_metrics()
            
            # Check if metrics are being collected
            if len(self.gauges) > 0:
                status = "healthy"
                message = f"Collecting {len(self.gauges)} gauges, {len(self.counters)} counters"
            else:
                status = "warning"
                message = "No metrics collected yet"
            
            return {
                "status": status,
                "message": message,
                "metrics_count": {
                    "gauges": len(self.gauges),
                    "counters": len(self.counters),
                    "histograms": len(self.histograms),
                },
                "timestamp": datetime.utcnow().isoformat(),
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }


class MetricsExporter:
    """Exports metrics to various backends."""
    
    def __init__(self, config):
        self.config = config
        self.exporters = []
        
        # Initialize exporters based on config
        export_config = config.get("monitoring", {}).get("metrics_export", {})
        
        if export_config.get("prometheus", {}).get("enabled", False):
            self.exporters.append(PrometheusExporter(export_config["prometheus"]))
        
        if export_config.get("elasticsearch", {}).get("enabled", False):
            self.exporters.append(ElasticsearchMetricsExporter(export_config["elasticsearch"]))
    
    async def export(self, metrics: Dict[str, Any]):
        """Export metrics through all configured exporters."""
        results = []
        
        for exporter in self.exporters:
            try:
                result = await exporter.export(metrics)
                results.append({
                    "exporter": exporter.__class__.__name__,
                    "success": True,
                    "result": result,
                })
            except Exception as e:
                results.append({
                    "exporter": exporter.__class__.__name__,
                    "success": False,
                    "error": str(e),
                })
        
        return results


class PrometheusExporter:
    """Exports metrics to Prometheus pushgateway."""
    
    def __init__(self, config: Dict[str, Any]):
        self.pushgateway_url = config.get("pushgateway_url")
        self.job_name = config.get("job_name", "ai-soc-platform")
        self.instance = config.get("instance", "default")
        self.interval = config.get("interval", 30)
    
    async def export(self, metrics: Dict[str, Any]):
        """Export metrics to Prometheus pushgateway."""
        if not self.pushgateway_url:
            return {"skipped": "No pushgateway URL configured"}
        
        import aiohttp
        
        # Format metrics for Prometheus
        # In a real implementation, this would format the metrics properly
        metric_data = "# AI SOC Platform metrics\n"
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.pushgateway_url}/metrics/job/{self.job_name}/instance/{self.instance}"
                async with session.post(url, data=metric_data, timeout=10) as response:
                    return {
                        "status_code": response.status,
                        "message": await response.text(),
                    }
        except Exception as e:
            raise Exception(f"Failed to export to Prometheus: {e}")


class ElasticsearchMetricsExporter:
    """Exports metrics to Elasticsearch."""
    
    def __init__(self, config: Dict[str, Any]):
        self.index_name = config.get("index_name", "ai-soc-metrics")
        self.batch_size = config.get("batch_size", 100)
    
    async def export(self, metrics: Dict[str, Any]):
        """Export metrics to Elasticsearch."""
        # In a real implementation, this would connect to Elasticsearch
        # and index the metrics
        return {
            "indexed": True,
            "document_count": 1,
            "index": self.index_name,
        }