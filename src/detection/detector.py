"""
Core detection engine.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from src.core.logger import LoggerMixin
from src.detection.rules.custom_rules import RuleEngine
from src.detection.correlator import CorrelationEngine
from src.detection.scoring import AlertScorer


class DetectionEngine(LoggerMixin):
    """Main detection engine orchestrator."""

    def __init__(self, config, ws_manager=None):
        super().__init__()
        self.config = config
        self.ws_manager = ws_manager  # Store WebSocket manager for real-time updates
        self.running = False

        # Engines
        self.rule_engine = RuleEngine(config)
        self.correlation_engine = CorrelationEngine(config)
        self.scorer = AlertScorer(config)

        # State
        self.event_buffer: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "rules_triggered": 0,
            "last_alert": None,
        }

    async def start(self):
        """Start the detection engine."""
        self.logger.info("Starting detection engine...")
        self.running = True

        # Load rules
        await self.rule_engine.load_rules()

        # Start processing loop
        await self._processing_loop()

    async def stop(self):
        """Stop the detection engine."""
        self.logger.info("Stopping detection engine...")
        self.running = False

        # Clear buffers
        self.event_buffer.clear()
        self.alerts.clear()

    async def _processing_loop(self):
        """Main processing loop."""
        self.logger.info("Detection engine started")

        while self.running:
            try:
                # Process batch of events
                await self._process_batch()

                # Run correlation
                await self._run_correlation()

                # Cleanup old events
                self._cleanup_old_events()

                # Sleep between cycles
                await asyncio.sleep(1)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in detection loop: {e}", exc_info=True)
                await asyncio.sleep(5)

    async def _process_batch(self):
        """Process a batch of events."""
        if not self.event_buffer:
            return

        events_to_process = self.event_buffer.copy()
        self.event_buffer.clear()

        for event in events_to_process:
            await self._process_event(event)

    async def _process_event(self, event: Dict[str, Any]):
        """Process a single event."""
        try:
            # Apply rule detection
            rule_matches = await self.rule_engine.evaluate(event)

            # Apply ML detection (if enabled)
            ml_matches = await self._apply_ml_detection(event)

            # Combine matches
            all_matches = rule_matches + ml_matches

            if all_matches:
                # Create alerts
                alerts = await self._create_alerts(event, all_matches)
                self.alerts.extend(alerts)

                # Update stats
                self.stats["events_processed"] += 1
                self.stats["alerts_generated"] += len(alerts)
                self.stats["rules_triggered"] += len(all_matches)
                self.stats["last_alert"] = datetime.utcnow().isoformat()

                # Broadcast alerts via WebSocket
                if self.ws_manager:
                    for alert in alerts:
                        await self.ws_manager.broadcast({
                            "type": "new_alert",
                            "alert": alert,
                        }, channel="alerts", event_type="alert")

                # Log alerts
                for alert in alerts:
                    self.logger.info(
                        f"Alert generated: {alert.get('alert_id')} - "
                        f"{alert.get('rule_name')} - "
                        f"Severity: {alert.get('severity')}"
                    )

            # Add to correlation engine
            await self.correlation_engine.add_event(event)

        except Exception as e:
            self.logger.error(f"Error processing event: {e}", exc_info=True)

    async def _apply_ml_detection(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply ML-based detection."""
        # TODO: Implement ML detection
        # This would call src.ml.inference for anomaly detection
        return []

    async def _create_alerts(
        self, event: Dict[str, Any], matches: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Create alerts from detection matches."""
        alerts = []

        for match in matches:
            alert = {
                "alert_id": self._generate_alert_id(),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event": event,
                "rule_id": match.get("rule_id"),
                "rule_name": match.get("rule_name"),
                "description": match.get("description"),
                "severity": match.get("severity", "medium"),
                "confidence": match.get("confidence", 0.5),
                "category": match.get("category", "unknown"),
                "indicators": match.get("indicators", []),
                "source_ip": event.get("src_ip") or event.get("source_ip"),
                "dest_ip": event.get("dst_ip") or event.get("dest_ip"),
                "status": "new",
            }

            # Calculate composite score
            alert["score"] = self.scorer.calculate_score(alert)

            # Determine if alert should be escalated
            alert["escalated"] = self.scorer.should_escalate(alert)

            alerts.append(alert)

        return alerts

    async def _run_correlation(self):
        """Run correlation engine."""
        try:
            correlation_alerts = await self.correlation_engine.run_correlation()

            if correlation_alerts:
                self.alerts.extend(correlation_alerts)
                self.stats["alerts_generated"] += len(correlation_alerts)

                # Broadcast correlation alerts via WebSocket
                if self.ws_manager:
                    for alert in correlation_alerts:
                        await self.ws_manager.broadcast({
                            "type": "new_alert",
                            "alert": alert,
                        }, channel="alerts", event_type="alert")

                for alert in correlation_alerts:
                    self.logger.info(
                        f"Correlation alert: {alert.get('alert_id')} - "
                        f"Pattern: {alert.get('pattern_name')}"
                    )

        except Exception as e:
            self.logger.error(f"Error in correlation: {e}", exc_info=True)

    def _cleanup_old_events(self):
        """Clean up old events from buffers."""
        # Keep last 10,000 events for correlation
        if len(self.event_buffer) > 10000:
            self.event_buffer = self.event_buffer[-10000:]

        # Keep last 1,000 alerts
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        import random
        return f"ALERT-{timestamp}-{random.randint(1000, 9999)}"

    async def add_event(self, event: Dict[str, Any]):
        """Add event for processing (called by ingestion)."""
        self.event_buffer.append(event)

    async def run_cycle(self):
        """Run a single detection cycle (for testing)."""
        await self._process_batch()
        await self._run_correlation()

    def get_alerts(
        self, limit: int = 100, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        alerts = self.alerts.copy()

        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]

        return alerts[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        return {
            "running": self.running,
            "alerts_count": len(self.alerts),
            **self.stats,
            "rule_engine": self.rule_engine.get_stats(),
            "correlation_engine": self.correlation_engine.get_stats(),
        }