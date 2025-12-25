"""
ML model inference engine.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime

from src.core.logger import LoggerMixin
from src.ml.anomaly.isolation_forest import IsolationForestAnomalyDetector
from src.ml.anomaly.autoencoder import AutoencoderAnomalyDetector


class MLInferenceEngine(LoggerMixin):
    """Orchestrates ML model inference."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.models: Dict[str, Any] = {}
        self.feature_extractor = FeatureExtractor(config)
        self.stats = {
            "inferences": 0,
            "anomalies_detected": 0,
            "model_load_errors": 0,
            "last_inference": None,
        }

    async def initialize(self):
        """Initialize ML models."""
        self.logger.info("Initializing ML inference engine...")

        ml_config = self.config.get("ml", {})

        # Load anomaly detection models
        if ml_config.get("models", {}).get("anomaly", {}).get("isolation_forest", {}).get("enabled", False):
            await self._load_isolation_forest()

        if ml_config.get("models", {}).get("anomaly", {}).get("autoencoder", {}).get("enabled", False):
            await self._load_autoencoder()

        self.logger.info(f"ML inference engine initialized with {len(self.models)} models")

    async def _load_isolation_forest(self):
        """Load Isolation Forest model."""
        try:
            model_path = self.config.get("storage", {}).get("model_path", "./data/models")
            model_file = f"{model_path}/isolation_forest.pkl"

            detector = IsolationForestAnomalyDetector(self.config)
            detector.load(model_file)
            self.models["isolation_forest"] = detector

            self.logger.info("Isolation Forest model loaded")
        except Exception as e:
            self.logger.error(f"Error loading Isolation Forest: {e}", exc_info=True)
            self.stats["model_load_errors"] += 1

    async def _load_autoencoder(self):
        """Load Autoencoder model."""
        try:
            model_path = self.config.get("storage", {}).get("model_path", "./data/models")
            model_file = f"{model_path}/autoencoder.h5"

            detector = AutoencoderAnomalyDetector(self.config)
            detector.load(model_file)
            self.models["autoencoder"] = detector

            self.logger.info("Autoencoder model loaded")
        except Exception as e:
            self.logger.error(f"Error loading Autoencoder: {e}", exc_info=True)
            self.stats["model_load_errors"] += 1

    async def detect_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect anomalies in events.

        Args:
            events: List of events to analyze

        Returns:
            List of anomaly detection results
        """
        if not self.models:
            self.logger.warning("No ML models loaded")
            return []

        results = []

        for event in events:
            try:
                # Extract features
                features = self.feature_extractor.extract(event)

                # Run inference with each model
                model_results = []
                for model_name, model in self.models.items():
                    if hasattr(model, 'detect'):
                        result = model.detect(features)
                        result["model"] = model_name
                        model_results.append(result)

                # Combine results
                combined_result = self._combine_results(model_results, event)
                results.append(combined_result)

                # Update stats
                self.stats["inferences"] += 1
                if combined_result.get("is_anomaly", False):
                    self.stats["anomalies_detected"] += 1
                self.stats["last_inference"] = datetime.utcnow().isoformat()

            except Exception as e:
                self.logger.error(f"Error detecting anomalies: {e}", exc_info=True)
                results.append({
                    "event_id": event.get("event_id", "unknown"),
                    "is_anomaly": False,
                    "error": str(e),
                })

        return results

    def _combine_results(self, model_results: List[Dict[str, Any]], event: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from multiple models."""
        if not model_results:
            return {
                "event_id": event.get("event_id", "unknown"),
                "is_anomaly": False,
                "confidence": 0.0,
                "models": [],
            }

        # Calculate weighted average of anomaly scores
        total_weight = 0
        weighted_score = 0
        model_details = []

        for result in model_results:
            score = result.get("score", 0)
            confidence = result.get("confidence", 0.5)
            
            # Weight by confidence
            weight = confidence
            weighted_score += score * weight
            total_weight += weight

            model_details.append({
                "model": result.get("model"),
                "score": score,
                "confidence": confidence,
                "anomaly": result.get("anomaly", False),
            })

        if total_weight > 0:
            combined_score = weighted_score / total_weight
        else:
            combined_score = 0

        # Determine if anomaly based on threshold
        threshold = self.config.get("ml", {}).get("inference", {}).get("anomaly_threshold", 0.95)
        is_anomaly = combined_score >= threshold

        return {
            "event_id": event.get("event_id", "unknown"),
            "is_anomaly": is_anomaly,
            "score": combined_score,
            "confidence": min(combined_score, 1.0),  # Use score as confidence
            "threshold": threshold,
            "models": model_details,
            "features": event.get("features", {}),
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def batch_detect(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect anomalies in batch mode."""
        start_time = datetime.utcnow()

        anomalies = await self.detect_anomalies(events)

        # Calculate statistics
        total_events = len(events)
        anomaly_count = sum(1 for a in anomalies if a.get("is_anomaly", False))
        anomaly_rate = anomaly_count / total_events if total_events > 0 else 0

        processing_time = (datetime.utcnow() - start_time).total_seconds()

        return {
            "total_events": total_events,
            "anomalies_detected": anomaly_count,
            "anomaly_rate": anomaly_rate,
            "processing_time_seconds": processing_time,
            "events_per_second": total_events / processing_time if processing_time > 0 else 0,
            "results": anomalies,
            "timestamp": start_time.isoformat(),
        }

    def get_model_stats(self) -> Dict[str, Any]:
        """Get model statistics."""
        model_stats = {}
        for name, model in self.models.items():
            if hasattr(model, 'get_stats'):
                model_stats[name] = model.get_stats()

        return {
            "total_models": len(self.models),
            "models": model_stats,
            **self.stats,
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on ML models."""
        checks = []

        for name, model in self.models.items():
            try:
                # Simple test inference
                test_features = {f"feature_{i}": 0.0 for i in range(10)}
                if hasattr(model, 'detect'):
                    result = model.detect(test_features)
                    status = "healthy"
                    message = "Model responding"
                else:
                    status = "warning"
                    message = "Model missing detect method"
            except Exception as e:
                status = "unhealthy"
                message = str(e)

            checks.append({
                "model": name,
                "status": status,
                "message": message,
                "timestamp": datetime.utcnow().isoformat(),
            })

        overall_status = "healthy"
        if any(check["status"] == "unhealthy" for check in checks):
            overall_status = "unhealthy"
        elif any(check["status"] == "warning" for check in checks):
            overall_status = "warning"

        return {
            "status": overall_status,
            "checks": checks,
            "timestamp": datetime.utcnow().isoformat(),
        }


class FeatureExtractor:
    """Extracts features from events for ML models."""

    def __init__(self, config):
        self.config = config
        self.feature_config = config.get("ml", {}).get("features", {})

    def extract(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from event."""
        features = {}

        # Network features
        network_features = self.feature_config.get("network", [])
        for feature_name in network_features:
            value = self._extract_network_feature(feature_name, event)
            features[feature_name] = value

        # Host features
        host_features = self.feature_config.get("host", [])
        for feature_name in host_features:
            value = self._extract_host_feature(feature_name, event)
            features[feature_name] = value

        # Add derived features
        features.update(self._extract_derived_features(event))

        return features

    def _extract_network_feature(self, feature_name: str, event: Dict[str, Any]) -> float:
        """Extract network-related feature."""
        if feature_name == "src_ip_entropy":
            src_ip = str(event.get("src_ip", ""))
            return self._calculate_entropy(src_ip)
        
        elif feature_name == "dst_port_entropy":
            dst_port = str(event.get("dst_port", 0))
            return self._calculate_entropy(dst_port)
        
        elif feature_name == "packet_size_mean":
            return float(event.get("packet_size", 0))
        
        elif feature_name == "packet_size_std":
            return 0.0  # Would need historical data
        
        elif feature_name == "bytes_per_second":
            bytes_transferred = event.get("bytes", 0)
            duration = event.get("duration", 1)
            return bytes_transferred / max(duration, 1)
        
        elif feature_name == "packets_per_second":
            packets = event.get("packets", 0)
            duration = event.get("duration", 1)
            return packets / max(duration, 1)
        
        elif feature_name == "unique_ports_per_ip":
            # Simplified - would need tracking
            return 1.0
        
        return 0.0

    def _extract_host_feature(self, feature_name: str, event: Dict[str, Any]) -> float:
        """Extract host-related feature."""
        if feature_name == "process_count":
            return float(event.get("process_count", 1))
        
        elif feature_name == "unique_users":
            return float(len(set(event.get("users", []))))
        
        elif feature_name == "failed_logins_per_hour":
            failed_logins = event.get("failed_logins", 0)
            time_window = event.get("time_window_hours", 1)
            return failed_logins / max(time_window, 1)
        
        elif feature_name == "successful_logins_per_hour":
            successful_logins = event.get("successful_logins", 0)
            time_window = event.get("time_window_hours", 1)
            return successful_logins / max(time_window, 1)
        
        elif feature_name == "file_access_count":
            return float(event.get("file_access_count", 0))
        
        return 0.0

    def _extract_derived_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract derived features."""
        features = {}

        # Time-based features
        timestamp = event.get("@timestamp", "")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                features["hour_of_day"] = dt.hour / 24.0
                features["day_of_week"] = dt.weekday() / 7.0
                features["is_weekend"] = 1.0 if dt.weekday() >= 5 else 0.0
            except (ValueError, TypeError):
                pass

        # Behavioral features
        src_ip = event.get("src_ip", "")
        if src_ip:
            # Simplified - would use actual IP reputation
            features["ip_reputation_score"] = 0.5

        # Protocol features
        protocol = str(event.get("protocol", "")).lower()
        features[f"protocol_{protocol}"] = 1.0 if protocol else 0.0

        return features

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0

        from collections import Counter
        import math

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy