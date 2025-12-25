"""
Model drift detection and monitoring.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from scipy import stats

from src.utils.logger import LoggerMixin
from src.storage.local_store import LocalStorage


class DriftMonitor(LoggerMixin):
    """Monitors model performance and data drift."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.storage = LocalStorage(config)
        self.drift_config = config.get("ml", {}).get("drift_detection", {})
        
        self.drift_history: List[Dict[str, Any]] = []
        self.stats = {
            "drift_checks": 0,
            "drifts_detected": 0,
            "false_positives": 0,
            "last_check": None,
        }

    async def check_drift(self, recent_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Check for model drift.

        Args:
            recent_events: Recent events to compare with training data

        Returns:
            Drift detection results
        """
        self.logger.info("Checking for model drift...")

        try:
            # Get reference data (training data)
            reference_data = await self._get_reference_data()
            if reference_data is None or len(reference_data) == 0:
                return {"error": "No reference data available"}

            # Get current data
            if recent_events is None:
                current_data = await self._get_current_data()
            else:
                current_data = await self._extract_features(recent_events)

            if current_data is None or len(current_data) == 0:
                return {"error": "No current data available"}

            # Check different types of drift
            drift_results = {
                "data_drift": await self._check_data_drift(reference_data, current_data),
                "concept_drift": await self._check_concept_drift(reference_data, current_data),
                "performance_drift": await self._check_performance_drift(),
                "timestamp": datetime.utcnow().isoformat(),
            }

            # Determine overall drift status
            overall_drift = self._determine_overall_drift(drift_results)
            drift_results["overall_drift"] = overall_drift

            # Update statistics
            self.stats["drift_checks"] += 1
            self.stats["last_check"] = datetime.utcnow().isoformat()
            
            if overall_drift.get("drift_detected", False):
                self.stats["drifts_detected"] += 1
                self.logger.warning(f"Drift detected: {overall_drift.get('severity')}")

            # Store drift history
            self.drift_history.append(drift_results)
            
            # Keep only recent history
            if len(self.drift_history) > 100:
                self.drift_history = self.drift_history[-100:]

            return drift_results

        except Exception as e:
            self.logger.error(f"Error checking drift: {e}", exc_info=True)
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def _get_reference_data(self) -> Optional[np.ndarray]:
        """Get reference/training data."""
        # Try to load from storage
        try:
            # This would load the actual training data used for models
            # For now, we'll use a simplified approach
            events = self.storage.load_events(
                event_type="processed",
                limit=5000,
                end_time=datetime.utcnow() - timedelta(days=7)  # Old data
            )
            
            if events:
                from src.ml.inference import FeatureExtractor
                feature_extractor = FeatureExtractor(self.config)
                
                features_list = []
                for event in events:
                    features = feature_extractor.extract(event)
                    features_list.append(features)
                
                df = pd.DataFrame(features_list).fillna(0)
                return df.values
            
        except Exception as e:
            self.logger.error(f"Error loading reference data: {e}", exc_info=True)
        
        return None

    async def _get_current_data(self) -> Optional[np.ndarray]:
        """Get current/production data."""
        try:
            events = self.storage.load_events(
                event_type="processed",
                limit=1000,
                start_time=datetime.utcnow() - timedelta(hours=24)  # Recent data
            )
            
            if events:
                from src.ml.inference import FeatureExtractor
                feature_extractor = FeatureExtractor(self.config)
                
                features_list = []
                for event in events:
                    features = feature_extractor.extract(event)
                    features_list.append(features)
                
                df = pd.DataFrame(features_list).fillna(0)
                return df.values
            
        except Exception as e:
            self.logger.error(f"Error loading current data: {e}", exc_info=True)
        
        return None

    async def _extract_features(self, events: List[Dict[str, Any]]) -> Optional[np.ndarray]:
        """Extract features from events."""
        try:
            from src.ml.inference import FeatureExtractor
            feature_extractor = FeatureExtractor(self.config)
            
            features_list = []
            for event in events:
                features = feature_extractor.extract(event)
                features_list.append(features)
            
            df = pd.DataFrame(features_list).fillna(0)
            return df.values
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}", exc_info=True)
            return None

    async def _check_data_drift(self, reference_data: np.ndarray, current_data: np.ndarray) -> Dict[str, Any]:
        """Check for data/feature drift."""
        results = {
            "drift_detected": False,
            "features": [],
            "statistical_tests": {},
        }

        try:
            # Check each feature
            n_features = reference_data.shape[1]
            drifted_features = []

            for i in range(min(n_features, reference_data.shape[1], current_data.shape[1])):
                ref_feature = reference_data[:, i]
                curr_feature = current_data[:, i]

                # Skip if all values are zero or constant
                if np.std(ref_feature) == 0 or np.std(curr_feature) == 0:
                    continue

                # Kolmogorov-Smirnov test for distribution change
                ks_statistic, ks_pvalue = stats.ks_2samp(ref_feature, curr_feature)

                # Wasserstein distance (Earth Mover's Distance)
                wasserstein_distance = stats.wasserstein_distance(ref_feature, curr_feature)

                # Check if drift is significant
                threshold = self.drift_config.get("threshold", 0.05)
                is_drifted = ks_pvalue < threshold

                feature_result = {
                    "feature_index": i,
                    "ks_statistic": float(ks_statistic),
                    "ks_pvalue": float(ks_pvalue),
                    "wasserstein_distance": float(wasserstein_distance),
                    "is_drifted": is_drifted,
                }

                results["features"].append(feature_result)

                if is_drifted:
                    drifted_features.append(i)

            # Update overall result
            drift_ratio = len(drifted_features) / n_features if n_features > 0 else 0
            results["drift_detected"] = drift_ratio > 0.1  # More than 10% features drifted
            results["drift_ratio"] = float(drift_ratio)
            results["drifted_features_count"] = len(drifted_features)

            # Statistical tests summary
            results["statistical_tests"] = {
                "ks_test_threshold": threshold,
                "total_features": n_features,
                "features_checked": len(results["features"]),
            }

        except Exception as e:
            self.logger.error(f"Error checking data drift: {e}", exc_info=True)
            results["error"] = str(e)

        return results

    async def _check_concept_drift(self, reference_data: np.ndarray, current_data: np.ndarray) -> Dict[str, Any]:
        """Check for concept drift (changes in relationships)."""
        results = {
            "drift_detected": False,
            "methods": {},
        }

        try:
            # Method 1: Compare covariance matrices
            ref_cov = np.cov(reference_data.T)
            curr_cov = np.cov(current_data.T)
            
            # Calculate Frobenius norm difference
            cov_diff = np.linalg.norm(ref_cov - curr_cov, 'fro')
            cov_norm = np.linalg.norm(ref_cov, 'fro')
            cov_change = cov_diff / cov_norm if cov_norm > 0 else 0

            # Method 2: Compare correlation matrices
            ref_corr = np.corrcoef(reference_data.T)
            curr_corr = np.corrcoef(current_data.T)
            
            # Handle NaN in correlation matrices
            ref_corr = np.nan_to_num(ref_corr)
            curr_corr = np.nan_to_num(curr_corr)
            
            corr_diff = np.linalg.norm(ref_corr - curr_corr, 'fro')
            corr_norm = np.linalg.norm(ref_corr, 'fro')
            corr_change = corr_diff / corr_norm if corr_norm > 0 else 0

            # Determine if drift is detected
            threshold = self.drift_config.get("threshold", 0.05)
            cov_drifted = cov_change > threshold
            corr_drifted = corr_change > threshold
            
            results["drift_detected"] = cov_drifted or corr_drifted
            results["methods"] = {
                "covariance_change": {
                    "value": float(cov_change),
                    "threshold": threshold,
                    "drift_detected": cov_drifted,
                },
                "correlation_change": {
                    "value": float(corr_change),
                    "threshold": threshold,
                    "drift_detected": corr_drifted,
                },
            }

        except Exception as e:
            self.logger.error(f"Error checking concept drift: {e}", exc_info=True)
            results["error"] = str(e)

        return results

    async def _check_performance_drift(self) -> Dict[str, Any]:
        """Check for performance drift (model accuracy degradation)."""
        results = {
            "drift_detected": False,
            "metrics": {},
        }

        try:
            # This would typically compare model performance metrics over time
            # For now, we'll use a simplified approach
            
            # Load recent anomaly detection results
            recent_alerts = self.storage.load_alerts(
                start_time=datetime.utcnow() - timedelta(hours=24),
                limit=1000
            )
            
            if recent_alerts:
                # Calculate anomaly rate
                total_alerts = len(recent_alerts)
                high_severity = sum(1 for a in recent_alerts if a.get("severity") in ["high", "critical"])
                
                anomaly_rate = total_alerts / 1000 if total_alerts > 0 else 0  # Assuming 1000 events
                high_severity_rate = high_severity / total_alerts if total_alerts > 0 else 0
                
                # Check for significant changes
                # In production, compare with historical baselines
                baseline_rate = 0.05  # 5% anomaly rate baseline
                baseline_high_rate = 0.01  # 1% high severity baseline
                
                rate_change = abs(anomaly_rate - baseline_rate) / baseline_rate if baseline_rate > 0 else 0
                high_rate_change = abs(high_severity_rate - baseline_high_rate) / baseline_high_rate if baseline_high_rate > 0 else 0
                
                threshold = 0.5  # 50% change threshold
                performance_drifted = rate_change > threshold or high_rate_change > threshold
                
                results["drift_detected"] = performance_drifted
                results["metrics"] = {
                    "anomaly_rate": float(anomaly_rate),
                    "high_severity_rate": float(high_severity_rate),
                    "rate_change": float(rate_change),
                    "high_rate_change": float(high_rate_change),
                    "threshold": threshold,
                    "baseline_rate": baseline_rate,
                    "baseline_high_rate": baseline_high_rate,
                }

        except Exception as e:
            self.logger.error(f"Error checking performance drift: {e}", exc_info=True)
            results["error"] = str(e)

        return results

    def _determine_overall_drift(self, drift_results: Dict[str, Any]) -> Dict[str, Any]:
        """Determine overall drift status from individual checks."""
        data_drift = drift_results.get("data_drift", {}).get("drift_detected", False)
        concept_drift = drift_results.get("concept_drift", {}).get("drift_detected", False)
        performance_drift = drift_results.get("performance_drift", {}).get("drift_detected", False)

        # Calculate severity
        if performance_drift:
            severity = "critical"
        elif concept_drift:
            severity = "high"
        elif data_drift:
            severity = "medium"
        else:
            severity = "low"

        return {
            "drift_detected": data_drift or concept_drift or performance_drift,
            "severity": severity,
            "data_drift": data_drift,
            "concept_drift": concept_drift,
            "performance_drift": performance_drift,
            "recommendation": self._get_recommendation(severity),
        }

    def _get_recommendation(self, severity: str) -> str:
        """Get recommendation based on drift severity."""
        recommendations = {
            "critical": "Immediate model retraining required. Performance degradation detected.",
            "high": "Schedule model retraining soon. Significant concept drift detected.",
            "medium": "Monitor closely. Consider retraining if drift persists.",
            "low": "No action required. Minor data drift detected.",
        }
        return recommendations.get(severity, "No recommendation available.")

    async def get_drift_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get drift detection history."""
        return self.drift_history[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get drift monitor statistics."""
        return {
            **self.stats,
            "drift_history_size": len(self.drift_history),
            "config": {
                "window_size": self.drift_config.get("window_size", 10000),
                "threshold": self.drift_config.get("threshold", 0.05),
                "check_interval": self.drift_config.get("check_interval", 3600),
            },
        }

    async def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive drift report."""
        recent_drift = await self.check_drift()
        
        report = {
            "summary": {
                "timestamp": datetime.utcnow().isoformat(),
                "overall_status": recent_drift.get("overall_drift", {}).get("severity", "unknown"),
                "drift_detected": recent_drift.get("overall_drift", {}).get("drift_detected", False),
            },
            "detailed_results": recent_drift,
            "history_summary": {
                "total_checks": self.stats["drift_checks"],
                "drifts_detected": self.stats["drifts_detected"],
                "recent_drifts": len([d for d in self.drift_history[-10:] 
                                     if d.get("overall_drift", {}).get("drift_detected", False)]),
            },
            "recommendations": recent_drift.get("overall_drift", {}).get("recommendation", ""),
        }
        
        return report