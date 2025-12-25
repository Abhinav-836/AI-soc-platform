"""
Isolation Forest for anomaly detection.
"""

import numpy as np
import joblib
from typing import Dict, List, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.utils.logger import LoggerMixin


class IsolationForestAnomalyDetector(LoggerMixin):
    """Isolation Forest based anomaly detector."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self.is_trained = False

        # Model parameters
        model_config = config.get("models", {}).get("anomaly", {}).get("isolation_forest", {})
        self.n_estimators = model_config.get("n_estimators", 100)
        self.contamination = model_config.get("contamination", 0.01)
        self.max_features = model_config.get("max_features", 1.0)
        self.bootstrap = model_config.get("bootstrap", False)
        self.random_state = model_config.get("random_state", 42)

        # Inference parameters
        inference_config = config.get("inference", {})
        self.anomaly_threshold = inference_config.get("anomaly_threshold", 0.95)

    def train(self, X: np.ndarray, feature_names: List[str]):
        """
        Train the Isolation Forest model.

        Args:
            X: Training data (n_samples, n_features)
            feature_names: Names of features
        """
        self.logger.info(f"Training Isolation Forest with {len(X)} samples")

        # Store feature names
        self.feature_names = feature_names

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train model
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_features=self.max_features,
            bootstrap=self.bootstrap,
            random_state=self.random_state,
            n_jobs=-1,
        )

        self.model.fit(X_scaled)
        self.is_trained = True

        # Calculate training stats
        train_scores = self.model.score_samples(X_scaled)
        self.train_score_mean = np.mean(train_scores)
        self.train_score_std = np.std(train_scores)

        self.logger.info(
            f"Training complete. Score mean: {self.train_score_mean:.3f}, "
            f"std: {self.train_score_std:.3f}"
        )

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies.

        Args:
            X: Input data (n_samples, n_features)

        Returns:
            Tuple of (predictions, anomaly_scores)
                predictions: 1 for normal, -1 for anomaly
                anomaly_scores: Higher means more anomalous
        """
        if not self.is_trained or self.model is None or self.scaler is None:
            raise RuntimeError("Model not trained")

        # Scale features
        X_scaled = self.scaler.transform(X)

        # Get anomaly scores (negative scores, more negative = more anomalous)
        scores = self.model.score_samples(X_scaled)

        # Convert to anomaly scores (0-1, higher = more anomalous)
        anomaly_scores = self._convert_to_anomaly_score(scores)

        # Predict anomalies based on threshold
        predictions = np.where(anomaly_scores >= self.anomaly_threshold, -1, 1)

        return predictions, anomaly_scores

    def _convert_to_anomaly_score(self, isolation_scores: np.ndarray) -> np.ndarray:
        """Convert isolation forest scores to anomaly scores (0-1)."""
        # Normalize scores to 0-1 range
        min_score = np.min(isolation_scores)
        max_score = np.max(isolation_scores)

        if max_score == min_score:
            return np.zeros_like(isolation_scores)

        normalized = (isolation_scores - min_score) / (max_score - min_score)

        # Invert so higher = more anomalous
        anomaly_scores = 1 - normalized

        return anomaly_scores

    def detect(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Detect anomaly for single sample.

        Args:
            features: Dictionary of feature names to values

        Returns:
            Detection results
        """
        if not self.is_trained:
            return {
                "anomaly": False,
                "score": 0.0,
                "confidence": 0.0,
                "error": "Model not trained",
            }

        try:
            # Convert features to array in correct order
            X = np.array([[features.get(f, 0.0) for f in self.feature_names]])

            # Predict
            predictions, scores = self.predict(X)

            is_anomaly = predictions[0] == -1
            score = float(scores[0])

            # Calculate confidence
            confidence = self._calculate_confidence(score)

            return {
                "anomaly": bool(is_anomaly),
                "score": score,
                "confidence": confidence,
                "features": features,
                "feature_importance": self._get_feature_importance(features, score),
            }

        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}", exc_info=True)
            return {
                "anomaly": False,
                "score": 0.0,
                "confidence": 0.0,
                "error": str(e),
            }

    def _calculate_confidence(self, score: float) -> float:
        """Calculate confidence based on anomaly score."""
        # Higher scores get higher confidence
        if score >= 0.95:
            return 0.9
        elif score >= 0.8:
            return 0.7
        elif score >= 0.6:
            return 0.5
        else:
            return 0.3

    def _get_feature_importance(
        self, features: Dict[str, float], anomaly_score: float
    ) -> Dict[str, float]:
        """Estimate feature importance for anomaly detection."""
        # Simple implementation: features far from 0 contribute more
        importance = {}
        for name, value in features.items():
            # Normalized absolute value as importance
            norm_value = abs(value)
            if norm_value > 1:
                importance[name] = min(norm_value / 10.0, 1.0)
            else:
                importance[name] = norm_value

        # Scale by anomaly score
        if anomaly_score > 0:
            for name in importance:
                importance[name] *= anomaly_score

        return importance

    def save(self, path: str):
        """Save model to disk."""
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained model")

        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "train_score_mean": self.train_score_mean,
            "train_score_std": self.train_score_std,
            "config": self.config,
        }

        joblib.dump(model_data, path)
        self.logger.info(f"Model saved to {path}")

    def load(self, path: str):
        """Load model from disk."""
        model_data = joblib.load(path)

        self.model = model_data["model"]
        self.scaler = model_data["scaler"]
        self.feature_names = model_data["feature_names"]
        self.train_score_mean = model_data.get("train_score_mean", 0)
        self.train_score_std = model_data.get("train_score_std", 1)
        self.is_trained = True

        self.logger.info(f"Model loaded from {path}")
        self.logger.info(f"Features: {len(self.feature_names)}")

    def get_stats(self) -> Dict[str, Any]:
        """Get model statistics."""
        return {
            "is_trained": self.is_trained,
            "feature_count": len(self.feature_names),
            "features": self.feature_names,
            "train_score_mean": getattr(self, "train_score_mean", 0),
            "train_score_std": getattr(self, "train_score_std", 1),
            "parameters": {
                "n_estimators": self.n_estimators,
                "contamination": self.contamination,
                "max_features": self.max_features,
                "anomaly_threshold": self.anomaly_threshold,
            },
        }