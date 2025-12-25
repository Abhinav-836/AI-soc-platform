"""
ML model training pipeline.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path

from src.utils.logger import LoggerMixin
from src.ml.anomaly.isolation_forest import IsolationForestAnomalyDetector
from src.ml.anomaly.autoencoder import AutoencoderAnomalyDetector
from src.storage.local_store import LocalStorage


class ModelTrainer(LoggerMixin):
    """Trains and manages ML models."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.storage = LocalStorage(config)
        self.models: Dict[str, Any] = {}
        self.training_data: Dict[str, np.ndarray] = {}
        self.feature_names: List[str] = []
        self.stats = {
            "training_sessions": 0,
            "models_trained": 0,
            "training_errors": 0,
            "last_training": None,
        }

    async def train_all_models(self, force_retrain: bool = False):
        """Train all configured models."""
        self.logger.info("Starting model training pipeline...")

        # Check if retraining is needed
        if not force_retrain and not self._should_retrain():
            self.logger.info("Skipping training - models are up to date")
            return

        try:
            # Load training data
            await self._load_training_data()

            if len(self.training_data) == 0:
                self.logger.warning("No training data available")
                return

            # Train each model
            ml_config = self.config.get("ml", {})

            # Train Isolation Forest
            if ml_config.get("models", {}).get("anomaly", {}).get("isolation_forest", {}).get("enabled", False):
                await self._train_isolation_forest()

            # Train Autoencoder
            if ml_config.get("models", {}).get("anomaly", {}).get("autoencoder", {}).get("enabled", False):
                await self._train_autoencoder()

            # Save models
            await self._save_models()

            # Update statistics
            self.stats["training_sessions"] += 1
            self.stats["models_trained"] = len(self.models)
            self.stats["last_training"] = datetime.utcnow().isoformat()

            self.logger.info(f"Model training complete. Trained {len(self.models)} models")

        except Exception as e:
            self.logger.error(f"Error in model training: {e}", exc_info=True)
            self.stats["training_errors"] += 1

    async def _load_training_data(self):
        """Load and prepare training data."""
        self.logger.info("Loading training data...")

        # Load events from storage
        events = self.storage.load_events(
            event_type="processed",
            limit=10000  # Limit for training
        )

        if not events:
            self.logger.warning("No events found for training")
            return

        # Extract features
        from src.ml.inference import FeatureExtractor
        feature_extractor = FeatureExtractor(self.config)

        features_list = []
        for event in events:
            features = feature_extractor.extract(event)
            features_list.append(features)

        # Convert to DataFrame
        df = pd.DataFrame(features_list)

        # Handle missing values
        df = df.fillna(0)

        # Store feature names
        self.feature_names = df.columns.tolist()

        # Convert to numpy array
        X = df.values

        # Store training data
        self.training_data["X"] = X

        self.logger.info(f"Loaded {len(events)} events with {len(self.feature_names)} features")

    async def _train_isolation_forest(self):
        """Train Isolation Forest model."""
        self.logger.info("Training Isolation Forest...")

        X = self.training_data.get("X")
        if X is None or len(X) == 0:
            self.logger.warning("No training data for Isolation Forest")
            return

        # Create and train model
        model = IsolationForestAnomalyDetector(self.config)
        model.train(X, self.feature_names)

        # Store model
        self.models["isolation_forest"] = model

        # Evaluate model
        predictions, scores = model.predict(X)
        anomaly_rate = np.mean(predictions == -1)

        self.logger.info(f"Isolation Forest trained. Anomaly rate: {anomaly_rate:.2%}")

    async def _train_autoencoder(self):
        """Train Autoencoder model."""
        self.logger.info("Training Autoencoder...")

        X = self.training_data.get("X")
        if X is None or len(X) == 0:
            self.logger.warning("No training data for Autoencoder")
            return

        # Check if we have enough data
        if len(X) < 100:
            self.logger.warning(f"Insufficient data for Autoencoder: {len(X)} samples")
            return

        # Create and train model
        model = AutoencoderAnomalyDetector(self.config)
        model.train(X, self.feature_names)

        # Store model
        self.models["autoencoder"] = model

        # Evaluate model
        predictions, scores = model.predict(X)
        anomaly_rate = np.mean(predictions == 1)

        self.logger.info(f"Autoencoder trained. Anomaly rate: {anomaly_rate:.2%}")

    async def _save_models(self):
        """Save trained models to storage."""
        for model_name, model in self.models.items():
            try:
                # Save to storage
                model_path = self.config.get("storage", {}).get("model_path", "./data/models")
                Path(model_path).mkdir(parents=True, exist_ok=True)

                if model_name == "isolation_forest":
                    file_path = f"{model_path}/isolation_forest.pkl"
                    model.save(file_path)
                elif model_name == "autoencoder":
                    file_path = f"{model_path}/autoencoder.h5"
                    model.save(file_path)

                self.logger.info(f"Saved {model_name} model to {file_path}")

            except Exception as e:
                self.logger.error(f"Error saving {model_name} model: {e}", exc_info=True)

    def _should_retrain(self) -> bool:
        """Check if models should be retrained."""
        training_config = self.config.get("ml", {}).get("training", {})
        retrain_interval = training_config.get("retrain_interval", 86400)  # 24 hours

        if not self.stats.get("last_training"):
            return True

        try:
            last_training = datetime.fromisoformat(self.stats["last_training"].replace("Z", "+00:00"))
            now = datetime.utcnow()
            time_since_training = (now - last_training).total_seconds()

            return time_since_training >= retrain_interval

        except (ValueError, KeyError):
            return True

    async def evaluate_models(self, test_data: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Evaluate model performance."""
        if test_data is None:
            # Use training data for evaluation (not ideal, but works for demo)
            test_data = self.training_data.get("X")
            if test_data is None:
                return {"error": "No test data available"}

        results = {}

        for model_name, model in self.models.items():
            try:
                if hasattr(model, 'predict'):
                    predictions, scores = model.predict(test_data)

                    # Calculate metrics
                    if model_name == "isolation_forest":
                        anomaly_rate = np.mean(predictions == -1)
                    elif model_name == "autoencoder":
                        anomaly_rate = np.mean(predictions == 1)
                    else:
                        anomaly_rate = 0.0

                    results[model_name] = {
                        "anomaly_rate": float(anomaly_rate),
                        "mean_score": float(np.mean(scores)),
                        "std_score": float(np.std(scores)),
                        "sample_size": len(test_data),
                        "timestamp": datetime.utcnow().isoformat(),
                    }

            except Exception as e:
                self.logger.error(f"Error evaluating {model_name}: {e}", exc_info=True)
                results[model_name] = {
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }

        return results

    async def cross_validate(self, n_folds: int = 5) -> Dict[str, Any]:
        """Perform cross-validation on models."""
        X = self.training_data.get("X")
        if X is None or len(X) < n_folds * 10:
            return {"error": "Insufficient data for cross-validation"}

        from sklearn.model_selection import KFold

        results = {}
        kfold = KFold(n_splits=n_folds, shuffle=True, random_state=42)

        for model_name in self.models.keys():
            fold_results = []

            for fold, (train_idx, val_idx) in enumerate(kfold.split(X)):
                try:
                    X_train, X_val = X[train_idx], X[val_idx]

                    # Train model on fold
                    if model_name == "isolation_forest":
                        model = IsolationForestAnomalyDetector(self.config)
                        model.train(X_train, self.feature_names)
                        predictions, scores = model.predict(X_val)
                        anomaly_rate = np.mean(predictions == -1)

                    elif model_name == "autoencoder":
                        model = AutoencoderAnomalyDetector(self.config)
                        model.train(X_train, self.feature_names)
                        predictions, scores = model.predict(X_val)
                        anomaly_rate = np.mean(predictions == 1)

                    else:
                        continue

                    fold_results.append({
                        "fold": fold,
                        "anomaly_rate": float(anomaly_rate),
                        "mean_score": float(np.mean(scores)),
                        "val_size": len(X_val),
                    })

                except Exception as e:
                    self.logger.error(f"Error in fold {fold} for {model_name}: {e}", exc_info=True)
                    fold_results.append({
                        "fold": fold,
                        "error": str(e),
                    })

            # Calculate aggregate statistics
            if fold_results and "error" not in fold_results[0]:
                anomaly_rates = [r["anomaly_rate"] for r in fold_results if "anomaly_rate" in r]
                mean_scores = [r["mean_score"] for r in fold_results if "mean_score" in r]

                results[model_name] = {
                    "mean_anomaly_rate": float(np.mean(anomaly_rates)),
                    "std_anomaly_rate": float(np.std(anomaly_rates)),
                    "mean_score": float(np.mean(mean_scores)),
                    "std_score": float(np.std(mean_scores)),
                    "folds": fold_results,
                    "timestamp": datetime.utcnow().isoformat(),
                }

        return results

    def get_training_stats(self) -> Dict[str, Any]:
        """Get training statistics."""
        return {
            **self.stats,
            "models_available": list(self.models.keys()),
            "feature_count": len(self.feature_names),
            "training_data_size": self.training_data.get("X", np.array([])).shape[0] if "X" in self.training_data else 0,
        }