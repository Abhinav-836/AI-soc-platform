"""
Autoencoder for anomaly detection (Optional - requires TensorFlow).
"""

import numpy as np
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path

from src.core.logger import LoggerMixin

# Lazy load TensorFlow - only when needed
_TENSORFLOW_AVAILABLE = None


def _is_tensorflow_available():
    """Check if TensorFlow is available (lazy check)."""
    global _TENSORFLOW_AVAILABLE
    if _TENSORFLOW_AVAILABLE is None:
        try:
            import tensorflow as tf
            _TENSORFLOW_AVAILABLE = True
        except ImportError:
            _TENSORFLOW_AVAILABLE = False
        except Exception as e:
            print(f"TensorFlow import error: {e}")
            _TENSORFLOW_AVAILABLE = False
    return _TENSORFLOW_AVAILABLE


class AutoencoderAnomalyDetector(LoggerMixin):
    """Autoencoder-based anomaly detector (optional - requires TensorFlow)."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.feature_names: List[str] = []
        self.is_trained = False
        self.train_error_mean = 0.0
        self.train_error_std = 1.0

        # Model parameters
        model_config = config.get("models", {}).get("anomaly", {}).get("autoencoder", {})
        self.encoding_dim = model_config.get("encoding_dim", 32)
        self.epochs = model_config.get("epochs", 50)
        self.batch_size = model_config.get("batch_size", 32)
        self.validation_split = model_config.get("validation_split", 0.2)
        self.patience = model_config.get("patience", 10)

        # Inference parameters
        inference_config = config.get("inference", {})
        self.anomaly_threshold = inference_config.get("anomaly_threshold", 0.95)

        # Training history
        self.training_history: Dict[str, List[float]] = {}

        # Warn if TensorFlow not available
        if not _is_tensorflow_available():
            self.logger.warning(
                "TensorFlow not available. AutoencoderAnomalyDetector will be disabled. "
                "Install with: pip install tensorflow-cpu"
            )

    def _get_tf(self):
        """Get TensorFlow module (lazy import)."""
        import tensorflow as tf
        return tf

    def build_model(self, input_dim: int):
        """Build autoencoder model."""
        if not _is_tensorflow_available():
            self.logger.error("Cannot build model: TensorFlow not available")
            return

        tf = self._get_tf()
        
        # Encoder
        encoder_input = tf.keras.Input(shape=(input_dim,))
        encoded = tf.keras.layers.Dense(self.encoding_dim * 2, activation='relu')(encoder_input)
        encoded = tf.keras.layers.Dense(self.encoding_dim, activation='relu')(encoded)

        # Decoder
        decoded = tf.keras.layers.Dense(self.encoding_dim * 2, activation='relu')(encoded)
        decoded = tf.keras.layers.Dense(input_dim, activation='sigmoid')(decoded)

        # Autoencoder
        self.model = tf.keras.Model(encoder_input, decoded)

        # Compile model
        self.model.compile(
            optimizer='adam',
            loss='mse',
            metrics=['mae']
        )

        self.logger.info(f"Built autoencoder model with input_dim={input_dim}, encoding_dim={self.encoding_dim}")

    def train(self, X: np.ndarray, feature_names: List[str]):
        """Train the autoencoder model."""
        if not _is_tensorflow_available():
            self.logger.error("Cannot train: TensorFlow not available")
            return

        tf = self._get_tf()
        
        self.logger.info(f"Training autoencoder with {len(X)} samples")

        # Store feature names
        self.feature_names = feature_names

        # Scale features to [0, 1]
        from sklearn.preprocessing import MinMaxScaler
        self.scaler = MinMaxScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Build model if not already built
        if self.model is None:
            self.build_model(X.shape[1])

        if self.model is None:
            self.logger.error("Failed to build model")
            return

        # Callbacks
        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=self.patience,
                restore_best_weights=True
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=self.patience // 2,
                min_lr=1e-6
            ),
        ]

        # Train model
        try:
            history = self.model.fit(
                X_scaled, X_scaled,
                epochs=self.epochs,
                batch_size=self.batch_size,
                validation_split=self.validation_split,
                callbacks=callbacks,
                verbose=1
            )

            # Store training history
            self.training_history = {
                'loss': history.history['loss'],
                'val_loss': history.history['val_loss'],
                'mae': history.history['mae'],
                'val_mae': history.history['val_mae'],
            }

            # Calculate reconstruction errors on training data
            train_predictions = self.model.predict(X_scaled, verbose=0)
            train_errors = np.mean(np.square(X_scaled - train_predictions), axis=1)
            
            self.train_error_mean = np.mean(train_errors)
            self.train_error_std = np.std(train_errors)
            self.is_trained = True

            self.logger.info(
                f"Training complete. Final loss: {history.history['loss'][-1]:.4f}, "
                f"val_loss: {history.history['val_loss'][-1]:.4f}"
            )
            self.logger.info(
                f"Reconstruction error - mean: {self.train_error_mean:.4f}, "
                f"std: {self.train_error_std:.4f}"
            )
        except Exception as e:
            self.logger.error(f"Error during training: {e}", exc_info=True)
            self.is_trained = False

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies."""
        if not _is_tensorflow_available():
            raise RuntimeError("TensorFlow not available")

        if not self.is_trained or self.model is None or self.scaler is None:
            raise RuntimeError("Model not trained")

        # Scale features
        X_scaled = self.scaler.transform(X)

        # Get reconstructions
        reconstructions = self.model.predict(X_scaled, verbose=0)

        # Calculate reconstruction errors
        reconstruction_errors = np.mean(np.square(X_scaled - reconstructions), axis=1)

        # Convert to anomaly scores (0-1, higher = more anomalous)
        anomaly_scores = self._calculate_anomaly_score(reconstruction_errors)

        # Predict anomalies based on threshold
        predictions = np.where(anomaly_scores >= self.anomaly_threshold, 1, 0)

        return predictions, anomaly_scores

    def _calculate_anomaly_score(self, reconstruction_errors: np.ndarray) -> np.ndarray:
        """Convert reconstruction errors to anomaly scores (0-1)."""
        # Avoid division by zero
        std = max(self.train_error_std, 1e-6)
        
        # Calculate probability using Gaussian assumption
        scores = 1 - np.exp(-(reconstruction_errors - self.train_error_mean)**2 / (2 * std**2))
        
        # Clip to [0, 1]
        scores = np.clip(scores, 0, 1)
        
        return scores

    def detect(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Detect anomaly for single sample."""
        if not _is_tensorflow_available():
            return {
                "anomaly": False,
                "score": 0.0,
                "confidence": 0.0,
                "error": "TensorFlow not available - autoencoder disabled",
            }

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

            is_anomaly = bool(predictions[0] == 1)
            score = float(scores[0])

            # Calculate confidence
            confidence = self._calculate_confidence(score)

            return {
                "anomaly": is_anomaly,
                "score": score,
                "confidence": confidence,
                "features": features,
                "reconstruction_error": float(score * self.train_error_std + self.train_error_mean),
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
        if score >= 0.95:
            return 0.9
        elif score >= 0.8:
            return 0.7
        elif score >= 0.6:
            return 0.5
        else:
            return 0.3

    def save(self, path: str):
        """Save model to disk."""
        if not _is_tensorflow_available():
            self.logger.error("Cannot save: TensorFlow not available")
            return

        if not self.is_trained or self.model is None:
            self.logger.error("Cannot save untrained model")
            return

        import joblib
        
        # Save TensorFlow model
        model_path = Path(path)
        self.model.save(str(model_path.with_suffix('')))

        # Save scaler and metadata
        metadata = {
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "train_error_mean": self.train_error_mean,
            "train_error_std": self.train_error_std,
            "training_history": self.training_history,
            "config": self.config,
        }

        metadata_path = str(model_path.with_suffix('.metadata.pkl'))
        joblib.dump(metadata, metadata_path)

        self.logger.info(f"Model saved to {path}")

    def load(self, path: str):
        """Load model from disk."""
        if not _is_tensorflow_available():
            self.logger.error("Cannot load: TensorFlow not available")
            return

        import joblib
        
        try:
            # Load TensorFlow model
            model_path = Path(path)
            tf = self._get_tf()
            self.model = tf.keras.models.load_model(str(model_path.with_suffix('')))

            # Load metadata
            metadata_path = str(model_path.with_suffix('.metadata.pkl'))
            metadata = joblib.load(metadata_path)

            self.scaler = metadata["scaler"]
            self.feature_names = metadata["feature_names"]
            self.train_error_mean = metadata.get("train_error_mean", 0)
            self.train_error_std = metadata.get("train_error_std", 1)
            self.training_history = metadata.get("training_history", {})
            self.is_trained = True

            self.logger.info(f"Model loaded from {path}")
            self.logger.info(f"Features: {len(self.feature_names)}")
        except Exception as e:
            self.logger.error(f"Error loading model: {e}", exc_info=True)
            self.is_trained = False

    def get_stats(self) -> Dict[str, Any]:
        """Get model statistics."""
        stats = {
            "is_trained": self.is_trained,
            "tensorflow_available": _is_tensorflow_available(),
            "feature_count": len(self.feature_names),
            "encoding_dim": self.encoding_dim,
            "train_error_mean": self.train_error_mean,
            "train_error_std": self.train_error_std,
            "anomaly_threshold": self.anomaly_threshold,
        }

        if self.training_history:
            stats["training_history"] = {
                "final_loss": self.training_history.get("loss", [0])[-1],
                "final_val_loss": self.training_history.get("val_loss", [0])[-1],
                "epochs_trained": len(self.training_history.get("loss", [])),
            }

        return stats

    def get_reconstruction_importance(self, features: Dict[str, float]) -> Dict[str, float]:
        """Get feature importance based on reconstruction error."""
        if not _is_tensorflow_available():
            return {}

        if not self.is_trained or self.model is None:
            return {}

        try:
            # Convert features to array
            X = np.array([[features.get(f, 0.0) for f in self.feature_names]])
            X_scaled = self.scaler.transform(X)

            # Get reconstruction
            reconstruction = self.model.predict(X_scaled, verbose=0)

            # Calculate per-feature reconstruction error
            errors = np.abs(X_scaled - reconstruction).flatten()

            # Map to feature names
            importance = {
                feature: float(error)
                for feature, error in zip(self.feature_names, errors)
            }

            return importance

        except Exception as e:
            self.logger.error(f"Error calculating reconstruction importance: {e}", exc_info=True)
            return {}