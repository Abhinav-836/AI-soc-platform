import pytest
from src.ml.anomaly.isolation_forest import AnomalyDetector
import numpy as np

def test_anomaly_detector_training():
    """Test anomaly detector training."""
    detector = AnomalyDetector(contamination=0.1, n_estimators=50)
    
    # Generate training data
    training_events = []
    for i in range(100):
        event = {
            "source_ip": f"192.168.1.{i % 50}",
            "dest_ip": "10.0.0.1",
            "source_port": 5000 + i,
            "dest_port": 80,
            "bytes_transferred": 1000 + i * 10,
            "packet_count": 10 + i,
            "duration": 60 + i,
            "protocol": "tcp"
        }
        training_events.append(event)
    
    # Train
    detector.train(training_events)
    assert detector.is_trained
    
    # Test prediction on normal event
    normal_event = {
        "source_ip": "192.168.1.10",
        "dest_ip": "10.0.0.1",
        "source_port": 5050,
        "dest_port": 80,
        "bytes_transferred": 1500,
        "packet_count": 50,
        "duration": 100,
        "protocol": "tcp"
    }
    
    result = detector.predict(normal_event)
    assert "is_anomaly" in result
    assert "anomaly_score" in result

def test_feature_extraction():
    """Test feature extraction from events."""
    detector = AnomalyDetector()
    
    event = {
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "source_port": 54321,
        "dest_port": 80,
        "bytes_transferred": 5000,
        "packet_count": 50,
        "duration": 120,
        "protocol": "tcp"
    }
    
    features = detector.extract_features(event)
    assert features.shape == (1, 8)
    assert np.all(np.isfinite(features))