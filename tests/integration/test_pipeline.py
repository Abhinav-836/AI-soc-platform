import pytest
from src.ingestion.pipeline import IngestionPipeline
from src.detection.detector import ThreatDetector
from src.storage.elastic import ElasticStorage
from unittest.mock import Mock

def test_full_pipeline(sample_log_event, config):
    """Test complete processing pipeline."""
    # Mock storage
    storage = Mock(spec=ElasticStorage)
    
    # Create pipeline
    pipeline = IngestionPipeline(storage)
    detector = ThreatDetector(config["detection"])
    
    # Process event
    import json
    raw_log = json.dumps(sample_log_event)
    processed = pipeline.process_log(raw_log)
    
    # Verify processing
    assert "log_id" in processed
    assert "normalized_at" in processed
    
    # Run detection
    alerts = detector.analyze_event(processed)
    
    # Should not alert on normal traffic
    assert len(alerts) == 0