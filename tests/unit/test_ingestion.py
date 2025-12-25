import pytest
import json
from src.ingestion.parsers.json_parser import JSONParser
from src.ingestion.parsers.normalizer import LogNormalizer

def test_json_parser():
    """Test JSON log parsing."""
    parser = JSONParser()
    
    # Valid JSON
    log_str = '{"timestamp": "2024-12-16T10:00:00Z", "source_ip": "192.168.1.1"}'
    result = parser.parse(log_str)
    
    assert "timestamp" in result
    assert result["source_ip"] == "192.168.1.1"
    
    # Invalid JSON
    invalid_log = "not json"
    result = parser.parse(invalid_log)
    assert result["parse_error"] == True

def test_log_normalizer():
    """Test log normalization."""
    normalizer = LogNormalizer()
    
    # Test field mapping
    log = {
        "src": "192.168.1.1",
        "dst": "10.0.0.1",
        "sport": 12345,
        "dport": 80
    }
    
    normalized = normalizer.normalize(log)
    
    assert normalized["source_ip"] == "192.168.1.1"
    assert normalized["destination_ip"] == "10.0.0.1"
    assert normalized["source_port"] == 12345
    assert normalized["destination_port"] == 80
    assert "normalized_at" in normalized
    assert "log_id" in normalized