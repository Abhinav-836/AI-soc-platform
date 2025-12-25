import pytest
from src.detection.rules.custom_rules import BruteForceRule, PortScanRule
from src.detection.scoring import ThreatScorer

def test_brute_force_rule(brute_force_events):
    """Test brute force detection rule."""
    rule = BruteForceRule(threshold=5, time_window=300)
    
    # First 4 attempts should not trigger
    for i in range(4):
        assert not rule.matches(brute_force_events[i])
    
    # 5th attempt should trigger
    assert rule.matches(brute_force_events[4])

def test_port_scan_rule():
    """Test port scan detection."""
    rule = PortScanRule(threshold=20, time_window=60)
    
    # Simulate scanning 25 ports
    for port in range(1, 26):
        event = {
            "event_type": "connection_attempt",
            "source_ip": "192.168.1.1",
            "dest_port": port
        }
        
        if port < 20:
            assert not rule.matches(event)
        else:
            assert rule.matches(event)

def test_threat_scorer(config):
    """Test threat scoring."""
    scorer = ThreatScorer(config["detection"]["scoring"]["weights"])
    
    # Test critical event
    critical_event = {
        "severity": "CRITICAL",
        "confidence": 0.9,
        "frequency": 5,
        "source_reputation": 0.1
    }
    
    score = scorer.calculate_score(critical_event)
    assert score >= 70  # Should be high severity
    assert scorer.get_severity_level(score) in ["CRITICAL", "HIGH"]
    
    # Test low severity event
    low_event = {
        "severity": "INFO",
        "confidence": 0.5,
        "frequency": 1,
        "source_reputation": 0.9
    }
    
    score = scorer.calculate_score(low_event)
    assert score < 50