from datetime import timedelta

import pytest

from conftest import feed
from src.core.time_utils import iso, utcnow
from src.detection.rules.matcher import compile_mapping
from src.detection.rules.sigma_parser import SigmaRule
from src.intel.ioc_matcher import IOCMatcher


def ts(seconds):
    return iso(utcnow() - timedelta(seconds=120) + timedelta(seconds=seconds))


def test_matcher_modifiers():
    m = compile_mapping({"event_type": ["a", "b"], "url|contains": "../", "dst_ip|private": False,
                         "bytes_out|gte": 10, "user|not": "root"})
    assert m({"event_type": "A", "url": "/x/../etc", "dst_ip": "198.51.100.1", "bytes_out": 10, "user": "bob"})
    assert not m({"event_type": "a", "url": "/x/../etc", "dst_ip": "10.0.0.1", "bytes_out": 10, "user": "bob"})
    assert not m({"event_type": "a", "url": "/x/../etc", "dst_ip": "198.51.100.1", "bytes_out": 10, "user": "root"})


async def test_brute_force_is_one_alert_that_aggregates(platform):
    events = [{"event_type": "ssh_failed", "src_ip": "198.51.100.77", "user": f"u{i % 3}", "dst_ip": "10.10.2.15",
               "@timestamp": ts(i)} for i in range(20)]
    alerts = await feed(platform, events)
    brute = [a for a in alerts if a["rule_id"] == "SOC-001"]
    assert len(brute) == 1
    assert brute[0]["event_count"] >= 15  # fires at the 6th failure, later failures aggregate into it
    assert brute[0]["entity"]["src_ip"] == "198.51.100.77"
    assert brute[0]["mitre"][0]["id"] == "T1110.001"


async def test_below_threshold_is_quiet(platform):
    events = [{"event_type": "ssh_failed", "src_ip": "10.10.1.20", "user": "alice", "@timestamp": ts(i)}
              for i in range(2)]
    assert not [a for a in await feed(platform, events) if a["rule_id"].startswith("SOC")]


async def test_port_scan_counts_distinct_ports(platform):
    same_port = [{"event_type": "firewall_drop", "src_ip": "198.51.100.5", "dst_port": 23, "@timestamp": ts(i)}
                 for i in range(15)]
    assert not [a for a in await feed(platform, same_port) if a["rule_id"] == "SOC-003"]
    scan = [{"event_type": "firewall_drop", "src_ip": "198.51.100.6", "dst_port": 1000 + i, "@timestamp": ts(i)}
            for i in range(12)]
    assert [a for a in await feed(platform, scan) if a["rule_id"] == "SOC-003"]


async def test_exfiltration_sums_bytes(platform):
    events = [{"event_type": "network_connection", "src_ip": "10.10.1.30", "dst_ip": "198.51.100.200",
               "bytes_out": 40_000_000, "@timestamp": ts(i * 10)} for i in range(3)]
    assert [a for a in await feed(platform, events) if a["rule_id"] == "SOC-007"]


async def test_attack_chain_brute_force_then_login(platform):
    events = [{"event_type": "ssh_failed", "src_ip": "198.51.100.88", "user": "root", "@timestamp": ts(i)}
              for i in range(8)]
    events.append({"event_type": "ssh_accepted", "src_ip": "198.51.100.88", "user": "svc", "@timestamp": ts(20)})
    chain = [a for a in await feed(platform, events) if a["rule_id"] == "CHAIN-001"]
    assert chain and chain[0]["severity"] == "critical" and chain[0]["score"] >= 90


async def test_threat_intel_match_on_parent_domain(platform):
    alerts = await feed(platform, [{"event_type": "dns_query", "src_ip": "10.10.1.11", "hostname": "ws-01",
                                    "query": "x.update-check.evil-cdn.example"}])
    intel = [a for a in alerts if a["rule_id"] == "INTEL-DOMAIN"]
    assert intel and intel[0]["intel"][0]["value"] == "evil-cdn.example"


def test_ioc_matcher_types():
    m = IOCMatcher()
    m.add("cidr", "203.0.113.0/25")
    m.add("hash", "E99A18C428CB38D5F260853678922E03")
    assert m.lookup_ip("203.0.113.9") and not m.lookup_ip("203.0.113.200")
    assert m.match_event({"file_hash": "e99a18c428cb38d5f260853678922e03"})
    assert not m.add("ip", "not-an-ip")


def test_sigma_conditions():
    rule = SigmaRule({"title": "t", "id": "S1", "level": "high", "tags": ["attack.execution", "attack.t1204"],
                      "detection": {"sel": {"ParentImage|endswith": "outlook.exe"},
                                    "ok": {"Image|endswith": ["excel.exe", "chrome.exe"]},
                                    "condition": "sel and not ok"}})
    assert rule.mitre == ["T1204"] and rule.category == "execution"
    assert rule.evaluate({"parent_process": "outlook.exe", "process_name": "invoice.exe"})
    assert not rule.evaluate({"parent_process": "outlook.exe", "process_name": "excel.exe"})
    one_of = SigmaRule({"title": "t", "detection": {"s1": {"user": "a"}, "s2": {"user": "b"},
                                                    "condition": "1 of s*"}}, "x.yml")
    assert one_of.evaluate({"user": "b"}) and not one_of.evaluate({"user": "c"})


def test_sigma_aggregation_is_rejected_not_misrun():
    with pytest.raises(ValueError):
        SigmaRule({"title": "t", "detection": {"s": {"user": "a"}, "condition": "s | count() > 5"}})


async def test_every_simulated_scenario_is_detected(platform):
    from src.simulation.traffic import SCENARIOS, TrafficGenerator
    gen = TrafficGenerator(seed=4)
    for _ in range(800):
        await platform.ingestion.process(gen.normal_event())
    baseline = {a["id"] for a in platform.store.list_alerts(500)["alerts"]}
    for scenario in SCENARIOS:
        _, _, steps = gen.attack(scenario)
        before = {a["id"] for a in platform.store.list_alerts(500)["alerts"]}
        for _, e in steps:
            await platform.ingestion.process(e)
        new = [a for a in platform.store.list_alerts(500)["alerts"] if a["id"] not in before]
        assert new, f"{scenario} was not detected"
    assert len(baseline) <= 2, "normal traffic should raise (almost) no alerts"


def test_chain_uses_event_time_for_imported_logs():
    from src.detection.correlator import CorrelationEngine
    cfg = {"detection": {"correlation": {"chains": [{
        "id": "C1", "first": {"category": "brute_force"}, "then_event": {"event_type": "ssh_accepted"},
        "key": "src_ip", "window": "10m"}]}}}
    first = {"id": "A1", "category": "brute_force", "last_seen": "2020-01-01T10:00:00Z",
             "entity": {"src_ip": "198.51.100.9"}}
    late = {"event_type": "ssh_accepted", "src_ip": "198.51.100.9", "@timestamp": "2020-01-01T10:30:00Z"}
    soon = {"event_type": "ssh_accepted", "src_ip": "198.51.100.9", "@timestamp": "2020-01-01T10:05:00Z"}
    eng = CorrelationEngine(cfg)
    eng.on_alert(first)
    assert eng.on_event(soon)  # old logs, 5 minutes apart in their own time -> correlated
    eng = CorrelationEngine(cfg)
    eng.on_alert(first)
    assert not eng.on_event(late)  # 30 minutes apart -> outside the window
