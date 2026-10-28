import time

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app


@pytest.fixture(scope="module")
def client():
    app = create_app(db_path=":memory:", simulate=False)
    with TestClient(app) as c:
        p = app.state.platform
        for _ in range(150):  # wait for the ML model (trained once per test session)
            if p.ml.detector:
                break
            time.sleep(0.2)
        yield c


def brute(ip, n=10):
    return [{"event_type": "ssh_failed", "src_ip": ip, "user": "root", "dst_ip": "10.10.2.15"} for _ in range(n)]


def test_health_and_ui(client):
    h = client.get("/health").json()
    assert h["status"] == "healthy" and h["response_mode"] == "dry_run"
    assert client.get("/ui/").status_code == 200
    assert client.get("/ui/vendor/chart.umd.min.js").status_code == 200


def test_ingest_detect_triage(client):
    r = client.post("/api/v1/ingest", json=brute("198.51.100.150")).json()
    assert r["accepted"] == 10 and r["alert_ids"]
    alert_id = r["alert_ids"][0]
    a = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "investigating", "note": "on it"},
                     headers={"X-Analyst": "abhinav"}).json()
    assert a["status"] == "investigating" and a["notes"][0]["by"] == "abhinav"
    assert client.get(f"/api/v1/alerts/{alert_id}").json()["status"] == "investigating"  # persisted
    time.sleep(0.8)  # events are written in small batches
    events = client.get("/api/v1/events?search=198.51.100.150").json()["events"]
    assert len(events) == 10 and any(e["flagged"] for e in events)


def test_raw_log_lines(client):
    lines = [{"raw_message": f"Oct 28 10:00:{i:02d} bastion sshd[1]: Failed password for root from 198.51.100.151 "
                             f"port 4{i:04d} ssh2"} for i in range(8)]
    r = client.post("/api/v1/ingest", json={"events": lines}).json()
    assert r["accepted"] == 8 and r["alert_ids"]


def test_clients_cannot_forge_ground_truth(client):
    r = client.post("/api/v1/ingest", json={"event_type": "x", "_truth": {"malicious": True}}).json()
    assert r["accepted"] == 1


def test_response_approval_cannot_be_bypassed(client):
    r = client.post("/api/v1/playbooks/block_ip/execute?require_approval=false",
                    json={"ip": "198.51.100.152"}).json()
    assert r["status"] == "pending_approval"
    bad = client.post("/api/v1/responses", json={"playbook": "block_ip", "target": {"src_ip": "1.1.1.1;id"}})
    assert bad.status_code == 422
    ok = client.post(f"/api/v1/responses/{r['id']}/approve").json()
    assert ok["status"] == "dry_run"
    assert any(b["ip"] == "198.51.100.152" for b in client.get("/api/v1/blocked").json()["blocked"])


def test_intel_rules_ml_endpoints(client):
    added = client.post("/api/v1/intel/iocs", json={"value": "198.51.100.199", "description": "test"}).json()
    assert added["type"] == "ip"
    assert client.get("/api/v1/intel/lookup?value=198.51.100.199").json()["local"]["value"] == "198.51.100.199"
    rules = client.get("/api/v1/rules").json()
    assert rules["stats"]["rules_failed"] == 0 and len(rules["rules"]) >= 13
    assert client.patch("/api/v1/rules/SOC-011", json={"enabled": False}).json()["enabled"] is False
    assert client.get("/api/v1/ml").json()["ready"] is True
    assert "soc_events_ingested_total" in client.get("/metrics").text


def test_simulation_and_websocket(client):
    with client.websocket_connect("/ws") as ws:
        assert ws.receive_json()["type"] == "connection"
        scenario = client.post("/api/v1/simulation/inject", json={"scenario": "port_scan"}).json()
        assert scenario["scenario"] == "port_scan"
        seen = set()
        for _ in range(300):
            seen.add(ws.receive_json()["type"])
            if {"event", "alert"} <= seen:
                break
        assert {"event", "alert"} <= seen


def test_api_key(client, monkeypatch):
    monkeypatch.setenv("SOC_API_KEY", "s3cret")
    assert client.get("/api/v1/stats").status_code == 401
    assert client.get("/api/v1/stats", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/health").status_code == 200


def test_entity_investigation(client):
    client.post("/api/v1/ingest", json=brute("198.51.100.160", 9))
    time.sleep(0.8)
    d = client.get("/api/v1/entities/198.51.100.160").json()
    assert d["events_total"] == 9 and d["by_type"] == {"ssh_failed": 9}
    assert d["alerts"] and d["open_alerts"] >= 1
    assert {"ip": "10.10.2.15", "events": 9} in d["top_peers"]
    assert client.get("/api/v1/entities/nothing-here").json()["events_total"] == 0


def test_sources_overview(client):
    s = client.get("/api/v1/sources").json()
    assert {"collectors", "events_by_source_1h", "event_volume", "simulation", "ingest_url"} <= set(s)
    assert s["events_by_source_1h"].get("api", 0) > 0
