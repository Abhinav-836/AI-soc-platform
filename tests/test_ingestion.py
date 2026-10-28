import asyncio
import json

import pytest

from src.core.config_loader import ConfigLoader
from src.ingestion.collectors.file_collector import FileCollector
from src.ingestion.parsers.normalizer import LogNormalizer


@pytest.fixture
def norm(config):
    return LogNormalizer(config)


def test_sshd_syslog_line(norm):
    e = norm.normalize_sync({"raw_message": "Oct 28 10:15:01 bastion-01 sshd[912]: Failed password for invalid user "
                                           "admin from 198.51.100.7 port 51522 ssh2"})
    assert e["event_type"] == "ssh_failed"
    assert (e["src_ip"], e["user"], e["src_port"], e["hostname"]) == ("198.51.100.7", "admin", 51522, "bastion-01")


def test_firewall_and_access_log(norm):
    fw = norm.normalize_sync({"raw_message": "kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.5 DST=10.0.0.2 PROTO=TCP "
                                             "SPT=4444 DPT=3389"})
    assert fw["event_type"] == "firewall_drop" and fw["dst_port"] == 3389
    web = norm.normalize_sync({"raw_message": '198.51.100.9 - - [28/Oct/2026:10:00:00 +0000] "GET /login HTTP/1.1" '
                                              '404 512 "-" "curl/8"'})
    assert web["event_type"] == "http_request" and web["status_code"] == 404
    assert web["@timestamp"].startswith("2026-10-28T10:00:00")


def test_cef(norm):
    e = norm.normalize_sync({"raw_message": "CEF:0|Vendor|IDS|1.0|100|Port scan|7|src=203.0.113.9 dst=10.0.0.5 "
                                            "dpt=22 act=blocked"})
    assert e["src_ip"] == "203.0.113.9" and e["dst_port"] == 22 and e["action"] == "blocked"


def test_structured_event_keeps_time_and_maps_aliases(norm):
    e = norm.normalize_sync({"event_type": "SSH_FAILED", "source_ip": "198.51.100.1", "username": "root",
                             "timestamp": "2026-01-02T03:04:05Z"})
    assert e["event_type"] == "ssh_failed" and e["src_ip"] == "198.51.100.1" and e["user"] == "root"
    assert e["@timestamp"] == "2026-01-02T03:04:05Z"  # not replaced by "now"
    assert e["event_id"]


async def test_file_collector_reads_existing_globbed_files_and_partial_lines(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("line one\nline two\npartial")
    cfg = ConfigLoader(overrides={"ingestion": {"sources": {"file": {"paths": [str(tmp_path / "*.log")]}}}})
    collector = FileCollector(cfg)
    collector.state_file = tmp_path / "offsets.json"
    collector.offsets = {}
    q = asyncio.Queue()
    assert await collector.poll(q) == 2           # existing content is read, the half line is held back
    with open(log, "a") as f:
        f.write(" now complete\n")
    assert await collector.poll(q) == 1
    lines = [q.get_nowait()["raw_message"] for _ in range(3)]
    assert lines[-1] == "partial now complete"
    assert json.loads(collector.state_file.read_text())[str(log)] == log.stat().st_size
    log.write_text("rotated\n")                      # truncation = rotation
    assert await collector.poll(q) == 1


def test_host_monitor_reports_real_processes(config):
    import os
    from src.ingestion.collectors.host_collector import HostCollector
    hc = HostCollector(config)
    hc.poll()  # first poll learns what is already running / listening
    events = hc.poll()
    assert all(e["source_type"] == "host" and e["hostname"] == hc.hostname for e in events)
    assert all("command_line" not in e for e in events)  # command lines are opt-in
    assert hc.stats["last_poll"] and hc._seen_pids.get(os.getpid())
