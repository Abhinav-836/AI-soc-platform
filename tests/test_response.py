import subprocess

import pytest

from src.response.executor import ResponseError
from src.response.firewall import FirewallError, FirewallManager


def test_firewall_rejects_injection_and_internal_addresses():
    fw = FirewallManager({"backend": "iptables"})
    for bad in ("1.2.3.4; id", "$(id)", "1.2.3.4 && id", "", "localhost"):
        with pytest.raises(FirewallError):
            fw.validate(bad)
    for internal in ("10.0.0.5", "192.168.1.1", "127.0.0.1"):
        with pytest.raises(FirewallError):
            fw.validate(internal)
    assert fw.validate("198.51.100.20") == "198.51.100.20"
    cmd = fw._commands("198.51.100.20", True)[0]
    assert isinstance(cmd, list) and "198.51.100.20" in cmd  # argument list, never a shell string


async def test_block_needs_approval_and_dry_run_changes_nothing(platform, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("dry-run must not execute commands")
    monkeypatch.setattr(subprocess, "run", forbidden)
    item = await platform.response.request("block_ip", target={"src_ip": "198.51.100.20"}, requested_by="test")
    assert item["status"] == "pending_approval"
    done = await platform.response.approve(item["id"], "lead")
    assert done["status"] == "dry_run" and done["decided_by"] == "lead"
    assert platform.store.list_blocks()[0]["mode"] == "dry_run"
    with pytest.raises(ResponseError):
        await platform.response.approve(item["id"], "lead")  # can't approve twice


async def test_bad_targets_are_rejected(platform):
    with pytest.raises(ResponseError):
        await platform.response.request("block_ip", target={"src_ip": "1.2.3.4; rm -rf /"})
    with pytest.raises(ResponseError):
        await platform.response.request("isolate_host", target={"hostname": "ws-01 && shutdown"})
    with pytest.raises(ResponseError):
        await platform.response.request("no_such_playbook")


async def test_reject(platform):
    item = await platform.response.request("isolate_host", target={"hostname": "ws-07"})
    rejected = await platform.response.reject(item["id"], "lead", "false positive")
    assert rejected["status"] == "rejected" and all(a["status"] == "skipped" for a in rejected["actions"])
