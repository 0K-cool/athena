# tests/test_sdk_agent_hook.py
import asyncio
import json

import command_log as cl
import command_log_hook as h
import pytest

pytestmark = pytest.mark.asyncio


def test_classify_backend():
    assert h.classify_backend("mcp__kali_external__nmap") == "kali_external"
    assert h.classify_backend("mcp__kali_internal__bash") == "kali_internal"
    assert h.classify_backend("Bash") == "host"
    for internal in ["mcp__athena_neo4j__create_host", "Read", "Write", "Grep", "WebFetch"]:
        assert h.classify_backend(internal) is None


class _StubServer:
    """In-process stand-in for the REST writer, backed by a real CommandLog."""
    def __init__(self, evidence_dir, eid):
        self.log = cl.CommandLog(evidence_dir, eid)
        self.fail = False

    async def start(self, **p):
        if self.fail:
            raise RuntimeError("down")
        return self.log.append_start(**p)

    async def complete(self, **p):
        if self.fail:
            raise RuntimeError("down")
        return self.log.append_complete(**p)


async def test_kali_and_host_logged_internal_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    c = h.CommandLogClient("http://x", "eng-h")
    sent = []
    async def fake_post(path, payload):
        sent.append((path, payload))
        if path.endswith("/start"):
            return {"ok": True, "seq": len(sent), "entry_hash": "h"}
        return {"ok": True, "seq": len(sent), "entry_hash": "h"}
    monkeypatch.setattr(c, "_post", fake_post)

    await c.start("mcp__kali_external__nmap", "t1", {"target": "10.0.0.1"})
    await c.start("Bash", "t2", {"command": "id"})
    await c.start("mcp__athena_neo4j__create_host", "t3", {})  # internal → no call
    assert [p["backend"] for _, p in sent if p] == ["kali_external", "host"]


async def test_complete_uses_tracked_start_seq(tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    c = h.CommandLogClient("http://x", "eng-h")
    calls = []
    async def fake_post(path, payload):
        calls.append((path, payload))
        return {"ok": True, "seq": 1, "entry_hash": "h"}
    monkeypatch.setattr(c, "_post", fake_post)
    await c.start("Bash", "t1", {"command": "id"})
    await c.complete("t1", "uid=0", False)
    complete = [p for path, p in calls if path.endswith("/complete")][0]
    assert complete["start_seq"] == 1


async def test_server_down_spools_without_raising(tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    c = h.CommandLogClient("http://x", "eng-h")
    async def boom(path, payload):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(c, "_post", boom)
    await c.start("Bash", "t1", {"command": "id"})   # must not raise
    await c.complete("t1", "uid=0", False)            # must not raise
    spool = tmp_path / "eng-h" / "08-evidence" / cl.SPOOL_NAME
    kinds = [json.loads(l)["kind"] for l in spool.read_text().splitlines() if l.strip()]
    assert kinds == ["start", "complete"]


async def test_complete_after_spooled_start_is_spooled(tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    c = h.CommandLogClient("http://x", "eng-h")
    async def boom(path, payload):
        raise RuntimeError("down")
    monkeypatch.setattr(c, "_post", boom)
    await c.start("Bash", "t1", {"command": "id"})
    await c.complete("t1", "out", False)
    spool = tmp_path / "eng-h" / "08-evidence" / cl.SPOOL_NAME
    recs = [json.loads(l) for l in spool.read_text().splitlines() if l.strip()]
    assert recs[1]["kind"] == "complete" and recs[1]["tool_use_id"] == "t1"


async def test_sdk_agent_imports_hook():
    import importlib
    mod = importlib.import_module("sdk_agent")
    assert hasattr(mod, "AthenaAgentSession")
    # classify_backend is imported inside __init__; just confirm the hook module wires in.
    import command_log_hook
    assert command_log_hook.classify_backend("Bash") == "host"
