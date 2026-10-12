# tests/test_api_command_log.py
import command_log as cl
import pytest

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _root(tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    return tmp_path


async def _start(client, eid="eng-api-1", tuid="t1"):
    return await client.post("/api/command-log/start", json={
        "engagement_id": eid, "agent": "WV", "backend": "host",
        "tool": "Bash", "tool_use_id": tuid, "input": {"command": "id"}})


async def test_start_complete_verify_entries(client):
    r = await _start(client)
    assert r.status_code == 200 and r.json()["seq"] == 1
    r2 = await client.post("/api/command-log/complete", json={
        "engagement_id": "eng-api-1", "start_seq": 1, "output": "uid=0", "is_error": False})
    assert r2.status_code == 200 and r2.json()["seq"] == 2
    rv = await client.get("/api/command-log/eng-api-1/verify")
    assert rv.status_code == 200 and rv.json()["status"] == "ok"
    re_ = await client.get("/api/command-log/eng-api-1/entries")
    body = re_.json()
    assert [e["seq"] for e in body["entries"]] == [1, 2]
    assert body["head"]["seq"] == 2


@pytest.mark.parametrize("eid", ["eng*", "../x", "", "x" * 65, "a b"])
async def test_bad_eid_rejected(client, eid):
    r = await client.post("/api/command-log/start", json={
        "engagement_id": eid, "agent": "WV", "backend": "host",
        "tool": "Bash", "tool_use_id": "t1", "input": {}})
    assert r.status_code == 400
    assert (await client.get(f"/api/command-log/{eid or 'x'}/verify") ).status_code in (200, 400, 404)  # 404: httpx normalizes '../x' away before routing


async def test_folder_resolution_is_exact(client, _root):
    (_root / "eng-10-acme").mkdir()
    (_root / "eng-1-2").mkdir()
    await _start(client, eid="eng-1", tuid="t1")
    assert (_root / "eng-1" / "08-evidence" / "command-log.jsonl").exists()
    assert not (_root / "eng-10-acme" / "08-evidence").exists()
    assert not (_root / "eng-1-2" / "08-evidence" / "command-log.jsonl").exists()


async def test_server_timestamp_wins(client):
    r = await client.post("/api/command-log/start", json={
        "engagement_id": "eng-ts", "agent": "WV", "backend": "host", "tool": "Bash",
        "tool_use_id": "t1", "input": {}, "ts": 1})
    seq = r.json()["seq"]
    e = (await client.get("/api/command-log/eng-ts/entries")).json()["entries"][seq - 1]
    assert e["ts"] > 1_600_000_000_000


async def test_unknown_start_is_409(client):
    await _start(client, eid="eng-u")
    r = await client.post("/api/command-log/complete", json={
        "engagement_id": "eng-u", "start_seq": 999, "output": "x", "is_error": False})
    assert r.status_code == 409


async def test_lock_timeout_is_503(client, monkeypatch):
    def boom(*a, **k):
        raise cl.CommandLogError("lock_timeout", "locked")
    monkeypatch.setattr(cl.CommandLog, "append_start", boom)
    r = await _start(client, eid="eng-lock")
    assert r.status_code == 503


async def test_engagements_are_isolated(client, _root):
    await _start(client, eid="eng-A", tuid="a1")
    await _start(client, eid="eng-B", tuid="b1")
    await _start(client, eid="eng-B", tuid="b2")
    a = (await client.get("/api/command-log/eng-A/entries")).json()["entries"]
    b = (await client.get("/api/command-log/eng-B/entries")).json()["entries"]
    assert [e["tool_use_id"] for e in a] == ["a1"]
    assert [e["tool_use_id"] for e in b] == ["b1", "b2"]
    assert all(e["engagement_id"] == "eng-A" for e in a)
    assert all(e["engagement_id"] == "eng-B" for e in b)


@pytest.mark.parametrize("eid", ["eng*", "x" * 65, "a b"])
async def test_get_routes_reject_bad_eid(client, eid):
    assert (await client.get(f"/api/command-log/{eid}/verify")).status_code == 400
    assert (await client.get(f"/api/command-log/{eid}/entries")).status_code == 400


async def test_entries_limit_semantics(client):
    for t in ("t1", "t2", "t3"):
        await _start(client, eid="eng-lim", tuid=t)
    base = "/api/command-log/eng-lim/entries"
    assert len((await client.get(base)).json()["entries"]) == 3
    assert len((await client.get(base + "?limit=0")).json()["entries"]) == 3
    assert len((await client.get(base + "?limit=2")).json()["entries"]) == 2
    assert (await client.get(base + "?limit=-1")).status_code == 422
