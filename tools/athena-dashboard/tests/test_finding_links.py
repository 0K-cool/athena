import json

import command_log as cl
import finding_links as fl
import pytest


@pytest.fixture
def log(tmp_path):
    return cl.CommandLog(tmp_path / "08-evidence", "eng-fl")


def _cmd(log, agent, tuid, out="x"):
    s = log.append_start(agent=agent, backend="host", tool="Bash", tool_use_id=tuid, input={})
    log.append_complete(start_seq=s["seq"], output=out, is_error=False)
    return s["seq"], s["seq"] + 1  # (start_seq, complete_seq)


def test_validate_citations(log):
    s1, c1 = _cmd(log, "WV", "t1")          # c1 is a complete
    valid, rejected = fl.validate_citations(log, [c1, s1, 999])
    assert valid == [c1]
    reasons = {r["seq"]: r["reason"] for r in rejected}
    assert s1 in reasons and 999 in reasons


def test_auto_window_same_agent_only(log):
    _cmd(log, "WV", "t1")   # seqs 1,2
    _cmd(log, "DA", "t2")   # seqs 3,4
    _cmd(log, "WV", "t3")   # seqs 5,6
    head = log.head()["seq"]
    assert fl.auto_window(log, "WV", prev_head_seq=0, cur_head_seq=head) == [2, 6]
    assert fl.auto_window(log, "WV", prev_head_seq=2, cur_head_seq=head) == [6]


def test_compute_links_cited_beats_auto(log):
    _s, c1 = _cmd(log, "WV", "t1")
    links = fl.compute_links(log, agent="WV", severity="critical", cited_seqs=[c1],
                             prev_agent_head_seq=0, cur_head_seq=log.head()["seq"])
    assert len(links) == 1 and links[0]["link"] == "cited" and links[0]["seq"] == c1
    assert links[0]["tool"] == "Bash"


def test_compute_links_auto_for_high(log):
    _cmd(log, "WV", "t1")
    links = fl.compute_links(log, agent="WV", severity="high", cited_seqs=[],
                             prev_agent_head_seq=0, cur_head_seq=log.head()["seq"])
    assert [l["link"] for l in links] == ["auto"]


def test_compute_links_no_auto_for_medium(log):
    _cmd(log, "WV", "t1")
    assert fl.compute_links(log, agent="WV", severity="medium", cited_seqs=[],
                            prev_agent_head_seq=0, cur_head_seq=log.head()["seq"]) == []


def test_links_file_round_trip(log):
    fl.append_links_file(log.evidence_dir, "f1", [{"seq": 2, "link": "cited"}])
    fl.append_links_file(log.evidence_dir, "f2", [{"seq": 4, "link": "auto"}])
    loaded = fl.load_links_file(log.evidence_dir)
    assert loaded["f1"][0]["seq"] == 2 and loaded["f2"][0]["link"] == "auto"


# ---- integration through POST /api/findings ----

async def _cmd_via_api(client, eid, agent, tuid, start_seq):
    r = await client.post("/api/command-log/start", json={
        "engagement_id": eid, "agent": agent, "backend": "host", "tool": "Bash",
        "tool_use_id": tuid, "input": {"command": "x"}})
    assert r.json()["seq"] == start_seq
    await client.post("/api/command-log/complete", json={
        "engagement_id": eid, "start_seq": start_seq, "output": "o", "is_error": False})


def _finding(eid, title, severity, agent="WV", **extra):
    body = {"title": title, "severity": severity, "category": "injection",
            "target": "10.0.0.1", "agent": agent, "description": "d", "engagement": eid}
    body.update(extra)
    return body


@pytest.mark.asyncio
async def test_finding_cites_entry(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await client.post("/api/command-log/start", json={
        "engagement_id": "eng-link", "agent": "WV", "backend": "host", "tool": "Bash",
        "tool_use_id": "t1", "input": {"command": "sqlmap"}})
    await client.post("/api/command-log/complete", json={
        "engagement_id": "eng-link", "start_seq": 1, "output": "injectable", "is_error": False})
    r = await client.post("/api/findings", json={
        "title": "SQL injection in login", "severity": "high", "category": "injection",
        "target": "10.0.0.1", "agent": "WV", "description": "blind sqli",
        "engagement": "eng-link", "evidence_seqs": [2]})
    body = r.json()
    assert body["ok"] and body["evidence_links"][0]["link"] == "cited"
    assert body["evidence_links"][0]["seq"] == 2
    links = fl.load_links_file(tmp_path / "eng-link" / "08-evidence")
    assert links[body["finding_id"]][0]["seq"] == 2


@pytest.mark.asyncio
async def test_high_finding_auto_links_when_uncited(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    for i, tuid in enumerate(["t1", "t2"], start=1):
        await _cmd_via_api(client, "eng-auto", "WV", tuid, i * 2 - 1)
    r = await client.post("/api/findings", json=_finding("eng-auto", "Remote code execution", "critical"))
    links = r.json()["evidence_links"]
    assert links and all(l["link"] == "auto" for l in links)


@pytest.mark.asyncio
async def test_auto_link_matches_agent_code_end_to_end(client, tmp_path, monkeypatch):
    """Guards the Task 5 defect: an empty start.agent produced zero auto-links."""
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await _cmd_via_api(client, "eng-e2e", "WV", "t1", 1)
    await _cmd_via_api(client, "eng-e2e", "DA", "t2", 3)
    r = await client.post("/api/findings", json=_finding("eng-e2e", "Auth bypass", "high", agent="WV"))
    links = r.json()["evidence_links"]
    assert links, "WV start agent must match finding agent WV"
    assert [l["seq"] for l in links] == [2]
    assert all(l["link"] == "auto" and l["agent"] == "WV" for l in links)


@pytest.mark.asyncio
async def test_auto_window_advances_per_agent(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await _cmd_via_api(client, "eng-win", "WV", "t1", 1)
    r1 = await client.post("/api/findings", json=_finding("eng-win", "First RCE", "critical", target="10.0.0.2"))
    assert [l["seq"] for l in r1.json()["evidence_links"]] == [2]
    await _cmd_via_api(client, "eng-win", "WV", "t2", 3)
    r2 = await client.post("/api/findings", json=_finding("eng-win", "Second RCE", "critical", target="10.0.0.3"))
    assert [l["seq"] for l in r2.json()["evidence_links"]] == [4]


@pytest.mark.asyncio
async def test_medium_never_auto_links(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await _cmd_via_api(client, "eng-med", "WV", "t1", 1)
    r = await client.post("/api/findings", json=_finding("eng-med", "Verbose errors", "medium"))
    assert r.json()["evidence_links"] == []


@pytest.mark.asyncio
async def test_invalid_citations_rejected_with_reason(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await _cmd_via_api(client, "eng-rej", "WV", "t1", 1)
    r = await client.post("/api/findings", json=_finding(
        "eng-rej", "Reflected XSS in search", "medium", evidence_seqs=[1, 2, 999]))
    body = r.json()
    assert [l["seq"] for l in body["evidence_links"]] == [2]
    rejected = {x["seq"]: x["reason"] for x in body["rejected_evidence_seqs"]}
    assert set(rejected) == {1, 999} and all(rejected.values())


@pytest.mark.asyncio
async def test_no_command_log_does_not_crash(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    r = await client.post("/api/findings", json=_finding("eng-empty", "Info leak", "high"))
    body = r.json()
    assert body["ok"] and body["evidence_links"] == [] and body["rejected_evidence_seqs"] == []


@pytest.mark.asyncio
async def test_bad_engagement_id_does_not_crash(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    r = await client.post("/api/findings", json=_finding("bad eng!", "Info leak", "high"))
    body = r.json()
    assert body["ok"] and body["evidence_links"] == []


@pytest.mark.asyncio
async def test_dedup_merge_unions_citations_keeps_auto(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await _cmd_via_api(client, "eng-dd", "WV", "t1", 1)
    await _cmd_via_api(client, "eng-dd", "WV", "t2", 3)
    first = await client.post("/api/findings", json=_finding("eng-dd", "Dup SQLi", "high"))
    fid = first.json()["finding_id"]
    assert [l["link"] for l in first.json()["evidence_links"]] == ["auto", "auto"]
    second = await client.post("/api/findings", json=_finding(
        "eng-dd", "Dup SQLi", "high", evidence_seqs=[4]))
    sb = second.json()
    assert sb["deduplicated"] is True and sb["finding_id"] == fid
    assert [l["seq"] for l in sb["evidence_links"]] == [4]
    stored = fl.load_links_file(tmp_path / "eng-dd" / "08-evidence")[fid]
    by_seq = {l["seq"]: l["link"] for l in stored}
    # earlier auto rows (2) are kept; the new citation (4) is unioned in
    assert by_seq[2] == "auto" and by_seq[4] == "cited" and 4 in by_seq


@pytest.mark.asyncio
async def test_auto_window_prev_comes_from_rehydrated_finding(client, tmp_path, monkeypatch):
    """After a restart, findings come back from Neo4j with log_head_seq already set
    (never via a fresh POST). The next auto window must start after it, not at 0."""
    import time
    import server
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await _cmd_via_api(client, "eng-rehyd", "WV", "t1", 1)   # seqs 1,2 (already reported)
    await _cmd_via_api(client, "eng-rehyd", "WV", "t2", 3)   # seqs 3,4 (new work)
    await server.state.add_finding(server.Finding(
        id="rehyd01", title="Earlier finding", severity=server.Severity.HIGH,
        category="x", target="10.9.9.9", agent="WV", description="d",
        timestamp=time.time(), engagement="eng-rehyd", log_head_seq=2))
    r = await client.post("/api/findings", json=_finding("eng-rehyd", "Later RCE", "critical"))
    assert [l["seq"] for l in r.json()["evidence_links"]] == [4]


@pytest.mark.asyncio
async def test_rehydrated_finding_without_head_falls_back_to_zero(client, tmp_path, monkeypatch):
    """Older Neo4j nodes have no log_head_seq (None): documented fallback is prev=0."""
    import time
    import server
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await _cmd_via_api(client, "eng-oldnode", "WV", "t1", 1)
    await server.state.add_finding(server.Finding(
        id="old00001", title="Pre-link finding", severity=server.Severity.HIGH,
        category="x", target="10.9.9.8", agent="WV", description="d",
        timestamp=time.time(), engagement="eng-oldnode", log_head_seq=None))
    r = await client.post("/api/findings", json=_finding("eng-oldnode", "Newer RCE", "critical"))
    assert [l["seq"] for l in r.json()["evidence_links"]] == [2]


@pytest.mark.asyncio
@pytest.mark.parametrize("broken", ["entries", "head"])
async def test_link_failure_never_drops_finding(client, tmp_path, monkeypatch, broken):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await _cmd_via_api(client, "eng-boom", "WV", "t1", 1)

    def _boom(self, *a, **k):
        raise OSError("torn log line")
    monkeypatch.setattr(cl.CommandLog, broken, _boom)
    r = await client.post("/api/findings", json=_finding(
        "eng-boom", f"Finding survives {broken} failure", "critical", evidence_seqs=[2]))
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["finding_id"]
    assert body["evidence_links"] == [] and body["rejected_evidence_seqs"] == []


@pytest.mark.asyncio
async def test_link_failure_on_dedup_path_keeps_merge(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await _cmd_via_api(client, "eng-boom2", "WV", "t1", 1)
    first = await client.post("/api/findings", json=_finding("eng-boom2", "Dup under failure", "high"))
    fid = first.json()["finding_id"]

    def _boom(self, *a, **k):
        raise OSError("io error")
    monkeypatch.setattr(cl.CommandLog, "entries", _boom)
    second = await client.post("/api/findings", json=_finding("eng-boom2", "Dup under failure", "high"))
    assert second.status_code == 200
    sb = second.json()
    assert sb["ok"] and sb["deduplicated"] is True and sb["finding_id"] == fid
    assert sb["evidence_links"] == []
