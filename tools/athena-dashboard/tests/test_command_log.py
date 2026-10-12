import hashlib
import json

import pytest

import command_log as cl


@pytest.fixture
def log(tmp_path):
    return cl.CommandLog(tmp_path / "08-evidence", "eng-test-001")


def _lines(log):
    return [json.loads(l) for l in log.path.read_text().splitlines() if l.strip()]


def test_genesis_and_seq(log):
    a = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={"command": "id"})
    b = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t2", input={"command": "pwd"})
    assert a["seq"] == 1 and a["prev_hash"] == cl.GENESIS
    assert b["seq"] == 2 and b["prev_hash"] == a["entry_hash"]


def test_entry_hash_is_canonical_recompute(log):
    e = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={"b": 1, "a": "ü"})
    body = {k: v for k, v in e.items() if k != "entry_hash"}
    expected = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    assert e["entry_hash"] == expected
    assert _lines(log)[0] == e


def test_server_fields(log):
    e = log.append_start(agent="WV", backend="kali_external", tool="mcp__kali_external__nmap",
                         tool_use_id="t1", input={"target": "10.0.0.1"})
    assert e["engagement_id"] == "eng-test-001"
    assert e["phase"] == "start"
    assert isinstance(e["ts"], int) and e["ts"] > 1_600_000_000_000
    assert e["input"] == {"target": "10.0.0.1"}


def test_complete_stores_output_by_hash(log):
    s = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={})
    c = log.append_complete(start_seq=s["seq"], output="hello\n", is_error=False)
    digest = hashlib.sha256(b"hello\n").hexdigest()
    assert c["phase"] == "complete" and c["start_seq"] == 1
    assert c["output_sha256"] == digest == c["stored_sha256"]
    assert c["output_bytes"] == c["stored_bytes"] == 6
    assert c["truncated"] is False
    assert c["output_file"] == f"tool-logs/cmd-{digest}.txt"
    assert (log.evidence_dir / c["output_file"]).read_bytes() == b"hello\n"


def test_output_cap_records_truncation(log, monkeypatch):
    monkeypatch.setattr(cl, "MAX_OUTPUT_BYTES", 10)
    s = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={})
    c = log.append_complete(start_seq=s["seq"], output=b"0123456789ABCDEF", is_error=False)
    assert c["truncated"] is True
    assert c["output_bytes"] == 16 and c["stored_bytes"] == 10
    assert c["output_sha256"] == hashlib.sha256(b"0123456789ABCDEF").hexdigest()
    assert c["stored_sha256"] == hashlib.sha256(b"0123456789").hexdigest()
    assert (log.evidence_dir / c["output_file"]).read_bytes() == b"0123456789"


def test_unknown_start_rejected(log):
    with pytest.raises(cl.CommandLogError) as ei:
        log.append_complete(start_seq=99, output="x", is_error=False)
    assert ei.value.code == "unknown_start"


def test_complete_cannot_target_a_complete(log):
    s = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={})
    c = log.append_complete(start_seq=s["seq"], output="x", is_error=False)
    with pytest.raises(cl.CommandLogError) as ei:
        log.append_complete(start_seq=c["seq"], output="x", is_error=False)
    assert ei.value.code == "unknown_start"


def test_duplicate_complete_rejected(log):
    s = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={})
    log.append_complete(start_seq=s["seq"], output="x", is_error=False)
    with pytest.raises(cl.CommandLogError) as ei:
        log.append_complete(start_seq=s["seq"], output="y", is_error=True)
    assert ei.value.code == "duplicate_complete"


def test_output_write_failure_is_recorded(log, monkeypatch):
    def boom(self, path, data):
        raise OSError("disk full")
    monkeypatch.setattr(cl.CommandLog, "_write_output", boom)
    s = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={})
    c = log.append_complete(start_seq=s["seq"], output="x", is_error=False)
    assert c["output_file"] is None
    assert "disk full" in c["output_error"]


def test_head_entries_get(log):
    assert log.head() == {"seq": 0, "entry_hash": cl.GENESIS}
    a = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={})
    b = log.append_complete(start_seq=1, output="x", is_error=False)
    assert log.head() == {"seq": 2, "entry_hash": b["entry_hash"]}
    assert [e["seq"] for e in log.entries()] == [1, 2]
    assert [e["seq"] for e in log.entries(after_seq=1)] == [2]
    assert [e["seq"] for e in log.entries(limit=1)] == [1]
    assert log.get(1) == a and log.get(3) is None


def test_non_utf8_output_is_stored(log):
    s = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={})
    c1 = log.append_complete(start_seq=s["seq"], output=b"\xff\xfe\x00binary", is_error=False)
    assert (log.evidence_dir / c1["output_file"]).read_bytes() == b"\xff\xfe\x00binary"
    s2 = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t2", input={})
    c2 = log.append_complete(start_seq=s2["seq"], output="lone \ud800 surrogate", is_error=False)
    assert c2["output_file"] is not None


def test_large_input_round_trips(log):
    big = {"command": "cat <<'EOF'\n" + ("A" * 1_000_000) + "\nEOF"}
    e = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input=big)
    assert log.get(e["seq"])["input"] == big


def _pair(log, n=1):
    for i in range(n):
        s = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id=f"t{i}", input={"i": i})
        log.append_complete(start_seq=s["seq"], output=f"out{i}", is_error=False)


def _rewrite(log, mutate):
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(mutate(lines)) + "\n")


def test_verify_ok(log):
    _pair(log, 3)
    r = cl.verify(log.evidence_dir)
    assert r["status"] == "ok" and r["entry_count"] == 6 and r["gaps"] == []
    assert r["head"] == log.head() and r["first_bad_seq"] is None


def test_verify_empty(tmp_path):
    r = cl.verify(tmp_path)
    assert r["status"] == "ok" and r["head"] == {"seq": 0, "entry_hash": cl.GENESIS}


def test_tamper_edit_field(log):
    _pair(log, 3)
    def m(lines):
        e = json.loads(lines[2]); e["input"] = {"i": 999}; lines[2] = json.dumps(e); return lines
    _rewrite(log, m)
    r = cl.verify(log.evidence_dir)
    assert r["status"] == "broken" and r["first_bad_seq"] == 3


def test_tamper_delete_middle(log):
    _pair(log, 3)
    _rewrite(log, lambda lines: lines[:2] + lines[3:])
    r = cl.verify(log.evidence_dir)
    assert r["status"] == "broken" and r["first_bad_seq"] == 3


def test_tamper_reorder(log):
    _pair(log, 3)
    _rewrite(log, lambda lines: [lines[0], lines[2], lines[1]] + lines[3:])
    r = cl.verify(log.evidence_dir)
    assert r["status"] == "broken" and r["first_bad_seq"] == 2


def test_tamper_recompute_single_hash(log):
    _pair(log, 3)
    def m(lines):
        e = json.loads(lines[2]); e["input"] = {"i": 999}
        e["entry_hash"] = cl.compute_entry_hash(e); lines[2] = json.dumps(e); return lines
    _rewrite(log, m)
    r = cl.verify(log.evidence_dir)
    assert r["status"] == "broken" and r["first_bad_seq"] == 4


def test_tamper_output_byte(log):
    _pair(log, 1)
    c = log.get(2)
    p = log.evidence_dir / c["output_file"]
    p.write_bytes(b"X" + p.read_bytes()[1:])
    r = cl.verify(log.evidence_dir)
    assert r["status"] == "broken" and r["first_bad_seq"] == 2


def test_deleted_output_file_is_broken(log):
    _pair(log, 1)
    (log.evidence_dir / log.get(2)["output_file"]).unlink()
    assert cl.verify(log.evidence_dir)["status"] == "broken"


def test_output_path_outside_tool_logs_is_broken(log):
    _pair(log, 1)
    def m(lines):
        e = json.loads(lines[1]); e["output_file"] = "../../etc/hosts"
        e["entry_hash"] = cl.compute_entry_hash(e); lines[1] = json.dumps(e); return lines
    _rewrite(log, m)
    r = cl.verify(log.evidence_dir)
    assert r["status"] == "broken" and r["first_bad_seq"] == 2


def test_tail_truncation_changes_head(log):
    _pair(log, 2)
    printed_head = log.head()
    _rewrite(log, lambda lines: lines[:-1])
    r = cl.verify(log.evidence_dir)
    assert r["head"] != printed_head


def test_unmatched_start_is_gap(log):
    log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={})
    r = cl.verify(log.evidence_dir)
    assert r["status"] == "ok_with_gaps"
    assert {"type": "unmatched_start", "seq": 1} in r["gaps"]


def test_late_and_missing_output_are_gaps(log, monkeypatch):
    s = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1", input={},
                         late=True, client_ts=123)
    monkeypatch.setattr(cl.CommandLog, "_write_output", lambda self, p, d: (_ for _ in ()).throw(OSError("x")))
    log.append_complete(start_seq=s["seq"], output="x", is_error=False)
    r = cl.verify(log.evidence_dir)
    types = {g["type"] for g in r["gaps"]}
    assert r["status"] == "ok_with_gaps" and {"late", "missing_output"} <= types
