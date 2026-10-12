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
