"""Tamper-evident command evidence log (stdlib only).

One hash-chained JSONL file per engagement plus outputs stored by hash.
Spec: docs/superpowers/specs/2026-10-12-command-evidence-log-design.md
"""
import fcntl
import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path

GENESIS = "0" * 64
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
LOG_NAME = "command-log.jsonl"
LOCK_NAME = "command-log.lock"
OUTPUT_DIR = "tool-logs"


class CommandLogError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_entry_hash(entry: dict) -> str:
    return hashlib.sha256(canonical({k: v for k, v in entry.items() if k != "entry_hash"})).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _to_bytes(output) -> bytes:
    if isinstance(output, bytes):
        return output
    return str(output).encode("utf-8", errors="replace")


class CommandLog:
    def __init__(self, evidence_dir: Path, engagement_id: str, lock_timeout: float = 5.0):
        self.evidence_dir = Path(evidence_dir)
        self.engagement_id = engagement_id
        self.path = self.evidence_dir / LOG_NAME
        self.outputs_dir = self.evidence_dir / OUTPUT_DIR
        self.lock_timeout = lock_timeout
        self.outputs_dir.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _locked(self):
        fd = os.open(self.evidence_dir / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            deadline = time.monotonic() + self.lock_timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise CommandLogError("lock_timeout", "command log is locked")
                    time.sleep(0.02)
            yield
        finally:
            os.close(fd)

    def _read_all(self) -> list:
        if not self.path.exists():
            return []
        with open(self.path, "rb") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _load_for_write(self) -> list:
        return self._read_all()

    def _append(self, entries: list, body: dict) -> dict:
        prev = entries[-1] if entries else None
        entry = dict(body)
        entry["seq"] = prev["seq"] + 1 if prev else 1
        entry["ts"] = _now_ms()
        entry["engagement_id"] = self.engagement_id
        entry["prev_hash"] = prev["entry_hash"] if prev else GENESIS
        entry["entry_hash"] = compute_entry_hash(entry)
        with open(self.path, "ab") as f:
            f.write(canonical(entry) + b"\n")
            f.flush()
            os.fsync(f.fileno())
        entries.append(entry)
        return entry

    def _write_output(self, path: Path, data: bytes) -> None:
        if path.exists() and path.stat().st_size == len(data):
            return
        tmp = path.with_suffix(".tmp")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _start(self, entries, *, agent, backend, tool, tool_use_id, input, late=False, client_ts=None):
        body = {"phase": "start", "agent": agent, "backend": backend, "tool": tool,
                "tool_use_id": tool_use_id, "input": input}
        if late:
            body["late"] = True
            body["client_ts"] = client_ts
        return self._append(entries, body)

    def _complete(self, entries, *, start_seq, output, is_error, late=False, client_ts=None):
        if not any(e["seq"] == start_seq and e["phase"] == "start" for e in entries):
            raise CommandLogError("unknown_start", f"no start entry with seq {start_seq}")
        if any(e["phase"] == "complete" and e.get("start_seq") == start_seq for e in entries):
            raise CommandLogError("duplicate_complete", f"start {start_seq} already completed")
        data = _to_bytes(output)
        stored = data[:MAX_OUTPUT_BYTES]
        output_sha = sha256_hex(data)
        body = {"phase": "complete", "start_seq": start_seq, "is_error": bool(is_error),
                "output_sha256": output_sha, "output_bytes": len(data),
                "stored_bytes": len(stored), "stored_sha256": sha256_hex(stored),
                "truncated": len(data) > MAX_OUTPUT_BYTES}
        rel = f"{OUTPUT_DIR}/cmd-{output_sha}.txt"
        try:
            self._write_output(self.evidence_dir / rel, stored)
            body["output_file"] = rel
        except OSError as e:
            body["output_file"] = None
            body["output_error"] = f"{type(e).__name__}: {str(e)[:200]}"
        if late:
            body["late"] = True
            body["client_ts"] = client_ts
        return self._append(entries, body)

    def append_start(self, *, agent, backend, tool, tool_use_id, input, late=False, client_ts=None) -> dict:
        with self._locked():
            entries = self._load_for_write()
            return self._start(entries, agent=agent, backend=backend, tool=tool,
                               tool_use_id=tool_use_id, input=input, late=late, client_ts=client_ts)

    def append_complete(self, *, start_seq, output, is_error, late=False, client_ts=None) -> dict:
        with self._locked():
            entries = self._load_for_write()
            return self._complete(entries, start_seq=start_seq, output=output, is_error=is_error,
                                  late=late, client_ts=client_ts)

    def entries(self, after_seq: int = 0, limit=None) -> list:
        out = [e for e in self._read_all() if e["seq"] > after_seq]
        return out[:limit] if limit is not None else out

    def get(self, seq: int):
        return next((e for e in self._read_all() if e["seq"] == seq), None)

    def head(self) -> dict:
        entries = self._read_all()
        if not entries:
            return {"seq": 0, "entry_hash": GENESIS}
        return {"seq": entries[-1]["seq"], "entry_hash": entries[-1]["entry_hash"]}


_OUTPUT_FILE_RE = re.compile(r"^tool-logs/cmd-[0-9a-f]{64}\.txt$")


def verify(evidence_dir) -> dict:
    evidence_dir = Path(evidence_dir)
    path = evidence_dir / LOG_NAME
    result = {"status": "ok", "head": {"seq": 0, "entry_hash": GENESIS}, "entry_count": 0,
              "gaps": [], "first_bad_seq": None, "reason": None}

    def broken(seq, reason):
        result.update(status="broken", first_bad_seq=seq, reason=reason)
        return result

    if not path.exists():
        return result
    lines = path.read_bytes().split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    prev_hash, expected = GENESIS, 1
    starts, completed = set(), set()
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            return broken(expected, "unparseable line")
        if not isinstance(e, dict):
            return broken(expected, "entry is not a JSON object")
        if e.get("seq") != expected:
            return broken(expected, f"seq {e.get('seq')} found, expected {expected}")
        if e.get("prev_hash") != prev_hash:
            return broken(expected, "prev_hash does not link to previous entry")
        if compute_entry_hash(e) != e.get("entry_hash"):
            return broken(expected, "entry_hash mismatch")
        phase = e.get("phase")
        if phase == "start":
            starts.add(expected)
        elif phase == "complete":
            s = e.get("start_seq")
            if s not in starts:
                return broken(expected, f"complete references unknown start {s}")
            if s in completed:
                return broken(expected, f"second complete for start {s}")
            completed.add(s)
            of = e.get("output_file")
            if of is None:
                result["gaps"].append({"type": "missing_output", "seq": expected,
                                       "reason": e.get("output_error", "")})
            else:
                if not isinstance(of, str) or not _OUTPUT_FILE_RE.fullmatch(of):
                    return broken(expected, "output_file path is not a tool-logs hash path")
                fp = evidence_dir / of
                if not fp.is_file():
                    return broken(expected, f"output file {of} missing")
                data = fp.read_bytes()
                if len(data) != e.get("stored_bytes") or sha256_hex(data) != e.get("stored_sha256"):
                    return broken(expected, f"output file {of} does not match its entry")
        elif phase == "event":
            gap = {"type": e.get("event"), "seq": expected}
            for k in ("bytes_removed", "tool_use_id"):
                if k in e:
                    gap[k] = e[k]
            result["gaps"].append(gap)
        else:
            return broken(expected, f"unknown phase {phase!r}")
        if e.get("late"):
            result["gaps"].append({"type": "late", "seq": expected})
        prev_hash = e["entry_hash"]
        result["head"] = {"seq": expected, "entry_hash": prev_hash}
        result["entry_count"] += 1
        expected += 1
    for s in sorted(starts - completed):
        result["gaps"].append({"type": "unmatched_start", "seq": s})
    if result["gaps"]:
        result["status"] = "ok_with_gaps"
    return result
