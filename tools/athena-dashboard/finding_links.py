"""Link findings to command-log entries (cited or auto)."""
import json
import os
from pathlib import Path

import command_log as cl

AUTO_SEVERITIES = {"high", "critical"}
LINKS_NAME = "finding-links.jsonl"


def validate_citations(log, seqs):
    by_seq = {e["seq"]: e for e in log.entries()}
    valid, rejected = [], []
    for s in seqs or []:
        e = by_seq.get(s)
        if e is None:
            rejected.append({"seq": s, "reason": "no such entry"})
        elif e["phase"] != "complete":
            rejected.append({"seq": s, "reason": f"entry {s} is '{e['phase']}', not a completed command"})
        else:
            valid.append(s)
    return valid, rejected


def auto_window(log, agent, prev_head_seq, cur_head_seq):
    entries = log.entries()
    by_seq = {e["seq"]: e for e in entries}
    out = []
    for e in entries:
        if e["phase"] != "complete":
            continue
        if not (prev_head_seq < e["seq"] <= cur_head_seq):
            continue
        start = by_seq.get(e["start_seq"])
        if start and start.get("agent") == agent:
            out.append(e["seq"])
    return out


def _link_rows(log, seqs, link_type):
    by_seq = {e["seq"]: e for e in log.entries()}
    rows = []
    for s in seqs:
        c = by_seq[s]
        start = by_seq.get(c["start_seq"], {})
        rows.append({"seq": s, "entry_hash": c["entry_hash"], "link": link_type,
                     "agent": start.get("agent", ""), "tool": start.get("tool", "")})
    return rows


def compute_links(log, *, agent, severity, cited_seqs, prev_agent_head_seq, cur_head_seq):
    valid, _ = validate_citations(log, cited_seqs)
    if valid:
        return _link_rows(log, valid, "cited")
    if (severity or "").lower() in AUTO_SEVERITIES:
        return _link_rows(log, auto_window(log, agent, prev_agent_head_seq, cur_head_seq), "auto")
    return []


def append_links_file(evidence_dir, finding_id, links):
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    rec = {"finding_id": finding_id, "links": links}
    with open(evidence_dir / LINKS_NAME, "ab") as f:
        f.write(cl.canonical(rec) + b"\n")
        f.flush()
        os.fsync(f.fileno())


def load_links_file(evidence_dir):
    p = Path(evidence_dir) / LINKS_NAME
    out = {}
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        if line.strip():
            rec = json.loads(line)
            out.setdefault(rec["finding_id"], [])
            for l in rec["links"]:
                if l not in out[rec["finding_id"]]:
                    out[rec["finding_id"]].append(l)
    return out
