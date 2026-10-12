"""Deterministic, secret-masked command-evidence appendix for reports."""
import command_log as cl
import secret_mask as sm

AUTO_SEVERITIES = {"high", "critical"}


def finding_evidence(log, links, literals=(), by_seq=None):
    """Per-link evidence rows (no raw output). Pass by_seq to reuse one entries map."""
    if by_seq is None:
        by_seq = {e["seq"]: e for e in log.entries()}
    out = []
    for l in links:
        c = by_seq.get(l["seq"])
        if not c:
            continue
        start = by_seq.get(c.get("start_seq"), {})
        inp = start.get("input", {})
        if not isinstance(inp, dict):
            inp = {"input": inp}
        # Keep the keys: "password=..." / "key: value" rules only fire with the key present.
        raw = " ".join(f"{k}={v}" for k, v in inp.items())
        summary = sm.mask_text(raw, literals)[:300]
        out.append({"seq": l["seq"], "entry_hash": c["entry_hash"], "link": l["link"],
                    "agent": l.get("agent", ""), "tool": l.get("tool", ""),
                    "input_summary": summary, "is_error": c.get("is_error"),
                    "output_sha256": c.get("output_sha256"), "truncated": c.get("truncated")})
    return out


def command_log_summary(evidence_dir):
    v = cl.verify(evidence_dir)
    return {"verify_status": v["status"], "head_seq": v["head"]["seq"],
            "head_hash": v["head"]["entry_hash"], "entry_count": v["entry_count"],
            "gaps": v["gaps"]}


def _read_excerpt(evidence_dir, output_file, excerpt_bytes):
    if not output_file:
        return "(output not stored)"
    p = evidence_dir / output_file
    if not p.is_file():
        return "(output file missing)"
    with p.open("rb") as fh:
        data = fh.read(excerpt_bytes)
    return data.decode("utf-8", errors="replace")


def render_appendix(evidence_dir, *, engagement_id, findings, excerpt_bytes=4096, literals=()):
    from pathlib import Path
    evidence_dir = Path(evidence_dir)
    log = cl.CommandLog(evidence_dir, engagement_id)
    by_seq = {e["seq"]: e for e in log.entries()}
    lines = ["# Command Evidence", "",
             "Secrets below are masked for presentation; hashes refer to the unmasked "
             "originals recorded in the command log.", ""]
    for f in findings:
        sev = str(f.get("severity") or "")
        lines.append(f"## {f['title']}  ({sev.upper()})")
        links = f.get("links") or []
        if not links:
            if sev.lower() in AUTO_SEVERITIES:
                lines.append("")
                lines.append("> **Unsupported:** no command evidence is linked to this finding.")
            lines.append("")
            continue
        for ev in finding_evidence(log, links, literals, by_seq):
            c = by_seq.get(ev["seq"], {})
            excerpt = sm.mask_text(_read_excerpt(evidence_dir, c.get("output_file"), excerpt_bytes), literals)
            lines += [
                f"- **seq {ev['seq']}** ({ev['link']}) — agent `{ev['agent']}`, tool `{ev['tool']}`"
                + ("  _[error]_" if ev["is_error"] else ""),
                f"  - command: `{ev['input_summary']}`",
                f"  - output sha256: `{ev['output_sha256']}`"
                + ("  _(truncated)_" if ev["truncated"] else ""),
                f"  - entry hash: `{ev['entry_hash']}`",
                "", "  ```", "  " + excerpt.replace("\n", "\n  ").rstrip(), "  ```", "",
            ]
    s = command_log_summary(evidence_dir)
    lines += ["---", "## Integrity",
              f"- verify status: **{s['verify_status']}**",
              f"- chain head: seq {s['head_seq']}, entry_hash `{s['head_hash']}`",
              f"- entries: {s['entry_count']}"]
    if s["gaps"]:
        lines.append("- gaps:")
        for g in s["gaps"]:
            lines.append(f"  - {g.get('type')} at seq {g.get('seq')}")
    lines += [f"- re-verify: `GET /api/command-log/{engagement_id}/verify` "
              f"or `python verify_command_log.py <evidence-dir>`", ""]
    return "\n".join(lines)
