# Command Evidence Log

A tamper-evident record of every command ATHENA agents run, so each finding in a
client report shows the exact commands and outputs that prove it — and so anyone
can verify after the fact that nothing was edited or removed.

## What it records

Scope: every **Kali backend** tool call (`kali_external`, `kali_internal`) and every
**host `Bash`** call. Internal ATHENA tool calls (Neo4j, dashboard API) are not logged.

Each command produces a **two-phase** record — a `start` entry (full tool input) when
the call is issued, and a `complete` entry (output hash, exit status, stored output
file) when it returns. An unmatched `start` is a visible **gap**, not a silent loss.

## Storage

Per engagement, under `engagements/active/<eid>/08-evidence/`:

- `command-log.jsonl` — one JSON object per line, **hash-chained**: each entry carries
  `prev_hash` (the previous entry's hash) and `entry_hash` = `sha256` of the entry's
  canonical JSON. Genesis `prev_hash` is 64 zeros; `seq` starts at 1 and increments by
  exactly 1. Captured output is the **full raw** tool result (never truncated), written
  before any noise filtering.
- `tool-logs/cmd-<sha256>.txt` — each command's output, stored by content hash, capped
  at 16 MB (truncation is recorded with the full-output hash).
- `command-log.spool.jsonl` — write-ahead spool used only when the server is briefly
  unreachable; the next successful call ingests it (entries marked `late`).
- `finding-links.jsonl` — finding→entry links (fallback when Neo4j is unavailable).

The server is the **single writer** (file-locked). The agent only ever writes the
spool, and only on a transport failure — logging never blocks or alters a pentest
command, and never fails silently.

## Verifying integrity

`verify` walks the chain and returns one of:

- `ok` — chain intact, no gaps.
- `ok_with_gaps` — intact but incomplete: unmatched starts, late (spooled) entries,
  missing output files, or recovered truncation, each listed.
- `broken` — tampering or corruption, with the first bad `seq` and the reason.

It detects an edited field, a deleted/inserted/reordered line, a changed output byte,
an output-path that isn't a `tool-logs/` hash path, and a truncated tail (the printed
**chain head** — final `seq` + `entry_hash` — no longer matches). `verify` is strictly
read-only.

Two ways to run it:

```bash
# Live, headless (no browser / WebSocket needed):
curl -s localhost:8080/api/command-log/<eid>/verify

# Offline, against an evidence folder, with no server running:
python verify_command_log.py engagements/active/<eid>/08-evidence
```

The offline CLI exits `0` for `ok`/`ok_with_gaps` and `2` for `broken`.

## Linking findings to evidence

Findings link to the commands that prove them, two ways:

- **cited** — an agent submits `"evidence_seqs": [<seq>, ...]` on `POST /api/findings`.
  A seq links only if it exists and is a completed command; invalid ones are dropped and
  returned in `rejected_evidence_seqs`.
- **auto** — a HIGH/CRITICAL finding with no valid citation auto-links that same agent's
  completed commands since its previous finding. Auto links are weaker evidence and are
  labelled as such.

Links are mirrored to Neo4j as `(:Finding)-[:PROVEN_BY {link}]->(:CommandEntry)` and to
`finding-links.jsonl` as the fallback.

## In the report

Report generation is deterministic — the RP (LLM) agent never transcribes hashes or
command text:

- `GET /api/engagements/<eid>/report-data` adds a masked `evidence` list per finding
  (seq, entry hash, link type, tool, input summary, output hash — no raw output) and a
  top-level `command_log` summary (verify status, chain head, entry count, gaps).
- `GET /api/engagements/<eid>/command-log/appendix` renders a deterministic
  "Command Evidence" appendix: each finding's proving commands with a masked output
  excerpt and the entry hash, ending with an **Integrity statement** (verify status,
  chain head, gaps, re-verify instructions). HIGH/CRITICAL findings with no evidence are
  flagged **Unsupported**.
- `POST /api/reports` attaches a server-computed `command_log_head` snapshot (and the
  rendered appendix); a client payload cannot forge it, and a `broken` log marks the
  report `integrity: "broken"`.

### Secret masking

Command text and output excerpts shown in the report are masked (the raw log keeps the
originals — hashes depend on them). Two layers:

1. **Literal** — every value in the engagement's credential store is masked wherever it
   appears. This is the authoritative backstop.
2. **Pattern** — command-line credential forms (`-p`, `-u user:pass`, `key=value`,
   URL userinfo, LM:NT) and output-borne secrets (PEM private-key blocks, unix crypt
   hashes, AWS keys, JWTs, `Bearer` tokens).

Pattern masking of `-p` (ports for scanners vs. password for other tools) is best-effort
over un-tokenized shell; the credential-store literal layer is the guarantee.

## API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/command-log/start` | Append a start entry → `{seq, entry_hash}` |
| POST | `/api/command-log/complete` | Append a complete entry → `{seq, entry_hash}` |
| GET | `/api/command-log/{eid}/verify` | Verify result + chain head |
| GET | `/api/command-log/{eid}/entries` | Paged entries (`?after_seq=&limit=`) |
| GET | `/api/engagements/{eid}/command-log/appendix` | Rendered evidence appendix |

Engagement IDs are validated against `^[A-Za-z0-9_-]{1,64}$`.

## Known limits

- The dashboard API is unauthenticated: the hash chain makes tampering **detectable**,
  not impossible, for anyone with filesystem access. The chain head printed in the
  delivered report is the anchor.
- `-p` ports-vs-password masking has contrived residuals (nested `$(...)`, backslash-
  escaped separators) backstopped by literal credential masking.
