# Dedup V3 — Deep Research Needed for Remaining Cross-Path Duplicates

**Date:** March 28, 2026
**Severity:** MEDIUM — Data quality, report accuracy
**Status:** RESEARCH NEEDED — Dedicated session
**Predecessor:** Dedup V1 (fingerprint MERGE) → V2 (input normalization) → V3 (this)

## Current State After V2

42 findings on Metasploitable 2 — down from ~82 (V1) and ~120 (pre-V1). ~45% reduction but duplicates persist.

### Remaining Duplicate Sources

**Source 1: Multi-CVE Batch Findings**
Bus messages dump multiple CVEs in one finding title:
- `bus-11801d9f7db8`: Contains CVE-2011-2523, CVE-2007-2447, CVE-2010-2075, CVE-2004-2687, CVE-2018-15473
- Fingerprinted on FIRST CVE only (Tier 3)
- Individual findings for each CVE from DA/EX get separate fingerprints
- Result: CVE-2011-2523 appears in BOTH the batch and as 6 individual findings = 7 copies

**Source 2: Cross-Path Fingerprint Divergence (Reduced but Not Eliminated)**
Despite V2 title normalization (`_fp_title`) and CVE normalization (`_canonical_cve`), some findings still diverge:
- Bus: `msg.summary = "Root shell via vsftpd 2.3.4 backdoor CVE-2011-2523"` → Tier 3 fingerprint on CVE-2011-2523
- POST: `payload.title = "CVE-2011-2523: vsftpd 2.3.4 Backdoor Command Execution"` → same Tier 3 fingerprint
- These SHOULD merge (same CVE) — but `bus-554af2fdf733` and `find-a8a4ce8c` both exist. Why?

**Source 3: 8-char Hex ID Findings**
EX creates findings via `POST /api/findings` → UUID8 IDs (`b266a79f`, `dba5875d`). These should merge with bus findings for the same CVE but some don't. Needs investigation of whether `_compute_finding_fingerprint` inputs are truly identical.

## Evidence (eng-8899fe, March 28, 2026)

| CVE | Copies | Paths |
|---|---|---|
| CVE-2011-2523 | 7 | batch bus + 3 bus + DA POST + 2 EX POST |
| CVE-2010-2075 | 5 | batch bus + 2 bus + DA POST + EX POST |
| CVE-2004-2687 | 5 | batch bus + 2 bus + DA POST + WV POST |
| CVE-2007-2447 | 4 | batch bus + bus + DA POST + EX POST |
| CVE-2018-15473 | 3 | batch bus + bus + DA POST |

## Research Questions

1. **Why don't same-CVE findings merge across paths?** If both bus and POST use `MERGE (f:Finding {fingerprint, engagement_id})` and both call `_compute_finding_fingerprint` with the same CVE → they should produce the same fingerprint → same Neo4j node. **Are the fingerprints actually different?** Need to log fingerprint values from both paths and compare.

2. **Should multi-CVE batch findings be split?** If bus agent dumps "5 CVEs detected: CVE-A, CVE-B, CVE-C..." as one finding, should we split it into 5 individual findings at ingestion? Or mark the batch as a "summary" finding and exclude from dedup?

3. **Are there timing/race conditions?** If bus and POST fire near-simultaneously, the MERGE might run concurrently — Neo4j MERGE is atomic per-node but two concurrent MERGEs with the same key should still converge. Unless one commits before the other reads.

4. **Is the engagement_id matching correctly?** If one path passes `eid` and the other passes `payload.engagement`, do they resolve to the same string?

## Proposed Research Approach

1. **Add fingerprint logging:** In both `_bus_to_neo4j` and `create_finding`, log the fingerprint value + all inputs: `logger.info("FINGERPRINT: %s from title=%s cve=%s host=%s port=%s eid=%s", fingerprint, title, cve, host_ip, port, eid)`
2. **Run engagement, collect logs**
3. **Compare fingerprints:** For same CVE, do bus and POST produce the same fingerprint? If not, which input differs?
4. **Design fix based on findings** — not assumptions

## Potential Fix Directions

**Direction A: Batch finding splitting** — Split multi-CVE bus findings at ingestion. Each CVE becomes its own finding with its own fingerprint. Eliminates the "batch covers 5 CVEs" problem.

**Direction B: CVE-level MERGE** — Instead of fingerprinting on title+CVE+host+port, add a second MERGE on just `{cve, host_ip, engagement_id}`. This would catch cross-path duplicates regardless of title differences.

**Direction C: Post-ingestion dedup** — After all findings are written, run a periodic dedup job that merges findings with the same CVE+host. Simplest approach but adds latency.

**Direction D: Unified creation function** — Route ALL finding writes through a single `create_or_merge_finding()` function. Eliminates input divergence by construction. Most architecturally sound but largest refactor.

## Session Stats

| Version | Findings on Metasploitable 2 | Reduction |
|---|---|---|
| Pre-V1 | ~120 | Baseline |
| V1 (fingerprint MERGE) | ~63-82 | ~35% |
| V2 (input normalization) | ~42 | ~65% |
| Target (unique vulns) | ~25-30 | ~75-80% |
