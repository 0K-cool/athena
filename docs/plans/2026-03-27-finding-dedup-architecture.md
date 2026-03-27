# ATHENA Finding Dedup Architecture — Proper Implementation

**Date:** March 27, 2026
**Author:** Kelvin + Vex
**Status:** PLANNED — Next session priority
**Research:** `output/research/2026-03-26-pentest-deduplication-strategies.md`
**Priority:** HIGH — Required for consulting-grade and open-source release

---

## Problem

Multiple agents (AR, DA, EX, VF) all create NEW findings for the same vulnerability.
Result: 22 "confirmed exploits" on Metasploitable 2 when the real count is ~8-9.
Current patch (`_dedup_key` in exploit-stats) deduplicates at QUERY time, but the
database still has duplicate Finding nodes. This is a band-aid, not a fix.

---

## Architecture (Based on Research)

### Design Principles (Faraday + MAPTA models)
1. **Dedup at ingestion** — findings are deduplicated when created, not when queried
2. **Canonical identity** — each finding gets a `dedup_id` (SHA-256 hash) at creation
3. **MERGE not CREATE** — Neo4j uses MERGE on `dedup_id` to update existing findings
4. **VF verifies, doesn't create** — VF should set `verified=true` on existing findings, not create new Finding nodes
5. **Never dedup across different hosts** — same CVE on host A and host B are separate findings

### Dedup ID Computation
```python
dedup_id = SHA256(
    CVE or service_canonical,  # What
    host_ip,                    # Where (host)
    port,                       # Where (port)
)
```

For non-CVE findings:
```python
dedup_id = SHA256(
    service_canonical,  # "mysql", "postgresql", "ingreslock"
    host_ip,
    port,
)
```

### Finding Lifecycle
```
AR discovers port 3306 (MySQL) → finding_pipeline creates Finding with dedup_id
DA researches CVE-2011-2523 (vsftpd) → finding_pipeline MERGES (updates existing or creates new)
EX exploits MySQL root → finding_pipeline MERGES, sets evidence + exploit_method
VF verifies MySQL root → finding_pipeline MERGES, sets verified=true + confirmed_at
```

Each agent enriches the SAME finding node instead of creating duplicates.

---

## Implementation Plan

### Files to Modify

1. **finding_pipeline.py** (~50 lines)
   - Add `compute_dedup_id(title, host, port)` function
   - Modify `validate_finding()` to compute and attach `dedup_id`
   - Modify Neo4j write to use MERGE on `dedup_id` instead of CREATE

2. **server.py** (~20 lines)
   - Finding creation endpoints: use `dedup_id` from pipeline
   - Remove query-time `_dedup_key()` from exploit-stats (no longer needed)
   - Keep `NOT_EXPLOIT_PATTERNS` filter (still useful for noise)

3. **agent_configs.py** (~15 lines)
   - VF prompt: instruct VF to reference existing finding IDs when verifying
   - VF should POST to `/api/verification/result` with finding_id, not create new findings
   - EX prompt: include finding_id from DA/AR when exploiting known vulnerabilities

4. **Finding model** (server.py ~5 lines)
   - Add `dedup_id: Optional[str] = None` to Finding class
   - Add `verified: bool = False` and `verification_status: str = ""` fields

### Build Sequence

| Step | What | Risk |
|------|------|------|
| 1 | Add `dedup_id` to Finding model | Low — new optional field |
| 2 | Add `compute_dedup_id()` to finding_pipeline.py | Low — new function |
| 3 | Modify Neo4j CREATE → MERGE on dedup_id | Medium — must not lose data |
| 4 | Update VF prompt to verify existing findings | Medium — prompt change |
| 5 | Remove query-time dedup from exploit-stats | Low — after steps 1-4 work |
| 6 | Test with full engagement on Metasploitable | — |

### Regression Tests

1. Run autonomous engagement — confirm findings are deduplicated
2. Run sprint engagement — confirm parallel EX findings are deduplicated
3. Verify Server #4 (5 confirmed) stays at 5 (not reduced by new dedup)
4. Verify VF verification cards still appear in dashboard
5. Verify MTTE/TTFS still calculate correctly
6. Verify finding count in sidebar matches KPI card

---

## What NOT to Change

- Sprint Mode mechanics (auto-stop, parallel EX, badges)
- Clock/KPI behavior
- Agent spawning and lifecycle
- Neo4j schema for Engagement, Host, Service nodes
- The finding creation API contract (backward compatible)

---

## Success Criteria

| Metric | Before | After |
|--------|--------|-------|
| Metasploitable confirmed exploits | 16-22 (inflated) | 8-10 (accurate) |
| Finding nodes in Neo4j | 110 (duplicated) | ~30-40 (unique per service:host:port) |
| VF verification | Creates new findings | Updates existing findings |
| Report accuracy | Overstates risk | Accurate exploit count |

---

## References

- Research: `output/research/2026-03-26-pentest-deduplication-strategies.md`
- DefectDojo dedup: hash_code algorithm with configurable fields per scanner
- Faraday model: host-first normalization, name+port+service dedup
- MAPTA (arXiv): PoC-gate model eliminates phantom duplicates
- GitLab: location fingerprint + identifier matching (never dedup CWE alone)
