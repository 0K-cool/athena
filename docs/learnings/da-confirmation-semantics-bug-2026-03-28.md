# BUG: DA Agent Marks Findings "Confirmed" Without Exploitation Evidence

**Date:** March 28, 2026
**Severity:** HIGH — Report quality, evidence integrity
**Status:** DOCUMENTED — Fix Monday

## Problem

DA (Deep Analysis) agent sets `status=confirmed` on 16 findings based on version matching and CVE research — but DA never actually exploits anything. These findings have zero evidence artifacts. In the dashboard, they inflate the "confirmed" count and appear alongside EX/VF-confirmed exploits that have real evidence.

## Evidence (eng-eb2adc, March 28, 2026)

- 37 total confirmed findings
- 21 with evidence (EX, VF, server auto-capture) — real exploitation proof
- 16 WITHOUT evidence — ALL from DA — version-match "confirmations"

## Examples of DA False Confirmations

- "CVE-2011-2523: vsftpd 2.3.4 Backdoor Command Execution" — DA found the CVE, didn't exploit it
- "MySQL 5.0 Root Account No Password" — DA identified the risk, didn't test login
- "VNC Server No/Weak Authentication - Port 5900" — DA read the service banner, didn't connect

## Impact

1. Confirmed exploit count inflated (37 vs ~21 real)
2. Confirmed Exploit Rate inflated (14% vs ~8% real)
3. Client reports mix real exploitation proof with version-match analysis
4. Evidence Gallery shows "confirmed" findings with no evidence — looks incomplete

## Root Cause

DA's prompt allows it to set `status=confirmed` when it finds a matching CVE with known exploit. DA interprets "this version is vulnerable" as "confirmed." Only EX (active exploitation) and VF (independent verification) should set confirmed.

## Proposed Fix

### Option A: DA prompt fix (probabilistic)
Add to DA prompt: "NEVER set status=confirmed. Your findings should use status=discovered or status=analyzed. Only EX and VF can confirm exploits."

### Option B: Server-side enforcement (deterministic — RECOMMENDED)
In finding_pipeline.py or the PATCH/POST endpoints:
- If `agent=DA` and `status=confirmed` → downgrade to `status=analyzed`
- Only allow `status=confirmed` from agents EX, VF, or server (auto-confirm)

### Option C: Separate confirmation tiers
- `status=discovered` — AR/WV found it
- `status=analyzed` — DA researched it, CVE matches, exploit exists
- `status=exploited` — EX successfully exploited
- `status=verified` — VF independently confirmed

Option C is the cleanest but requires schema changes.

## Files to Modify

- `agent_configs.py` — DA prompt (Option A)
- `server.py` — PATCH/POST finding endpoints (Option B)
- Report templates — distinguish "analyzed" from "confirmed" in output
