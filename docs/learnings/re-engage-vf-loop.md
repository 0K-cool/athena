# Re-Engage VF Verification Loop

**Created:** 2026-03-20
**Status:** Pending fix
**Priority:** MEDIUM — Only affects re-engage flow, not fresh engagements
**Discovered during:** Beta test monitoring, Gym website re-engagement

## Problem

When re-engaging an existing engagement (Clear & Re-engage), VF enters a verification loop — repeatedly re-verifying the same already-confirmed findings.

**Observed behavior:**
- VF's own thinking: "Another duplicate verification request. This is the 5th+ time I'm being asked to verify EDB-48506 RCE"
- System log: "EDB-48506 RCE verification count: 5"
- ST keeps sending "NEW VERIFICATION REQUEST — CRITICAL priority" for findings VF already confirmed

## Root Cause

Re-engage clears Neo4j state (findings, evidence) but agents retain their SDK session context. The loop is:

```
1. WV/DA rediscovers vulnerability → creates finding
2. ST sees new finding → requests VF verification
3. VF verifies → confirms (status: confirmed)
4. ST sees confirmation → but doesn't track "already requested verification for this finding"
5. ST requests VF verification again → back to step 3
```

**Why it doesn't happen on fresh engagements:** On fresh engagements, ST's session memory tracks which findings have been verified. On re-engage, Neo4j is cleared but ST's decision loop doesn't check Neo4j for existing `confirmed` status before requesting re-verification.

## Evidence from AI Drawer

```
VF thinking: "Another duplicate verification request. This is the 5th+ time
I'm being asked to verify EDB-48506 RCE. The request says..."

System: "vrf-9b7b84ee — CONFIRMED (confidence 1.0, $0.11 spent)
EDB-48506 RCE verification count: 5"

System: "Processing operator command: NEW VERIFICATION REQUEST — CRITICAL priority
Verify finding: SQL Injection in upload.php via unsani..."
```

## Impact

- Wastes AI API budget on redundant verification cycles ($0.11 per VF verification)
- VF tool call budget (100 max) consumed faster
- Clutters AI drawer with duplicate confirmation messages
- Slows overall engagement progress

## Proposed Fix Options

### Option A: ST checks Neo4j before requesting verification
In `_ST_PROMPT` (agent_configs.py), add instruction:
"Before requesting VF verification, query Neo4j to check if the finding already has status 'confirmed'. Skip verification for already-confirmed findings."

### Option B: VF rejects duplicate verification requests
In `_VF_PROMPT`, add instruction:
"If you have already verified this finding in the current session (check your conversation history), respond with 'ALREADY VERIFIED' and skip re-verification."

### Option C: Server-side dedup on verification requests
In `server.py`, the verification request endpoint should check if a verification with the same finding fingerprint already exists with status 'confirmed'. If so, return the existing result instead of spawning VF.

### Option D: Route ALL verification requests through ST (PREFERRED — architectural fix)
**Current:** Server injects verification commands directly into VF session (`server.py:9738 vf_session.send_command(...)`) — bypasses ST entirely.
**Fix:** Change `server.py:9729-9750` to send verification notifications to ST instead of VF. ST evaluates (already confirmed? priority? timing?) and requests VF only if appropriate.
- ST already has Neo4j access to check existing confirmations
- ST can batch verification requests and prioritize
- Respects the architectural principle: **ST is the coordinator, all agent decisions flow through ST**
- No direct server→worker agent communication bypass

**Implementation:**
```python
# Instead of: vf_session.send_command(verify_prompt)
# Do: st_session.send_command(f"New finding needs verification: {finding.title}...")
```

### Recommendation
**Option D** is the correct architectural fix — enforces ST as the single coordinator. Option C (server-side dedup) should be added as defense-in-depth. Options A and B are unnecessary if D is implemented correctly.

**Kelvin's directive:** No communication bypass to ST. All agent coordination must flow through ST.

## Also Observed (Related)

- **ST chip not pulsing on re-engage** — the pulsing animation is tied to `engagement_started` WS event which may not fire on re-engage
- **updateStrategyPanel null element** — 385+ console errors, pre-existing, causes ST bar to not synthesize messages properly
