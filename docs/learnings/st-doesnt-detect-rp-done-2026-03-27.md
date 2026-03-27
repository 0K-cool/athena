# BUG: ST Doesn't Detect RP Completion — Sleeps Instead of Checking Status

**Date:** March 27, 2026
**Severity:** HIGH — Wastes 5+ minutes after reports are done
**Status:** DOCUMENTED — Not yet fixed

## Problem

RP finished generating reports (43/100 calls, session ended, debrief sent to ST) but ST continues running — sleeping 300 seconds to "wait 5 more minutes for RP." ST doesn't check RP's actual agent status, just blindly waits.

## Evidence

- RP session ended at 02:58:46 with debrief message
- ST ran `sleep 300` at 02:58:35 — will wait until ~03:03:35
- Engagement stays "running" for 5 extra unnecessary minutes
- At $8.85 cost, those 5 minutes add ~$1 in wasted ST token costs

## Root Cause

The _ST_RP_COMPLETION_GATE prompt says "WAIT for RP to finish — check agent status" but doesn't specify HOW to check. ST uses `sleep` instead of polling the agent status API.

## Proposed Fix

### Option A: Prompt improvement (probabilistic)
Add explicit check instruction: "Check RP status via GET /api/agents/status. When RP shows IDLE or DONE, immediately stop the engagement. Do NOT use sleep — poll every 30 seconds."

### Option B: Server-side enforcement (deterministic — RECOMMENDED)
When RP's session ends AND RP was the last requested agent:
1. Server detects RP completion via agent_complete event
2. Server auto-stops the engagement (same as sprint auto-stop)
3. ST doesn't need to decide — server handles it

### Option C: Debrief-triggered stop
When the server receives RP's debrief message (msg_type="debrief" from RP):
1. Check if all other agents are IDLE/DONE
2. If yes, auto-stop engagement
3. Fastest path — debrief IS the completion signal

## Files to Modify

- `server.py` — Option C: detect RP debrief in /api/messages, auto-stop if all agents done
- OR `agent_session_manager.py` — Option B: on agent_complete for RP, trigger engagement stop
- `agent_configs.py` — Option A: improve ST prompt (least reliable)
