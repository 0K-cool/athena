# BUG: PE Agent Never Spawned — Concurrency Queue + Tier Limit

**Date:** March 27, 2026
**Severity:** HIGH — Missing PTES phase (Post-Exploitation)
**Status:** PARTIALLY FIXED — Queue API fixed (8b9265c), tier limit still an issue

## Problem

PE agent was never spawned during autonomous engagement (0din Server #5, eng-eb2adc). ST requested PE at 01:11:16 but it was blocked by the concurrency limit.

## Root Causes

### 1. Queue API Bug (FIXED — commit 8b9265c)
Concurrency limit code used `self._agent_request_queue.append()` but `_agent_request_queue` is `asyncio.Queue` which uses `.put_nowait()`. The `AttributeError` was caught silently, so PE was never queued.

### 2. Standard Tier Too Low for Full PTES (NOT FIXED)
Standard tier allows 5 concurrent agents. A full PTES engagement needs:
- ST (always running as coordinator)
- AR (recon)
- DA (analysis)
- EX (exploitation)
- VF (verification)
= **5 agents → no room for PE**

When PE is requested, the concurrency limit blocks it. Even with the queue fix, PE won't spawn until one of the 5 running agents completes.

## Impact

- No post-exploitation phase — no lateral movement, no privilege escalation
- PTES methodology incomplete (Phase 6 skipped)
- ST explicitly recommended "PE post-exploit on 5 root shells" but couldn't spawn it
- Client reports would show incomplete methodology coverage

## Proposed Fixes

1. **Raise Standard tier from 5 → 6** — allows full PTES (ST+AR+DA+EX+VF+PE)
2. **Smart agent lifecycle** — DA and AR should complete before PE is needed, freeing slots
3. **Priority queuing** — PE should have higher priority than continuing AR scans
4. **Auto-spawn PE after VF completes** — VF finishing frees a slot, PE takes it
5. **Consider that RP also needs a slot** — full PTES needs 7 agents total (ST+AR+DA+EX+VF+PE+RP), but they don't all run simultaneously

## Recommended Fix

Raise Standard tier from 5 → 6 max agents. On M1 Air with 8 cores, 6 concurrent Claude SDK sessions is feasible. The agents are I/O bound (waiting for Kali tool responses), not CPU bound.
