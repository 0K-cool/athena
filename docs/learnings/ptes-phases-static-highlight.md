# PTES Phases Widget Shows Static Coverage, Not Actual Activity

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** MEDIUM — misleading to operator

## Problem

The PTES Phases widget at the bottom of the dashboard shows all phases as "Covered" based on tool/methodology definitions — not based on which agents have actually run in the current engagement. EXPLOITATION shows as highlighted even though EX hasn't been spawned yet.

## Expected

Phase coverage should be DYNAMIC — reflect actual agent activity:
- **Covered (green):** Agent for this phase has run AND produced results
- **Partial (yellow):** Agent spawned but still running or had errors
- **No Coverage (grey):** Agent for this phase has NOT been spawned yet

## Fix

Update the PTES coverage logic in `index.html` to check agent status:
- Map PTES phases to agents: Pre-Engagement→ST, Intel Gathering→PR/AR, Threat Modeling→DA, Vuln Analysis→WV, Exploitation→EX, Post-Exploitation→PE, Reporting→RP
- Query `/api/agents/status` or check agent chip states
- Only mark "Covered" if the mapped agent has `tool_calls > 0`
