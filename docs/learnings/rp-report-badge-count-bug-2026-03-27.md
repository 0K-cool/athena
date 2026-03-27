# BUG: Reports Badge Shows 1 When 2+ Reports Exist

**Date:** March 27, 2026
**Severity:** MEDIUM — Dashboard displays stale count
**Status:** DOCUMENTED — Beta test when API stable

## Problem

RP wrote 2 reports but the Reports sidebar badge only showed 1. The badge count didn't update when the second report was generated.

## Likely Root Cause Candidates

1. **Badge reads from initial load, not WebSocket updates** — Reports badge set on page load from `/api/reports` count, but RP's second report event doesn't trigger a badge refresh
2. **WebSocket event for new report not incrementing counter** — the `report_generated` event may update the Reports page but not the sidebar badge
3. **Race condition** — badge updates from a stale API response while RP is actively writing
4. **RP writes to disk but doesn't POST to /api/reports** — second report may be written as a file but never registered via the API

## Where to Look

- `index.html` — sidebar badge update logic (search for `reports-badge` or `report-count`)
- `server.py` — `/api/reports` endpoint, WebSocket `report_generated` event
- `agent_configs.py` — RP prompt, does it POST each report to the API or just write files?

## How to Verify

1. Run engagement to completion (RP phase)
2. Watch Reports badge as RP writes each report
3. Check: does badge increment on each `report_generated` WebSocket event?
4. Check: does `/api/reports?engagement=eng-XXX` return correct count?
