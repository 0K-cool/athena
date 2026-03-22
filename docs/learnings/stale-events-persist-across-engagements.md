# Stale Events Persist Across Engagement Deletion

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** MEDIUM — confusing UX, phantom events in new engagements

## Problem

In-memory events from a deleted engagement persist in `DashboardState.events` and appear in new engagements. Creating a new 0din Server engagement showed an AR event from a prior deleted engagement.

## Root Cause

`DashboardState.events` is a flat in-memory list. When an engagement is deleted, its events are NOT cleared from this list. New engagements see stale events because the events API may not filter strictly by engagement ID, or the WebSocket replays all events regardless.

## Fix

1. **On engagement deletion:** Clear all events matching the deleted engagement_id from `state.events`
2. **On new engagement creation:** Ensure `_clearDrawerUI()` clears the timeline AND the server doesn't serve stale events
3. **Events API:** Always filter by `engagement_id` parameter — never return events from other engagements
4. **Server restart workaround:** Restarting the server flushes in-memory events (current behavior)
