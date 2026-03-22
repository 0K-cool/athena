# Orphan Claude Processes After Fire-and-Forget Cancel

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** HIGH — orphans post stale events to new engagements

## Problem

Our fire-and-forget cancel fix (don't await cancelled tasks in pause/stop) leaves `claude` subprocess processes alive after engagement ends. These orphans continue running and can post events to new engagements, causing stale/phantom data.

## Evidence

- PID 40954: Running since Friday, 110+ min CPU, posted AR event to brand new engagement
- PID 45594: Running since Thursday, orphan from prior ATHENA session

## Root Cause

`sdk_agent.py` `pause()` and `stop()` call `self._query_task.cancel()` but don't await the task. The task's `claude` subprocess continues running because:
1. `cancel()` sends CancelledError but subprocess I/O blocks delivery
2. Without `await`, the task's `finally` block (which kills the subprocess) never runs
3. The subprocess persists as an orphan

## Fix Options

### Option A: Kill subprocess directly on stop (recommended)
In `stop()` and `pause()`, after `cancel()`, also kill the `claude` subprocess directly:
```python
if hasattr(self, '_process') and self._process:
    self._process.terminate()
```
This doesn't require awaiting — `terminate()` sends SIGTERM immediately.

### Option B: Process cleanup in stop_engagement endpoint
In `server.py` `stop_engagement()`, after the fire-and-forget cancel, add:
```python
# Kill ALL orphaned claude processes for this engagement
import subprocess
subprocess.run(['pkill', '-f', f'claude.*{eid}'], capture_output=True)
```
This is already partially implemented (BUG-043 fix at line ~708 in agent_session_manager.py).

### Option C: Periodic orphan reaper
A background task that checks for `claude` processes not associated with any active session and kills them. Runs every 60 seconds.

### Recommendation
Option A + B: Kill subprocess directly in stop() AND run pkill cleanup as defense-in-depth.

## Impact

- Stale events appear in new engagements
- CPU/memory waste from zombie processes
- Potential API token consumption from orphaned SDK queries
