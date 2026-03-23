# Messages to Unspawned Agents — ST Should Decide

**Created:** 2026-03-22
**Status:** Feature request
**Priority:** MEDIUM

## Problem

AR sends service inventory to DA via bilateral message, but DA was never spawned by ST. The message sits in a queue nobody reads. The AR → DA DISCOVERY card shows in the drawer but DA's chip never lights up.

## Current Behavior

- AR sends `POST /api/messages` with `to_agent: "DA"`
- Message queues in the message bus
- DA never spawned → message never processed
- AR doesn't know DA is offline

## Proposed Behavior

When a bilateral message targets an agent that is NOT running:

1. Message bus detects `to_agent` is not in active agents
2. Forwards the message to ST instead:
   "AR sent intel to DA, but DA is not running. Spawn DA to process?
    Content: [31 services, 4 priority CVEs]"
3. ST decides:
   - Spawn DA → DA receives the queued message on startup
   - Ignore → ST absorbs the intel directly
4. ST stays in control — no auto-spawning behind ST's back

## Why Not Auto-Spawn

- ST may have intentionally skipped DA (adaptive strategy)
- Auto-spawning overrides ST's decisions
- Budget implications — spawning costs API tokens
- ST needs to control agent count (too many parallel = chaos)

## Implementation

In `server.py` or `agent_session_manager.py`, the bilateral message handler should:
```python
if to_agent not in active_agents:
    # Redirect to ST with spawn recommendation
    st_session.send_command(
        f"{from_agent} sent intel to {to_agent}, but {to_agent} is not running. "
        f"Spawn {to_agent}? Content: {message[:200]}"
    )
```
