# Phase F: Claude Agent SDK Migration

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the subprocess-based Claude CLI spawning with the Claude Agent SDK for interactive, multi-turn operator control of the AI pentest team.

**Architecture:** The ATHENA server maintains an SDK agent session per engagement. Operator commands are injected as new turns in the same session, giving Claude full context of what it scanned, found, and reported. HITL approvals become native SDK tool callbacks instead of REST polling loops.

**Tech Stack:** `claude-agent-sdk` (Python), FastAPI (existing), asyncio, WebSocket (existing)

---

## Why

The current architecture spawns `claude -p` as a one-shot subprocess. This means:
- Operator commands never reach the AI agent (responses are canned strings)
- No multi-turn interaction — the agent is deaf after launch
- HITL approvals require Claude to poll REST endpoints every 5s
- Pause/resume doesn't actually pause the Claude process
- All events are labeled "Orchestrator" regardless of which logical agent is executing
- No way to cancel mid-tool-execution

The Agent SDK solves all of these natively.

---

## Current State (Phase E)

| Component | Implementation | Lines |
|-----------|---------------|-------|
| Process spawn | `subprocess.Popen(claude_bin, "-p", ...)` | server.py:4001-4029 |
| Output parsing | `_stream_ai_output` reads stdout NDJSON | server.py:3761-3880 |
| Process control | `_ai_process.terminate()` / `.kill()` | server.py:4070-4076 |
| Operator commands | Canned `_generate_command_response()` | server.py:4696-4731 |
| HITL approvals | Claude polls `GET /api/approvals/{id}` | server.py:824-848 |
| Agent identity | Hardcoded `agent_code = "OR"` | server.py:3764 |
| Prompt | Single f-string with all PTES phases | server.py:3949-3999 |

---

## Target State (Phase F)

| Component | SDK Implementation |
|-----------|-------------------|
| Agent session | `query()` with `session_id` resume |
| Output streaming | Async generator → WebSocket broadcast |
| Process control | `asyncio.Task.cancel()` — cooperative |
| Operator commands | `query(prompt=cmd, resume=session_id)` — full context |
| HITL approvals | SDK tool callback blocks until operator resolves |
| Agent identity | Per-agent SDK calls with explicit agent code |
| Prompt | Structured system prompt + per-phase tool sets |

---

## Tasks

### Task 1: Install SDK and Validate

**Files:**
- Modify: `tools/athena-dashboard/requirements.txt`
- Create: `tools/athena-dashboard/test_sdk.py`

**Step 1: Install the SDK in the dashboard venv**

```bash
cd tools/athena-dashboard
.venv/bin/pip install claude-agent-sdk
```

**Step 2: Write a minimal validation script**

```python
# test_sdk.py
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    async for msg in query(
        prompt="What is 2+2? Reply with just the number.",
        options=ClaudeAgentOptions(
            allowed_tools=[],
            model="haiku",
        )
    ):
        print(f"Type: {type(msg).__name__}, Content: {msg}")

asyncio.run(main())
```

**Step 3: Run and verify**

```bash
.venv/bin/python test_sdk.py
```
Expected: SDK connects, Claude responds "4", clean exit.

**Step 4: Verify session resume works**

```python
# test_sdk_resume.py
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    session_id = None
    # Turn 1
    async for msg in query(
        prompt="Remember the word 'PINEAPPLE'. Confirm you have it.",
        options=ClaudeAgentOptions(model="haiku")
    ):
        if hasattr(msg, 'session_id'):
            session_id = msg.session_id
        if hasattr(msg, 'result'):
            print(f"Turn 1: {msg.result}")

    # Turn 2 — resume
    async for msg in query(
        prompt="What word did I ask you to remember?",
        options=ClaudeAgentOptions(resume=session_id, model="haiku")
    ):
        if hasattr(msg, 'result'):
            print(f"Turn 2: {msg.result}")

asyncio.run(main())
```

Expected: Turn 2 returns "PINEAPPLE" — proving context preservation.

**Step 5: Commit**

```bash
git add requirements.txt test_sdk.py test_sdk_resume.py
git commit -m "feat(phase-f): Install Claude Agent SDK and validate multi-turn sessions"
```

---

### Task 2: Create SDK Agent Wrapper Class

**Files:**
- Create: `tools/athena-dashboard/sdk_agent.py`
- Test: `tools/athena-dashboard/test_sdk_agent.py`

**Step 1: Write the failing test**

```python
# test_sdk_agent.py
import asyncio
import pytest
from sdk_agent import AthenaAgentSession

@pytest.mark.asyncio
async def test_session_lifecycle():
    session = AthenaAgentSession(
        engagement_id="eng-test",
        target="https://example.com",
        backend="external",
    )
    assert session.session_id is None
    assert session.is_running is False
```

**Step 2: Run test to verify it fails**

```bash
.venv/bin/pytest test_sdk_agent.py -v
```
Expected: FAIL — `sdk_agent` module not found.

**Step 3: Implement `AthenaAgentSession`**

```python
# sdk_agent.py
"""Claude Agent SDK wrapper for ATHENA AI engagements."""
import asyncio
from typing import AsyncGenerator, Callable, Optional
from claude_agent_sdk import query, ClaudeAgentOptions

class AthenaAgentSession:
    """Manages a multi-turn Claude Agent SDK session for one engagement."""

    def __init__(self, engagement_id: str, target: str, backend: str = "external"):
        self.engagement_id = engagement_id
        self.target = target
        self.backend = backend
        self.session_id: Optional[str] = None
        self.is_running = False
        self._task: Optional[asyncio.Task] = None
        self._event_callback: Optional[Callable] = None

    def set_event_callback(self, callback: Callable):
        """Set callback for streaming events to WebSocket."""
        self._event_callback = callback

    async def start(self, system_prompt: str) -> str:
        """Start the engagement. Returns session_id."""
        self.is_running = True
        async for msg in query(
            prompt=system_prompt,
            options=ClaudeAgentOptions(
                model="sonnet",
                allowed_tools=[
                    "Bash", "Read", "Write", "Edit",
                    f"mcp__kali_{self.backend}__*",
                    "mcp__athena_neo4j__*",
                ],
                permission_mode="acceptEdits",
                mcp_servers={
                    f"kali_{self.backend}": {
                        # MCP server config inherited from .mcp.json
                    },
                    "athena_neo4j": {},
                },
            )
        ):
            if hasattr(msg, 'session_id') and not self.session_id:
                self.session_id = msg.session_id
            if self._event_callback:
                await self._event_callback(msg)
        self.is_running = False
        return self.session_id

    async def send_command(self, command: str) -> str:
        """Send operator command to the running session."""
        if not self.session_id:
            raise RuntimeError("No active session")
        result = None
        async for msg in query(
            prompt=command,
            options=ClaudeAgentOptions(resume=self.session_id)
        ):
            if self._event_callback:
                await self._event_callback(msg)
            if hasattr(msg, 'result'):
                result = msg.result
        return result or ""

    async def stop(self):
        """Stop the session."""
        self.is_running = False
        if self._task and not self._task.done():
            self._task.cancel()
```

**Step 4: Run test to verify it passes**

```bash
.venv/bin/pytest test_sdk_agent.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add sdk_agent.py test_sdk_agent.py
git commit -m "feat(phase-f): AthenaAgentSession wrapper for Claude Agent SDK"
```

---

### Task 3: Build Event Translator (SDK → WebSocket)

**Files:**
- Modify: `tools/athena-dashboard/sdk_agent.py`
- Test: `tools/athena-dashboard/test_event_translator.py`

The SDK emits its own event types. We need to translate them to the existing WebSocket event format that the dashboard expects (agent_status, tool_start, tool_complete, agent_thinking, system, finding).

**Step 1: Write the failing test**

```python
# test_event_translator.py
from sdk_agent import translate_sdk_event

def test_tool_use_event():
    sdk_event = {"type": "tool_use", "name": "Bash", "input": {"command": "nmap -sV target"}}
    ws_event = translate_sdk_event(sdk_event, agent_code="PO")
    assert ws_event["type"] == "tool_start"
    assert ws_event["agent"] == "PO"
    assert ws_event["metadata"]["tool"] == "Bash"
```

**Step 2: Implement `translate_sdk_event`**

Map SDK event types → ATHENA dashboard event types:

| SDK Event | Dashboard Event | Notes |
|-----------|----------------|-------|
| `tool_use` | `tool_start` | Extract tool name, input |
| `tool_result` | `tool_complete` | Extract output, truncate |
| `text` / `assistant` | `system` or `agent_thinking` | Parse for findings patterns |
| `init` | Capture `session_id` | Internal only |
| `result` | `system` (completion) | Final summary |

**Step 3: Add agent code detection heuristic**

Infer which ATHENA agent is active based on tool names and prompt context:
- `nmap`, `httpx`, `amass` → PO (Passive OSINT)
- `nuclei`, `nikto` → WV (Web Vuln Scanner)
- `sqlmap`, `exploit` → EX (Exploitation)
- `POST /api/approvals` → EX (Exploitation requesting HITL)
- Default → OR (Orchestrator)

**Step 4: Commit**

```bash
git add sdk_agent.py test_event_translator.py
git commit -m "feat(phase-f): Event translator — SDK events to dashboard WebSocket format"
```

---

### Task 4: Replace `start_engagement_ai` with SDK Session

**Files:**
- Modify: `tools/athena-dashboard/server.py` (lines 3883-4059)
- Modify: `tools/athena-dashboard/sdk_agent.py`

**Step 1: Add `_active_session` global**

Replace `_ai_process: subprocess.Popen` with `_active_session: AthenaAgentSession`.

**Step 2: Rewrite `start_engagement_ai`**

```python
@app.post("/api/engagement/{eid}/start-ai")
async def start_engagement_ai(eid: str, backend: str = "external", target: str = ""):
    global _active_session
    # ... target resolution (keep existing logic) ...

    # Stop any existing session
    if _active_session and _active_session.is_running:
        await _active_session.stop()

    _active_session = AthenaAgentSession(eid, target, backend)
    _active_session.set_event_callback(lambda msg: _broadcast_sdk_event(msg, eid))

    # Launch in background task
    prompt = _build_engagement_prompt(eid, target, backend)
    asyncio.create_task(_run_sdk_engagement(_active_session, prompt, eid))

    return {"ok": True, "engagement_id": eid, "mode": "ai-sdk"}
```

**Step 3: Extract prompt builder**

Move the prompt f-string into `_build_engagement_prompt(eid, target, backend)` function. Simplify it — remove REST polling instructions for HITL (SDK handles natively).

**Step 4: Delete `_stream_ai_output` function**

Remove lines 3761-3880 entirely. The SDK event translator replaces it.

**Step 5: Commit**

```bash
git add server.py sdk_agent.py
git commit -m "feat(phase-f): Replace subprocess spawn with Agent SDK session"
```

---

### Task 5: Wire Operator Commands to SDK Session

**Files:**
- Modify: `tools/athena-dashboard/server.py` (WebSocket handler, lines 613-631)

**Step 1: Replace canned response with SDK call**

```python
elif msg_type == "operator_command":
    cmd_text = msg.get("content", "").strip()
    if cmd_text:
        await state.broadcast({
            "type": "operator_command",
            "content": cmd_text,
            "timestamp": time.time(),
        })
        if _active_session and _active_session.session_id:
            # Real AI response via SDK session resume
            asyncio.create_task(_handle_operator_command(cmd_text))
        else:
            # Fallback: canned response if no active session
            response = _generate_command_response(cmd_text)
            await state.broadcast({
                "type": "operator_response",
                "agent": "OR",
                "agentName": "Orchestrator",
                "content": response,
                "timestamp": time.time(),
            })
```

**Step 2: Implement `_handle_operator_command`**

```python
async def _handle_operator_command(cmd_text: str):
    result = await _active_session.send_command(cmd_text)
    await state.broadcast({
        "type": "operator_response",
        "agent": "OR",
        "agentName": "Orchestrator",
        "content": result,
        "timestamp": time.time(),
    })
```

**Step 3: Delete `_generate_command_response` function**

Keep as fallback for when no SDK session is active, but the primary path is now real AI.

**Step 4: Commit**

```bash
git add server.py
git commit -m "feat(phase-f): Operator commands forwarded to Agent SDK session"
```

---

### Task 6: Native HITL Approval via SDK Callbacks

**Files:**
- Modify: `tools/athena-dashboard/sdk_agent.py`
- Modify: `tools/athena-dashboard/server.py`

**Step 1: Implement tool approval callback in SDK options**

Instead of Claude polling `GET /api/approvals/{id}`, the SDK can natively pause on tool execution and wait for approval:

```python
async def _tool_approval_handler(tool_name: str, tool_input: dict) -> bool:
    """SDK callback — blocks until operator approves or rejects."""
    # Only require approval for exploitation tools
    exploit_tools = ["sqlmap", "metasploit", "exploit", "hydra"]
    if not any(t in tool_name.lower() for t in exploit_tools):
        return True  # Auto-approve non-exploit tools

    # Create HITL request and wait
    req = ApprovalRequest(...)
    await state.request_approval(req)

    # Block here until operator resolves via WebSocket
    event = asyncio.Event()
    state.approval_events[req.id] = {"event": event, "approved": False}
    await event.wait()
    return state.approval_events[req.id]["approved"]
```

**Step 2: Wire into SDK options**

Pass the callback as the tool approval handler in `ClaudeAgentOptions`.

**Step 3: Remove REST polling from prompt**

Delete the "poll GET /api/approvals/{id}" instructions. The SDK handles this natively.

**Step 4: Commit**

```bash
git add sdk_agent.py server.py
git commit -m "feat(phase-f): Native HITL approval via SDK tool callbacks"
```

---

### Task 7: Pause/Resume via SDK

**Files:**
- Modify: `tools/athena-dashboard/server.py` (pause/resume endpoints)
- Modify: `tools/athena-dashboard/sdk_agent.py`

**Step 1: Implement cooperative pause**

Add an `asyncio.Event` gate in `AthenaAgentSession` that the event callback checks before forwarding. When paused, the SDK continues but events are buffered. On resume, buffered events flush.

Alternative (better): SDK sessions can be paused by not calling `query()` for the next turn. Since the SDK is turn-based, the agent naturally pauses between turns.

**Step 2: Update `pause_engagement` endpoint**

Set `_active_session.paused = True`. The next time the SDK yields control (between tool calls), it checks the pause flag.

**Step 3: Update `stop_engagement` endpoint**

Cancel the asyncio task wrapping the SDK session. Clean shutdown.

**Step 4: Commit**

```bash
git add server.py sdk_agent.py
git commit -m "feat(phase-f): Cooperative pause/resume for SDK sessions"
```

---

### Task 8: Per-Agent Identity in Events

**Files:**
- Modify: `tools/athena-dashboard/sdk_agent.py`

**Step 1: Enhanced agent detection**

Replace the hardcoded `agent_code = "OR"` with intelligent detection:

```python
TOOL_TO_AGENT = {
    "nmap": "PO", "httpx": "PO", "amass": "PO", "gau": "PO",
    "nuclei": "WV", "nikto": "WV", "gobuster": "WV",
    "sqlmap": "EX", "hydra": "EX", "metasploit": "EX",
    "bloodhound": "PE", "linpeas": "PE", "crackmapexec": "LM",
}

def detect_agent(tool_name: str, content: str = "") -> str:
    for keyword, agent in TOOL_TO_AGENT.items():
        if keyword in tool_name.lower() or keyword in content.lower():
            return agent
    return "OR"
```

**Step 2: Emit `agent_status` events on agent transitions**

When the detected agent changes, emit `agent_status` running/idle events so dashboard LEDs update.

**Step 3: Commit**

```bash
git add sdk_agent.py
git commit -m "feat(phase-f): Per-agent identity detection for SDK events"
```

---

### Task 9: End-to-End Integration Test

**Files:**
- Create: `tools/athena-dashboard/test_e2e_sdk.py`

**Step 1: Write integration test**

```python
@pytest.mark.asyncio
async def test_full_engagement_flow():
    """Test: start engagement → operator command → HITL approval → stop."""
    # 1. Start engagement via API
    # 2. Verify session_id is returned
    # 3. Send operator command "status"
    # 4. Verify real AI response (not canned)
    # 5. Trigger HITL approval
    # 6. Resolve approval
    # 7. Stop engagement
    # 8. Verify clean shutdown
```

**Step 2: Run against test target (Juice Shop or ACME GYM)**

**Step 3: Commit**

```bash
git add test_e2e_sdk.py
git commit -m "test(phase-f): End-to-end SDK integration test"
```

---

### Task 10: Cleanup and Documentation

**Files:**
- Modify: `tools/athena-dashboard/server.py` — remove dead code
- Delete: `test_sdk.py`, `test_sdk_resume.py` (validation scripts)
- Modify: `docs/plans/` — update Phase F status

**Step 1: Remove dead code**

- Delete `_stream_ai_output` function
- Delete `_ai_process` global and all references
- Delete `CLAUDECODE` env var stripping
- Simplify `stop_engagement` (no more process.kill)

**Step 2: Update ATHENA memory notes**

**Step 3: Final commit**

```bash
git add -A
git commit -m "refactor(phase-f): Remove subprocess remnants, SDK migration complete"
```

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| SDK not yet stable for Python | Keep subprocess path as fallback (feature flag) |
| MCP tool config differs from CLI | Test each tool individually before full engagement |
| Session resume latency | Measure latency; consider keep-alive pattern |
| Token costs (multi-turn = more context) | Monitor via spend alerting hook (L17) |
| Agent SDK package name/API changes | Pin version in requirements.txt |

## Dependencies

- `claude-agent-sdk` Python package (verify exact package name on PyPI)
- MCP server configs must work from SDK context (not just CLI)
- Kali backends healthy (verified Feb 24)
- Neo4j accessible (verified Feb 24)

## Execution

**Estimated tasks:** 10
**Approach:** Subagent-driven development (one task per subagent)
**Fallback:** Keep subprocess path behind `?mode=legacy` query param until SDK path is proven
