# Dashboard Auth Hardening — Implementation Plan (Phase 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two-role (operator vs agent) Bearer-token authentication to the ATHENA dashboard's sensitive routes and WebSocket, so the in-process agent cannot resolve its own HITL approvals or destroy the audit trail.

**Architecture:** A new `auth.py` holds config + two FastAPI dependencies (`require_authenticated`, `require_operator`) using constant-time token compare. Phase 1 attaches these dependencies to the operator-only and evidence-log routes only, plus a `/ws` operator handshake. The agent's `httpx` clients send `Authorization: Bearer <agent token>` + an `X-Athena-Principal: agent` marker. Tokens come from env/1Password via `start.sh`. A mode flag (`off|phase1|enforce`) makes rollout reversible and fails closed when tokens are missing.

**Tech Stack:** Python 3.11+, FastAPI, Starlette WebSockets, `httpx`, `hmac`, pytest + pytest-asyncio (`ASGITransport` in-process client).

**Spec:** `docs/architecture/2026-10-12-dashboard-auth-hardening-design.md`

## Global Constraints

- All work is under `tools/athena-dashboard/`. Branch: `feat/dashboard-auth-hardening`.
- Token compare MUST use `hmac.compare_digest` (constant-time). Never `==`.
- **Import-time default is `off` (open).** `load_auth_config()` (real startup) is the only place that fails closed. Reason: the test harness (`tests/conftest.py`) runs the app via `ASGITransport` and does NOT trigger lifespan, so an uninitialized default of anything but `off` would break every existing route test.
- Never log token values. Log method + path + resolved role only.
- Default shipped mode: `phase1`.
- Only the operator token is popped from `os.environ`; the agent token stays in env (the agent reads it to build its client).
- Phase 2 (default-deny middleware) is OUT OF SCOPE — do not add it.
- Run tests from `tools/athena-dashboard/` with its venv: `.venv/bin/pytest`.

## Review Focus

- **Bearer header format variance** — `"bearer x"`, extra spaces, no scheme, raw token without `Bearer ` → must resolve or reject cleanly, never 500. (Task 2)
- **Dependencies invoked before init / `_config` default** — a route hit with no `load_auth_config()` call (tests, misimport) must behave as `off`/open, not crash. (Task 1, Task 3)
- **WS token missing/invalid** — `/ws?token=` absent or wrong must close with code 1008, never raise into the accept loop. (Task 6)
- **`mode=off` preserves legacy open behavior** — existing command-log/finding tests still pass with no token. (Task 5)
- **Timing/early-return on token compare** — equal-length-independent compare; no prefix short-circuit. (Task 2)

---

### Task 1: `auth.py` — config + fail-closed + environ hardening

**Files:**
- Create: `tools/athena-dashboard/auth.py`
- Test: `tools/athena-dashboard/tests/test_auth.py`

**Interfaces:**
- Produces: `class AuthConfig(mode: str, operator_token: str, agent_token: str)`;
  module global `_config: AuthConfig` (import-time default `AuthConfig("off","","")`);
  `load_auth_config() -> AuthConfig`; `set_auth_config_for_test(mode, operator_token="", agent_token="") -> None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_auth.py
import os, pytest, importlib

def fresh_auth(monkeypatch, **env):
    for k in ("ATHENA_AUTH_MODE","ATHENA_OPERATOR_TOKEN","ATHENA_AGENT_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import auth as _a
    importlib.reload(_a)
    return _a

def test_import_default_is_off_open(monkeypatch):
    a = fresh_auth(monkeypatch)
    assert a._config.mode == "off"

def test_phase1_requires_both_tokens(monkeypatch):
    a = fresh_auth(monkeypatch, ATHENA_AUTH_MODE="phase1")
    with pytest.raises(RuntimeError):
        a.load_auth_config()

def test_phase1_loads_with_tokens_and_pops_operator(monkeypatch):
    a = fresh_auth(monkeypatch, ATHENA_AUTH_MODE="phase1",
                   ATHENA_OPERATOR_TOKEN="op", ATHENA_AGENT_TOKEN="ag")
    cfg = a.load_auth_config()
    assert cfg.mode == "phase1" and cfg.operator_token == "op" and cfg.agent_token == "ag"
    assert "ATHENA_OPERATOR_TOKEN" not in os.environ   # hardening
    assert os.environ.get("ATHENA_AGENT_TOKEN") == "ag"  # agent token stays

def test_invalid_mode_raises(monkeypatch):
    a = fresh_auth(monkeypatch, ATHENA_AUTH_MODE="bogus")
    with pytest.raises(RuntimeError):
        a.load_auth_config()

def test_off_mode_warns_not_raises(monkeypatch):
    a = fresh_auth(monkeypatch, ATHENA_AUTH_MODE="off")
    assert a.load_auth_config().mode == "off"
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/pytest tests/test_auth.py -v`
Expected: FAIL (no module `auth` / attributes missing).

- [ ] **Step 3: Implement**

```python
# auth.py
"""Dashboard authentication: two-role Bearer-token auth (operator vs agent).

Import-time default is OFF (open) so the in-process test harness, which does
not trigger lifespan, keeps working. load_auth_config() is the only place that
fails closed; call it at real server startup.
"""
import hmac
import logging
import os

logger = logging.getLogger("athena.auth")

VALID_MODES = ("off", "phase1", "enforce")


class AuthConfig:
    def __init__(self, mode: str, operator_token: str, agent_token: str):
        self.mode = mode
        self.operator_token = operator_token
        self.agent_token = agent_token


# Import-time default: OFF / open. Never fail closed at import.
_config = AuthConfig("off", "", "")


def load_auth_config() -> AuthConfig:
    """Read mode + tokens from env. Fail closed (RuntimeError) in phase1/enforce
    when tokens are missing or the mode is invalid. Pops the operator token from
    os.environ after reading (hardening; friction, not a boundary)."""
    global _config
    mode = os.environ.get("ATHENA_AUTH_MODE", "phase1").strip().lower()
    if mode not in VALID_MODES:
        raise RuntimeError(f"Invalid ATHENA_AUTH_MODE={mode!r}; expected one of {VALID_MODES}")
    operator = os.environ.get("ATHENA_OPERATOR_TOKEN", "")
    agent = os.environ.get("ATHENA_AGENT_TOKEN", "")
    if mode in ("phase1", "enforce"):
        missing = [n for n, v in (("ATHENA_OPERATOR_TOKEN", operator),
                                  ("ATHENA_AGENT_TOKEN", agent)) if not v]
        if missing:
            raise RuntimeError(
                f"ATHENA_AUTH_MODE={mode} requires {missing}; refusing to start")
    else:  # off
        logger.warning("ATHENA_AUTH_MODE=off — dashboard auth DISABLED (migration only)")
    os.environ.pop("ATHENA_OPERATOR_TOKEN", None)  # hardening
    _config = AuthConfig(mode, operator, agent)
    return _config


def set_auth_config_for_test(mode: str, operator_token: str = "", agent_token: str = "") -> None:
    """Test hook: set the active config without touching env or failing closed."""
    global _config
    _config = AuthConfig(mode, operator_token, agent_token)
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/test_auth.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add tools/athena-dashboard/auth.py tools/athena-dashboard/tests/test_auth.py
git commit -m "feat(auth): auth config load with fail-closed + environ hardening"
```

---

### Task 2: `auth.py` — bearer extraction, constant-time match, role resolution

**Files:**
- Modify: `tools/athena-dashboard/auth.py`
- Test: `tools/athena-dashboard/tests/test_auth.py`

**Interfaces:**
- Produces: `_extract_bearer(authorization: str | None) -> str`;
  `_match(token: str, expected: str) -> bool`;
  `_resolve_role(token: str) -> str | None` (`"operator"`, `"agent"`, or `None`).

- [ ] **Step 1: Write the failing tests**

```python
def test_extract_bearer_variants(monkeypatch):
    a = fresh_auth(monkeypatch)
    assert a._extract_bearer("Bearer abc") == "abc"
    assert a._extract_bearer("bearer abc") == "abc"      # case-insensitive scheme
    assert a._extract_bearer("Bearer   abc  ") == "abc"  # trimmed
    assert a._extract_bearer("abc") == ""                # no scheme -> empty
    assert a._extract_bearer(None) == ""
    assert a._extract_bearer("") == ""

def test_match_constant_time(monkeypatch):
    a = fresh_auth(monkeypatch)
    assert a._match("same", "same") is True
    assert a._match("x", "y") is False
    assert a._match("x", "") is False   # empty expected never matches

def test_resolve_role(monkeypatch):
    a = fresh_auth(monkeypatch)
    a.set_auth_config_for_test("phase1", operator_token="op", agent_token="ag")
    assert a._resolve_role("op") == "operator"
    assert a._resolve_role("ag") == "agent"
    assert a._resolve_role("nope") is None
    assert a._resolve_role("") is None
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/pytest tests/test_auth.py -k "bearer or match or resolve" -v`
Expected: FAIL (functions not defined).

- [ ] **Step 3: Implement (append to `auth.py`)**

```python
def _extract_bearer(authorization: str | None) -> str:
    if not authorization:
        return ""
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return ""


def _match(token: str, expected: str) -> bool:
    # Empty expected must never match; compare_digest is constant-time for equal-length.
    return bool(expected) and hmac.compare_digest(token, expected)


def _resolve_role(token: str) -> str | None:
    if _match(token, _config.operator_token):
        return "operator"
    if _match(token, _config.agent_token):
        return "agent"
    return None
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/test_auth.py -k "bearer or match or resolve" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/athena-dashboard/auth.py tools/athena-dashboard/tests/test_auth.py
git commit -m "feat(auth): bearer extraction + constant-time role resolution"
```

---

### Task 3: `auth.py` — `require_authenticated` & `require_operator` dependencies

**Files:**
- Modify: `tools/athena-dashboard/auth.py`
- Test: `tools/athena-dashboard/tests/test_auth.py`

**Interfaces:**
- Consumes: `_resolve_role`, `_extract_bearer`, `_config` (Task 1–2).
- Produces: `async require_authenticated(request, authorization=Header(None)) -> str`;
  `async require_operator(request, authorization=Header(None)) -> str`.
  Both return the resolved role string. Raise `HTTPException(401)` on missing/invalid,
  `HTTPException(403)` on wrong role. In `mode=off` both return `"operator"` without checks.

- [ ] **Step 1: Write the failing tests** (use a throwaway FastAPI app so the dependencies run through real request plumbing)

```python
import pytest
from fastapi import FastAPI, Depends
from httpx import AsyncClient, ASGITransport

def _app_with(dep):
    app = FastAPI()
    @app.get("/probe")
    async def probe(role: str = Depends(dep)):
        return {"role": role}
    return app

@pytest.mark.asyncio
async def test_require_operator_rejects_agent(monkeypatch):
    a = fresh_auth(monkeypatch)
    a.set_auth_config_for_test("phase1", operator_token="op", agent_token="ag")
    app = _app_with(a.require_operator)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/probe", headers={"Authorization": "Bearer ag"})).status_code == 403
        assert (await c.get("/probe", headers={"Authorization": "Bearer op"})).status_code == 200
        assert (await c.get("/probe")).status_code == 401
        assert (await c.get("/probe", headers={"Authorization": "Bearer junk"})).status_code == 401

@pytest.mark.asyncio
async def test_require_authenticated_accepts_both(monkeypatch):
    a = fresh_auth(monkeypatch)
    a.set_auth_config_for_test("phase1", operator_token="op", agent_token="ag")
    app = _app_with(a.require_authenticated)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/probe", headers={"Authorization": "Bearer ag"})).json()["role"] == "agent"
        assert (await c.get("/probe", headers={"Authorization": "Bearer op"})).json()["role"] == "operator"
        assert (await c.get("/probe")).status_code == 401

@pytest.mark.asyncio
async def test_off_mode_is_open(monkeypatch):
    a = fresh_auth(monkeypatch)
    a.set_auth_config_for_test("off")
    app = _app_with(a.require_operator)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/probe")).status_code == 200  # open, no token
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/pytest tests/test_auth.py -k "require_" -v`
Expected: FAIL (dependencies not defined).

- [ ] **Step 3: Implement (append to `auth.py`)**

```python
from fastapi import Header, HTTPException, Request


def _detect_privilege_abuse(request: "Request", token: str) -> None:
    marker = request.headers.get("x-athena-principal", "").lower()
    if marker == "agent" and _match(token, _config.operator_token):
        logger.warning("PRIVILEGE-ABUSE: agent-origin request presented operator token: %s %s",
                       request.method, request.url.path)


async def require_authenticated(request: Request, authorization: str | None = Header(default=None)) -> str:
    if _config.mode == "off":
        return "operator"
    token = _extract_bearer(authorization)
    _detect_privilege_abuse(request, token)
    role = _resolve_role(token)
    if role is None:
        logger.warning("auth 401 %s %s", request.method, request.url.path)
        raise HTTPException(status_code=401, detail={"error": "authentication required", "mode": _config.mode})
    return role


async def require_operator(request: Request, authorization: str | None = Header(default=None)) -> str:
    if _config.mode == "off":
        return "operator"
    token = _extract_bearer(authorization)
    _detect_privilege_abuse(request, token)
    role = _resolve_role(token)
    if role is None:
        logger.warning("auth 401 %s %s", request.method, request.url.path)
        raise HTTPException(status_code=401, detail={"error": "authentication required", "mode": _config.mode})
    if role != "operator":
        logger.warning("auth 403 %s %s role=%s", request.method, request.url.path, role)
        raise HTTPException(status_code=403, detail={"error": "operator role required", "mode": _config.mode})
    return role
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/test_auth.py -k "require_ or off_mode" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/athena-dashboard/auth.py tools/athena-dashboard/tests/test_auth.py
git commit -m "feat(auth): require_authenticated + require_operator dependencies"
```

---

### Task 4: `auth.py` — `ws_authenticate` helper + privilege-abuse unit coverage

**Files:**
- Modify: `tools/athena-dashboard/auth.py`
- Test: `tools/athena-dashboard/tests/test_auth.py`

**Interfaces:**
- Produces: `ws_authenticate(token: str | None) -> bool` — True iff token is the operator
  token, or mode is `off`.

- [ ] **Step 1: Write the failing tests**

```python
def test_ws_authenticate(monkeypatch):
    a = fresh_auth(monkeypatch)
    a.set_auth_config_for_test("phase1", operator_token="op", agent_token="ag")
    assert a.ws_authenticate("op") is True
    assert a.ws_authenticate("ag") is False      # agent cannot open WS
    assert a.ws_authenticate(None) is False
    assert a.ws_authenticate("") is False
    a.set_auth_config_for_test("off")
    assert a.ws_authenticate(None) is True        # off = open

def test_privilege_abuse_logged(monkeypatch, caplog):
    a = fresh_auth(monkeypatch)
    a.set_auth_config_for_test("phase1", operator_token="op", agent_token="ag")
    class FakeReq:
        method = "POST"
        class url: path = "/api/approvals/x/resolve"
        headers = {"x-athena-principal": "agent"}
    import logging
    with caplog.at_level(logging.WARNING):
        a._detect_privilege_abuse(FakeReq(), "op")
    assert any("PRIVILEGE-ABUSE" in r.message for r in caplog.records)
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/pytest tests/test_auth.py -k "ws_authenticate or privilege" -v`
Expected: FAIL (`ws_authenticate` not defined).

- [ ] **Step 3: Implement (append to `auth.py`)**

```python
def ws_authenticate(token: str | None) -> bool:
    if _config.mode == "off":
        return True
    return _match(token or "", _config.operator_token)
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/test_auth.py -k "ws_authenticate or privilege" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/athena-dashboard/auth.py tools/athena-dashboard/tests/test_auth.py
git commit -m "feat(auth): ws_authenticate helper + privilege-abuse detection"
```

---

### Task 5: Gate operator-only + evidence-log routes in `server.py`

**Files:**
- Modify: `tools/athena-dashboard/server.py` (route signatures at the lines below)
- Test: `tools/athena-dashboard/tests/test_api_auth.py`

**Interfaces:**
- Consumes: `require_operator`, `require_authenticated`, `set_auth_config_for_test` (Tasks 1–3).
- Operator-only routes to gate (add `_role: str = Depends(require_operator)` to each handler signature):
  `POST /api/approvals/{request_id}/resolve` (L1924), `PATCH /api/engagements/{eid}` (L6272),
  `POST /api/engagements/{eid}/credentials` (L7959), `DELETE /api/engagements/{eid}` (L6621),
  `DELETE /api/engagements/{eid}/findings` (L8522), `DELETE /api/engagements/{eid}/graph` (L11369),
  `POST /api/engagements/{eid}/reset-state` (L11462), `POST /api/engagements/{eid}/clear` (L6489).
- Authenticated routes to gate (add `_role: str = Depends(require_authenticated)`):
  `POST /api/command-log/start` (L8358), `POST /api/command-log/complete` (L8373).

- [ ] **Step 1: Write the failing integration tests**

```python
# tests/test_api_auth.py
import pytest
from httpx import AsyncClient, ASGITransport

@pytest_asyncio.fixture
async def auth_client():
    import auth
    auth.set_auth_config_for_test("phase1", operator_token="op-test", agent_token="ag-test")
    from server import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    auth.set_auth_config_for_test("off")  # reset so other test modules stay open

OP = {"Authorization": "Bearer op-test"}
AG = {"Authorization": "Bearer ag-test", "X-Athena-Principal": "agent"}

@pytest.mark.asyncio
async def test_resolve_approval_blocks_agent(auth_client):
    r = await auth_client.post("/api/approvals/nonexistent/resolve?approved=true", headers=AG)
    assert r.status_code == 403            # agent refused (self-approval blocked)

@pytest.mark.asyncio
async def test_resolve_approval_allows_operator(auth_client):
    r = await auth_client.post("/api/approvals/nonexistent/resolve?approved=true", headers=OP)
    assert r.status_code in (200, 404)     # operator passes auth (404 = unknown id, auth OK)

@pytest.mark.asyncio
async def test_resolve_approval_requires_token(auth_client):
    r = await auth_client.post("/api/approvals/nonexistent/resolve?approved=true")
    assert r.status_code == 401

@pytest.mark.asyncio
async def test_delete_engagement_blocks_agent(auth_client):
    r = await auth_client.delete("/api/engagements/eng-x", headers=AG)
    assert r.status_code == 403

@pytest.mark.asyncio
async def test_command_log_requires_any_token(auth_client):
    unauth = await auth_client.post("/api/command-log/start", json={"engagement_id": "eng-x"})
    assert unauth.status_code == 401
    withtok = await auth_client.post("/api/command-log/start", json={"engagement_id": "eng-x"}, headers=AG)
    assert withtok.status_code != 401      # agent token accepted (may 400/422 on payload)
```

Note: import `pytest_asyncio` at top of the test file.

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/pytest tests/test_api_auth.py -v`
Expected: FAIL (routes return 200/404, not 401/403 — not yet gated).

- [ ] **Step 3: Implement — add the dependency to each handler**

At the top of `server.py` near the other local imports (after `from sdk_agent import ...` block), add:

```python
from auth import require_authenticated, require_operator
from fastapi import Depends  # if not already imported
```

Then edit each handler signature. Example for the core route (L1924):

```python
@app.post("/api/approvals/{request_id}/resolve")
async def resolve_approval_api(request_id: str, approved: bool, reason: str = "",
                               _role: str = Depends(require_operator)):
```

Apply the same `_role: str = Depends(require_operator)` parameter to the other 7 operator-only
handlers listed in Interfaces, and `_role: str = Depends(require_authenticated)` to the two
command-log handlers. Add the param as the LAST parameter of each signature; do not change bodies.

- [ ] **Step 4: Run to verify pass + no regressions**

Run: `.venv/bin/pytest tests/test_api_auth.py tests/test_api_command_log.py -v`
Expected: `test_api_auth.py` PASS; `test_api_command_log.py` still PASS (those tests run under the default `off` config since they don't set phase1).

- [ ] **Step 5: Commit**

```bash
git add tools/athena-dashboard/server.py tools/athena-dashboard/tests/test_api_auth.py
git commit -m "feat(auth): gate operator-only + evidence-log routes (phase 1)"
```

---

### Task 6: `/ws` operator handshake

**Files:**
- Modify: `tools/athena-dashboard/server.py` (`websocket_endpoint`, from L826; approve/reject block L893–L915)
- Test: `tools/athena-dashboard/tests/test_api_auth.py`

**Interfaces:**
- Consumes: `ws_authenticate` (Task 4).
- Behavior: on connect, read `token = ws.query_params.get("token")`; if `not ws_authenticate(token)`,
  `await ws.close(code=1008)` and return before `ws.accept()`-driven loop. Track `ws_is_operator=True`
  once accepted; the `approve`/`reject` handlers no-op (send an error frame) if not operator.

- [ ] **Step 1: Write the failing test** (use Starlette's WS test client via the sync `TestClient`)

```python
def test_ws_rejects_without_operator_token():
    import auth
    auth.set_auth_config_for_test("phase1", operator_token="op-test", agent_token="ag-test")
    from starlette.testclient import TestClient
    from server import app
    client = TestClient(app)
    import pytest
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws") as ws:   # no token -> closed 1008
            ws.receive_text()
    # valid operator token connects
    with client.websocket_connect("/ws?token=op-test") as ws:
        msg = ws.receive_text()     # state_sync snapshot on connect
        assert msg
    auth.set_auth_config_for_test("off")
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/pytest tests/test_api_auth.py -k ws -v`
Expected: FAIL (connect without token currently succeeds).

- [ ] **Step 3: Implement**

In `websocket_endpoint`, before `await ws.accept()`:

```python
from auth import ws_authenticate
token = ws.query_params.get("token")
if not ws_authenticate(token):
    await ws.close(code=1008)   # policy violation
    return
await ws.accept()
ws_is_operator = True   # only operator-authenticated connections reach here
```

In the `approve` / `reject` branches (L893, L906), guard before resolving:

```python
if msg_type == "approve":
    if not ws_is_operator:
        await ws.send_text(json.dumps({"type": "error",
            "content": "operator role required", "timestamp": time.time()}))
        continue
    ...
```

(With the connect-time gate, `ws_is_operator` is always True here; the guard is
defense-in-depth and documents intent.)

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/test_api_auth.py -k ws -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/athena-dashboard/server.py tools/athena-dashboard/tests/test_api_auth.py
git commit -m "feat(auth): operator handshake on /ws (second self-approval vector)"
```

---

### Task 7: Agent clients send Bearer + `X-Athena-Principal` marker

**Files:**
- Modify: `tools/athena-dashboard/sdk_agent.py` (`_get_http_client`, L417–421)
- Modify: `tools/athena-dashboard/command_log_hook.py` (the `CommandLogClient` httpx client)
- Test: `tools/athena-dashboard/tests/test_auth.py` (header-builder unit)

**Interfaces:**
- Produces (new shared helper in `auth.py`): `agent_request_headers() -> dict` →
  `{"Authorization": "Bearer <ATHENA_AGENT_TOKEN>", "X-Athena-Principal": "agent"}` (empty
  Authorization value if the env var is unset, so `off` mode still works).

- [ ] **Step 1: Write the failing test**

```python
def test_agent_request_headers(monkeypatch):
    a = fresh_auth(monkeypatch, ATHENA_AGENT_TOKEN="ag")
    h = a.agent_request_headers()
    assert h["Authorization"] == "Bearer ag"
    assert h["X-Athena-Principal"] == "agent"

def test_agent_request_headers_no_token(monkeypatch):
    a = fresh_auth(monkeypatch)   # no ATHENA_AGENT_TOKEN
    h = a.agent_request_headers()
    assert h["X-Athena-Principal"] == "agent"
    assert h["Authorization"] == "Bearer "   # harmless in off mode
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/pytest tests/test_auth.py -k agent_request_headers -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

Append to `auth.py`:

```python
def agent_request_headers() -> dict:
    return {
        "Authorization": f"Bearer {os.environ.get('ATHENA_AGENT_TOKEN', '')}",
        "X-Athena-Principal": "agent",
    }
```

In `sdk_agent.py` `_get_http_client`:

```python
async def _get_http_client(self) -> httpx.AsyncClient:
    if self._http_client is None or self._http_client.is_closed:
        from auth import agent_request_headers
        self._http_client = httpx.AsyncClient(timeout=5.0, headers=agent_request_headers())
    return self._http_client
```

In `command_log_hook.py`, `CommandLogClient._post` (L38–39) builds the client as
`async with httpx.AsyncClient(timeout=5.0) as client:`. Change it to:

```python
async def _post(self, path: str, payload: dict) -> dict:
    from auth import agent_request_headers
    async with httpx.AsyncClient(timeout=5.0, headers=agent_request_headers()) as client:
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/test_auth.py -k agent_request_headers -v`
Expected: PASS. Then grep-verify both clients set headers:
`grep -n "agent_request_headers" tools/athena-dashboard/sdk_agent.py tools/athena-dashboard/command_log_hook.py`

- [ ] **Step 5: Commit**

```bash
git add tools/athena-dashboard/auth.py tools/athena-dashboard/sdk_agent.py tools/athena-dashboard/command_log_hook.py tools/athena-dashboard/tests/test_auth.py
git commit -m "feat(auth): agent httpx clients send Bearer + principal marker"
```

---

### Task 8: `start.sh` token sourcing + server startup init

**Files:**
- Modify: `tools/athena-dashboard/server.py` (lifespan startup — add `load_auth_config()`)
- Modify: `tools/athena-dashboard/start.sh` (token sourcing, `ATHENA_AUTH_MODE` default)
- Test: `tools/athena-dashboard/tests/test_auth.py` (startup init behavior already covered by Task 1; add a guard that server import does not crash in off mode)

**Interfaces:**
- Consumes: `load_auth_config` (Task 1).

- [ ] **Step 1: Write the failing test**

```python
def test_server_import_safe_without_tokens(monkeypatch):
    # server import must not fail closed at import (only load_auth_config does)
    monkeypatch.delenv("ATHENA_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("ATHENA_AGENT_TOKEN", raising=False)
    import importlib, auth
    importlib.reload(auth)
    assert auth._config.mode == "off"   # import-time default, no raise
```

- [ ] **Step 2: Run to verify fail/pass**

Run: `.venv/bin/pytest tests/test_auth.py -k server_import_safe -v`
Expected: PASS already (import-time default is off) — this pins the invariant so Task 8 edits don't regress it.

- [ ] **Step 3: Implement**

In `server.py` `lifespan` startup (near the top of the async startup body, before Neo4j init), add:

```python
from auth import load_auth_config
load_auth_config()   # fails closed in phase1/enforce if tokens missing
```

In `start.sh`, after the Neo4j block and before launch, add a Kali-style block:

```bash
# ── Dashboard Auth (two-role tokens) ──
export ATHENA_AUTH_MODE="${ATHENA_AUTH_MODE:-phase1}"
if [ -z "$ATHENA_OPERATOR_TOKEN" ] && command -v op &>/dev/null; then
    export ATHENA_OPERATOR_TOKEN=$(op read "op://Vex/ATHENA Dashboard Operator Token/credential" 2>/dev/null)
fi
if [ -z "$ATHENA_AGENT_TOKEN" ] && command -v op &>/dev/null; then
    export ATHENA_AGENT_TOKEN=$(op read "op://Vex/ATHENA Dashboard Agent Token/credential" 2>/dev/null)
fi
if [ "$ATHENA_AUTH_MODE" != "off" ] && { [ -z "$ATHENA_OPERATOR_TOKEN" ] || [ -z "$ATHENA_AGENT_TOKEN" ]; }; then
    echo "  Auth:       MISSING tokens for mode=$ATHENA_AUTH_MODE — server will refuse to start."
    echo "              Set ATHENA_OPERATOR_TOKEN / ATHENA_AGENT_TOKEN or add them to 1Password (Vex vault),"
    echo "              or run with ATHENA_AUTH_MODE=off for legacy open mode."
else
    echo "  Auth:       mode=$ATHENA_AUTH_MODE ✓"
fi
```

Also extend the first-run wizard `.env` block to generate tokens:

```bash
    athena_op_token=$(openssl rand -hex 32)
    athena_ag_token=$(openssl rand -hex 32)
```

and append to the heredoc that writes `.env`:

```bash
ATHENA_AUTH_MODE=phase1
ATHENA_OPERATOR_TOKEN=${athena_op_token}
ATHENA_AGENT_TOKEN=${athena_ag_token}
```

- [ ] **Step 4: Verify**

Run: `.venv/bin/pytest tests/test_auth.py -v` (all pass) and `bash -n start.sh` (syntax OK).
Manual check (optional, operator's terminal): `ATHENA_AUTH_MODE=phase1 .venv/bin/python -c "import os; os.environ.pop('ATHENA_OPERATOR_TOKEN',None); os.environ.pop('ATHENA_AGENT_TOKEN',None); from auth import load_auth_config; load_auth_config()"` → should raise RuntimeError (fail-closed proof).

- [ ] **Step 5: Commit**

```bash
git add tools/athena-dashboard/server.py tools/athena-dashboard/start.sh tools/athena-dashboard/tests/test_auth.py
git commit -m "feat(auth): startup fail-closed init + start.sh token sourcing"
```

---

## Final Verification (whole branch)

- [ ] Run the full dashboard suite: `.venv/bin/pytest tests/ -v` — all green, no regressions.
- [ ] Confirm `git grep -n "== .*_token\|_token.*==" tools/athena-dashboard/auth.py` returns nothing (no `==` compares).
- [ ] Confirm fail-closed: the manual check in Task 8 Step 4 raises.
- [ ] ISC criteria 1–8 from the spec §11 each map to a passing test (1,2→Task 5; 3→Task 6; 4→Task 5; 5→Task 5; 6→regression suite; 7→Task 1/8; 8→Task 1).
