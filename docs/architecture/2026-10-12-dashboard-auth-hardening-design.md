# ATHENA Dashboard Auth Hardening — Design Spec

**Date:** 2026-10-12
**Author:** Kelvin Lomboy (with Vex)
**Status:** Approved for planning
**Branch:** `feat/dashboard-auth-hardening`
**Scope:** `tools/athena-dashboard/` (dashboard API only). Kali backend (`kali_server.py`) is a separate follow-up — see §9.

---

## 1. Problem

The ATHENA dashboard API (`tools/athena-dashboard/server.py`, 160 routes) has **no
authentication on any route**. The autonomous SDK agent reaches this API over HTTP
(`httpx` → `http://localhost:8080`) — the *same* API surface the human operator and UI
use. Two concrete consequences:

1. **Agent self-approval.** `POST /api/approvals/{request_id}/resolve` and the `/ws`
   inbound `approve`/`reject` messages resolve HITL gates with no auth. An agent can
   approve its own high-risk actions, defeating the human-in-the-loop control.
2. **Open evidence-log writes.** `POST /api/command-log/start` and
   `/api/command-log/complete` accept writes from any caller, so a non-agent process
   can inject fabricated evidence entries.

The network perimeter is already safe (operator-verified 2026-10-12): the dashboard
binds `127.0.0.1:8080` via `start.sh`, and the box sits behind a Firewalla with no WAN
inbound, reachable only over ZeroTier. **This is therefore a defense-in-depth gap
*within* the LAN/ZeroTier trust boundary — specifically the agent-vs-operator boundary
on a shared localhost — not a public RCE.** This is ATHENA's instance of the
"dangerous middle": agent and operator are indistinguishable to the API.

## 2. Goals / Non-goals

**Goals**
- Distinguish **operator** (human) from **agent** at the dashboard boundary so the agent
  cannot resolve HITL approvals or mutate/destroy the audit trail.
- Close unauthenticated access to sensitive routes from *other* localhost processes.
- Preserve **headless-first**: every control works via REST with a Bearer token, no
  browser or WebSocket required. The UI is an equal client, not a prerequisite.
- Reversible, phased rollout that does not break a live engagement.

**Non-goals**
- A hard boundary against a *fully compromised, malicious* in-process agent (see §3
  "Known limit"). That requires process/uid separation — roadmap, not this spec.
- Multi-user accounts, login sessions, RBAC beyond two roles. YAGNI for a solo
  single-operator tool today.
- Changes to `kali_server.py` (separate deploy/host — §9).

## 3. Trust model & principals

Three principals, enforced at the dashboard HTTP/WS boundary:

| Principal | Credential | May do |
|-----------|-----------|--------|
| **Operator** (human; UI or headless CLI) | `ATHENA_OPERATOR_TOKEN` | Everything, incl. the operator-only set (§6) |
| **Agent** (in-process SDK sessions + curl-spawned workers) | `ATHENA_AGENT_TOKEN` | Run the engagement: findings, tools, telemetry, approval *requests*, command-log *appends*. **Refused** on operator-only routes |
| **Unauthenticated** | none | Public allowlist only (§5) |

### What the two-role token actually buys (stated honestly)

The agent runs **in-process**: `server.py` does `from sdk_agent import
AthenaAgentSession` and `_spawn_agent` creates agents as in-process asyncio sessions in
the same OS process, which then call back over `httpx` to their own `:8080`. The agent
therefore shares `os.environ` and process memory with the server.

Given that, the token delivers three real things — and is honest about a fourth it does
**not**:

1. **Closes sensitive routes to other localhost processes** — the stated defense-in-depth goal. ✅
2. **Honest-agent intent gate.** Self-approval stops being an incidental call; it now
   requires the agent to deliberately read `os.environ['ATHENA_OPERATOR_TOKEN']` and
   forge an operator request. ✅
3. **Detection signal.** An agent-origin request bearing the operator token is logged as
   privilege abuse (see §7). ✅
4. **NOT a wall against a malicious in-process agent.** ❌ A compromised agent sharing
   process memory can recover the operator token. This is a deliberate, documented limit,
   consistent with the gh-policy confirm-token correction (a local secret an agent with
   read access can forge is an intent gate, not proof against a malicious actor).

### Known limit & future hard boundary

The real boundary against a malicious agent is to run the agent as a **separate
low-privilege process/uid** (or under an L10/L11 OS sandbox) that cannot read the
operator token — the same pattern as the Kali backend separation. This is named here as
the roadmap item and is explicitly out of scope for this spec. We stop at the
honest-agent gate + detection and document the limit rather than pretend tokens close it.

## 4. Token issuance, storage, delivery

- **At rest.** Both tokens live in 1Password (`Vex` vault), following the existing
  `KALI_API_KEY` pattern. Generated once with `openssl rand -hex 32`. Rotatable by
  replacing the item and restarting.
- **Into the server.** `start.sh` sources both tokens into the **server** process env
  (env var first, then `op read` fallback, mirroring the existing Neo4j/Graphiti blocks).
- **Agent.** The shared `httpx.AsyncClient` in `sdk_agent.py` attaches
  `Authorization: Bearer $ATHENA_AGENT_TOKEN` to every request. Curl-based worker spawns
  (ST → `/api/agents/force-spawn`, `/api/agents/request`) carry the agent token only.
- **Operator — UI.** No token is embedded in the served HTML. The operator pastes the
  token once; the frontend stores it in `sessionStorage` and sends it as
  `Authorization: Bearer`. The WebSocket connects with `?token=<operator_token>`,
  validated on accept.
- **Operator — headless.** Same Bearer token via `-H "Authorization: Bearer ..."` or an
  `ATHENA_OPERATOR_TOKEN` env read by a thin CLI helper. No browser/WS needed.
- **Hardening (honest).** After reading the operator token at startup, the server
  `os.environ.pop("ATHENA_OPERATOR_TOKEN", None)` so a casual `os.environ` read by
  in-process code fails. This is documented as *friction, not a boundary* — shared
  process memory still holds it.

## 5. Enforcement mechanism (Approach B)

New module `tools/athena-dashboard/auth.py`:

- `require_authenticated` — FastAPI dependency; accepts a request bearing **any** valid
  token (operator or agent). Returns the resolved role.
- `require_operator` — FastAPI dependency; accepts **only** the operator token.
- Token comparison uses `hmac.compare_digest` (constant-time). Missing/invalid token →
  `401`; valid token, wrong role → `403`.
- Both dependencies read tokens from module state captured at import/startup (not per
  request), so the startup `environ.pop` hardening holds.

**Phase 1 (this implementation):**
- Add `Depends(require_operator)` to the operator-only routes (§6).
- Add `Depends(require_authenticated)` to the evidence-log write routes (§6).
- **WebSocket handshake:** validate the operator token on `/ws` accept (query param);
  reject the connection if absent/invalid. Belt-and-suspenders: the inbound
  `approve`/`reject` handlers re-check that the connection authenticated as operator
  before calling `resolve_approval`.

**Phase 2 (follow-up, planned here, implemented separately):**
- A default-deny ASGI middleware baseline requiring a valid token on every route except
  the public allowlist. The operator-only dependencies continue to gate the dangerous
  subset underneath.

**Public allowlist (no auth, both phases):** `GET /` and static assets, `GET /health`
(add if missing), and `GET /docs` + `/openapi.json` (kept in `off`/`phase1`; gated or
disabled in `enforce` — operator decision at Phase 2).

**Config flag** `ATHENA_AUTH_MODE`:
- `off` — no enforcement (legacy behavior; for migration only).
- `phase1` — operator-only + evidence-log + WS gates active; everything else open.
- `enforce` — Phase 1 gates **plus** Phase 2 default-deny baseline.

**Fail-closed:** in `phase1`/`enforce`, if the required token(s) are not configured, the
server refuses to start with a clear error (not a silent allow-all). In `off` it warns
loudly on startup that auth is disabled. Default mode ships as `phase1`.

## 6. Route classification — Phase 1

**Operator-only (`require_operator`)** — irreducible HITL + integrity + destruction core:

- `POST /api/approvals/{request_id}/resolve` — the core self-approval vector
- `/ws` inbound `approve` / `reject` — the second self-approval vector
- `PATCH /api/engagements/{eid}` — carries the `authorization` assertion + scope fields
- `POST /api/engagements/{eid}/credentials` — credential storage
- `DELETE /api/engagements/{eid}` — destroys an engagement
- `DELETE /api/engagements/{eid}/findings` — destroys findings (audit trail)
- `DELETE /api/engagements/{eid}/graph` — destroys the graph
- `POST /api/engagements/{eid}/reset-state` — wipes engagement state
- `POST /api/engagements/{eid}/clear` — clears engagement

**Authenticated (`require_authenticated`)** — the named "open evidence-log writes" gap:

- `POST /api/command-log/start`
- `POST /api/command-log/complete`

  (Append-only and already hash-chained per #105. Auth stops non-agent injection; the
  hash chain detects tampering of existing entries. There is intentionally no
  delete/mutate endpoint for the command log — verified; do not add one.)

**Explicitly agent-allowed (authenticated, NOT operator-only):**

- `POST /api/scope/expand` — this is the agent's *request*; it only creates a HITL
  approval. The commit happens on `resolve` (operator-gated above). Note: a
  `_is_autonomous` path (BUG-026) auto-approves scope expansion in Lab/CTF mode with no
  HITL — acceptable for lab/CTF, flagged here for visibility.

**Deferred to Phase 2 (enumerated, not silently dropped — classify at Phase 2):**
engagement lifecycle (`/api/engagement/{eid}/start`, `start-ai`, `stop`, `pause`,
`resume`, `cleanup-orphans`), fleet control (`/api/agents/force-spawn`,
`stop-all-workers`, `stop/{agent_code}`), `POST /api/bus/directive`, `POST
/api/config/update|rag|toggle`, `POST /api/tools/reload`, demo control, and the bulk
destructive `DELETE`s (`/api/cei`, `/api/events`, `/api/scans`, `/api/reports*`,
`/api/artifacts*`, `/api/messages/rate-limits`). Several of these are strong operator-only
candidates; promoting them is a Phase 2 decision, kept out of Phase 1 to keep the diff
tight and reviewable.

## 7. Error handling, logging, detection

- `401` for missing/invalid token; `403` for valid-but-wrong-role. JSON body
  `{"error": "...", "mode": "<ATHENA_AUTH_MODE>"}`.
- **Detection signal:** the agent's `httpx` client sets a fixed marker header
  `X-Athena-Principal: agent` on every request. If a request carries that marker **and**
  presents the operator token, the server logs a `privilege-abuse` warning to the server
  log and the command-log audit stream. This is the signal referenced in §3.3; it does
  not block beyond the normal role check. The marker is advisory (an honest agent sets it;
  a malicious one could strip it) — it is detection, not enforcement, consistent with the
  §3 known limit.
- Auth failures are logged with route + method + presented-role (never the token value).

## 8. Rollout & compatibility

1. Ship with `ATHENA_AUTH_MODE=phase1`. Agent (`sdk_agent` httpx client + curl spawns)
   and UI are updated in the same change to send their tokens, so a running engagement
   keeps working end-to-end.
2. `start.sh` generates/sources tokens on first run (wizard prompt + 1Password fallback),
   mirroring the existing Kali/Neo4j blocks; existing `.env` files gain the two new keys.
3. `off` mode is retained as an escape hatch for migration and local debugging, with a
   loud startup warning.
4. Phase 2 (`enforce`) ships only after Phase 1 is observed healthy in real use.

## 9. Follow-up — Kali backend (separate spec)

Out of scope here, carried forward so it is not lost: `kali_server.py` on the antsle box
binds `0.0.0.0:5000` as root with `shell=True` and **ignores the `X-API-Key` it already
receives**. Follow-up spec: **enforce the `X-API-Key` it receives** + **bind to the
private/ZeroTier interface** + add a host firewall rule. Separate deploy/host/repo →
separate PR with independent revert (Directive #13). Not a go/no-go gate — the perimeter
is already safe — but a real defense-in-depth gap within the trust boundary.

## 10. Testing strategy

**Unit (`auth.py`):**
- `require_operator` accepts operator token, rejects agent token (`403`), rejects
  missing/garbage (`401`).
- `require_authenticated` accepts both valid tokens, rejects missing/garbage (`401`).
- Constant-time compare is used (no early-return on length/prefix).

**Integration (FastAPI `TestClient`):**
- Agent token is **refused** on `POST /api/approvals/{id}/resolve` (`403`) — the core
  regression guard against self-approval.
- Operator token **succeeds** on the same route.
- Unauthenticated `/ws` connect is rejected; `approve`/`reject` over a non-operator WS is
  refused.
- Evidence-log write (`command-log/start`) refused unauthenticated, accepted with a valid
  token.
- Each operator-only route in §6 refuses the agent token.

**Regression:**
- Existing agent flows (create finding, request approval, append command-log, run a tool)
  still succeed when carrying the agent token — proves Phase 1 did not break the live
  agent path.
- `ATHENA_AUTH_MODE=off` preserves legacy open behavior (for the migration window only).

**Fail-closed:**
- Server refuses to start in `phase1`/`enforce` with tokens unset; starts with a warning
  in `off`.

## 11. Success criteria (ISC — independently checkable)

1. With `ATHENA_AUTH_MODE=phase1`, an agent-token request to
   `POST /api/approvals/{id}/resolve` returns `403`.
2. With `phase1`, an operator-token request to the same route returns `200` and resolves.
3. With `phase1`, a `/ws` connection without a valid operator token is rejected at accept.
4. With `phase1`, `POST /api/command-log/start` without any token returns `401`.
5. With `phase1`, every route listed operator-only in §6 returns `403` for the agent token.
6. Existing agent engagement flow completes end-to-end carrying only the agent token.
7. In `phase1` with tokens unset, the server refuses to start with a non-zero exit and a
   clear message.
8. After startup, `os.environ` in the shared server process does not contain
   `ATHENA_OPERATOR_TOKEN` (the server popped it per §4 — friction against casual
   in-process reads, not a boundary).
