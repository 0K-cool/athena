"""Integration tests: dashboard route auth gating (phase 1)."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

pytestmark = pytest.mark.asyncio


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


async def test_resolve_approval_blocks_agent(auth_client):
    r = await auth_client.post("/api/approvals/nonexistent/resolve?approved=true", headers=AG)
    assert r.status_code == 403            # agent refused (self-approval blocked)


async def test_resolve_approval_allows_operator(auth_client):
    r = await auth_client.post("/api/approvals/nonexistent/resolve?approved=true", headers=OP)
    assert r.status_code in (200, 404)     # operator passes auth (404 = unknown id, auth OK)


async def test_resolve_approval_requires_token(auth_client):
    r = await auth_client.post("/api/approvals/nonexistent/resolve?approved=true")
    assert r.status_code == 401


async def test_delete_engagement_blocks_agent(auth_client):
    r = await auth_client.delete("/api/engagements/eng-x", headers=AG)
    assert r.status_code == 403


async def test_command_log_requires_any_token(auth_client):
    unauth = await auth_client.post("/api/command-log/start", json={"engagement_id": "eng-x"})
    assert unauth.status_code == 401
    withtok = await auth_client.post("/api/command-log/start", json={"engagement_id": "eng-x"}, headers=AG)
    assert withtok.status_code != 401      # agent token accepted (may 400/422 on payload)
