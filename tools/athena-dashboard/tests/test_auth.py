"""Unit tests for the dashboard auth module (two-role Bearer auth)."""
import os
import importlib

import pytest


def fresh_auth(monkeypatch, **env):
    """Reload the auth module with a controlled environment."""
    for k in ("ATHENA_AUTH_MODE", "ATHENA_OPERATOR_TOKEN", "ATHENA_AGENT_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import auth as _a
    importlib.reload(_a)
    return _a


# ── Task 1: config load + fail-closed + environ hardening ──

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


# ── Task 2: bearer extraction, constant-time match, role resolution ──

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


# ── Task 3: require_authenticated / require_operator dependencies ──

import pytest as _pytest
from fastapi import FastAPI, Depends
from httpx import AsyncClient, ASGITransport


def _app_with(dep):
    app = FastAPI()

    @app.get("/probe")
    async def probe(role: str = Depends(dep)):
        return {"role": role}

    return app


@_pytest.mark.asyncio
async def test_require_operator_rejects_agent(monkeypatch):
    a = fresh_auth(monkeypatch)
    a.set_auth_config_for_test("phase1", operator_token="op", agent_token="ag")
    app = _app_with(a.require_operator)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/probe", headers={"Authorization": "Bearer ag"})).status_code == 403
        assert (await c.get("/probe", headers={"Authorization": "Bearer op"})).status_code == 200
        assert (await c.get("/probe")).status_code == 401
        assert (await c.get("/probe", headers={"Authorization": "Bearer junk"})).status_code == 401


@_pytest.mark.asyncio
async def test_require_authenticated_accepts_both(monkeypatch):
    a = fresh_auth(monkeypatch)
    a.set_auth_config_for_test("phase1", operator_token="op", agent_token="ag")
    app = _app_with(a.require_authenticated)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/probe", headers={"Authorization": "Bearer ag"})).json()["role"] == "agent"
        assert (await c.get("/probe", headers={"Authorization": "Bearer op"})).json()["role"] == "operator"
        assert (await c.get("/probe")).status_code == 401


@_pytest.mark.asyncio
async def test_off_mode_is_open(monkeypatch):
    a = fresh_auth(monkeypatch)
    a.set_auth_config_for_test("off")
    app = _app_with(a.require_operator)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/probe")).status_code == 200  # open, no token


# ── Task 4: ws_authenticate + privilege-abuse detection ──

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

        class url:
            path = "/api/approvals/x/resolve"

        headers = {"x-athena-principal": "agent"}

    import logging
    with caplog.at_level(logging.WARNING):
        a._detect_privilege_abuse(FakeReq(), "op")
    assert any("PRIVILEGE-ABUSE" in r.message for r in caplog.records)
