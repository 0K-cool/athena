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
