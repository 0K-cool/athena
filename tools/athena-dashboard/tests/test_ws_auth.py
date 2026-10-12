"""WebSocket operator-handshake auth test (sync Starlette TestClient).

Kept in its own module (no module-level asyncio marker) because the WS
TestClient API is synchronous.
"""
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


def test_ws_rejects_without_operator_token():
    import auth
    auth.set_auth_config_for_test("phase1", operator_token="op-test", agent_token="ag-test")
    try:
        from server import app
        client = TestClient(app)
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws") as ws:   # no token -> closed 1008
                ws.receive_text()
        # valid operator token connects and receives the state_sync snapshot
        with client.websocket_connect("/ws?token=op-test") as ws:
            msg = ws.receive_text()
            assert msg
    finally:
        auth.set_auth_config_for_test("off")
