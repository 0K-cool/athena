"""Tests for the isolated Kali screenshot worker and the root-side proxy.

Stdlib only: CI installs neither Flask nor Playwright, so the worker keeps
its validation and rendering pure, imports Playwright lazily, and the proxy
is exercised against a minimal Flask stand-in plus a real Unix socket.
"""
import importlib.util
import json
import os
import re
import socket
import stat
import sys
import tempfile
import threading
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
WORKER_DIR = REPO / "tools" / "kali-screenshot-worker"
PROXY_PATH = REPO / "tools" / "athena-dashboard" / "kali-screenshot-endpoints.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def worker():
    return _load("shot_worker", WORKER_DIR / "shot_worker.py")


@pytest.fixture
def sock_path():
    d = tempfile.mkdtemp(prefix="shot")
    yield os.path.join(d, "s.sock")


def _request(path, raw: bytes):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(path)
        s.sendall(raw)
        s.shutdown(socket.SHUT_WR)
        buf = b""
        while chunk := s.recv(65536):
            buf += chunk
    return json.loads(buf)


@pytest.fixture
def running_worker(worker, sock_path, monkeypatch):
    """Real worker server on a temp socket, with browser handlers stubbed."""
    calls = []

    def fake_web(data):
        calls.append(("web", data))
        return 200, {"success": True, "image_b64": "AA==", "file_size": 1, "viewport": "1280x900"}

    def boom(data):
        raise RuntimeError("browser crashed")

    monkeypatch.setitem(worker.HANDLERS, "web", fake_web)
    monkeypatch.setitem(worker.HANDLERS, "terminal", boom)
    srv = worker.make_server(sock_path)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield sock_path, calls
    srv.shutdown()
    srv.server_close()


# --- web request validation -------------------------------------------------

@pytest.mark.parametrize("url", ["file:///etc/passwd", "javascript:alert(1)", "ftp://x", ""])
def test_web_rejects_non_http_schemes(worker, url):
    err, _ = worker.parse_web_request({"url": url})
    assert err and "http" in err


@pytest.mark.parametrize("viewport", ["99999x99999", "10x10", "abc", "1280"])
def test_web_rejects_bad_viewport(worker, viewport):
    err, _ = worker.parse_web_request({"url": "https://a.test", "viewport": viewport})
    assert err


def test_web_caps_wait_and_defaults(worker):
    err, req = worker.parse_web_request({"url": "https://a.test", "wait_ms": 10**9})
    assert err is None
    assert req["wait_ms"] == worker.MAX_WAIT_MS
    assert (req["width"], req["height"]) == (1280, 900)


# --- terminal rendering -----------------------------------------------------

TEMPLATE = "<h1>{{TOOL_NAME}}</h1><i>{{TIMESTAMP}}</i><b>{{COMMAND}}</b><pre>{{OUTPUT}}</pre>"


def test_terminal_escapes_every_field(worker):
    attack = "<img src=x onerror=alert(1)>"
    err, html = worker.render_terminal_html(
        {"command": attack, "output": attack, "tool_name": attack, "timestamp": attack}, TEMPLATE)
    assert err is None
    assert "<img" not in html
    assert html.count("&lt;img") == 4


def test_terminal_ansi_still_rendered(worker):
    err, html = worker.render_terminal_html(
        {"command": "nmap", "output": "\x1b[32mopen\x1b[0m 443/tcp"}, TEMPLATE)
    assert err is None
    assert '<span class="ansi-green">open</span>' in html


def test_terminal_truncates_and_bounds_max_lines(worker):
    out = "\n".join(f"line{i}" for i in range(50))
    _, html = worker.render_terminal_html({"command": "c", "output": out, "max_lines": 5}, TEMPLATE)
    assert "line4" in html and "line5" not in html and "45 more lines truncated" in html
    _, html = worker.render_terminal_html({"command": "c", "output": "x", "max_lines": 10**9}, TEMPLATE)
    assert html is not None


def test_terminal_requires_command(worker):
    err, _ = worker.render_terminal_html({"output": "x"}, TEMPLATE)
    assert err


# --- browser launch ---------------------------------------------------------

def test_launch_enables_chromium_sandbox(worker):
    seen = {}

    class FakeChromium:
        def launch(self, **kw):
            seen.update(kw)
            return "browser"

    worker._launch(types.SimpleNamespace(chromium=FakeChromium()))
    assert seen.get("chromium_sandbox") is True
    assert seen.get("headless") is True


# --- socket protocol --------------------------------------------------------

def test_socket_is_owner_only(running_worker):
    path, _ = running_worker
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_socket_round_trip(running_worker):
    path, calls = running_worker
    reply = _request(path, json.dumps({"kind": "web", "data": {"url": "https://a.test"}}).encode())
    assert reply == {"status": 200, "body": {"success": True, "image_b64": "AA==",
                                             "file_size": 1, "viewport": "1280x900"}}
    assert calls == [("web", {"url": "https://a.test"})]


@pytest.mark.parametrize("raw", [b"not json", b'{"kind":"nope"}', b'{"kind":"web","data":[1]}'])
def test_socket_rejects_bad_requests(running_worker, raw):
    path, calls = running_worker
    reply = _request(path, raw)
    assert reply["status"] == 400 and reply["body"]["success"] is False
    assert calls == []


def test_socket_rejects_oversized_request(running_worker, worker):
    path, calls = running_worker
    reply = _request(path, b"x" * (worker.MAX_REQUEST_BYTES + 10))
    assert reply["status"] == 413
    assert calls == []


def test_missing_browser_gets_actionable_error(worker):
    msg = worker._friendly_error(RuntimeError("BrowserType.launch: Executable doesn't exist at /x"))
    assert "playwright install chromium" in msg
    assert worker._friendly_error(RuntimeError("other")) == "other"


def test_socket_reports_browser_errors(running_worker):
    path, _ = running_worker
    reply = _request(path, json.dumps({"kind": "terminal", "data": {}}).encode())
    assert reply["body"] == {"success": False, "error": "browser crashed"}


# --- root-side proxy --------------------------------------------------------

@pytest.fixture
def proxy(monkeypatch):
    """Load the real proxy module against a minimal Flask stand-in."""
    state = {"json": None}
    fake = types.ModuleType("flask")

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            return lambda fn: fn

    fake.Blueprint = Blueprint
    fake.jsonify = lambda body: body
    fake.request = types.SimpleNamespace(get_json=lambda **k: state["json"])
    monkeypatch.setitem(sys.modules, "flask", fake)
    mod = _load("kali_screenshot_endpoints", PROXY_PATH)
    return mod, state


def test_proxy_forwards_to_worker(proxy, running_worker, monkeypatch):
    mod, state = proxy
    path, calls = running_worker
    monkeypatch.setattr(mod, "SHOT_SOCKET", path)
    state["json"] = {"url": "https://a.test"}
    body, status = mod.screenshot_web()
    assert status == 200 and body["success"] is True
    assert calls == [("web", {"url": "https://a.test"})]


def test_proxy_contains_no_browser(proxy):
    src = PROXY_PATH.read_text()
    assert "playwright" not in src.lower().replace("pre-isolation", "")


def test_proxy_fails_closed_when_worker_down(proxy, sock_path, monkeypatch):
    mod, state = proxy
    monkeypatch.setattr(mod, "SHOT_SOCKET", sock_path)  # nothing listening
    state["json"] = {"url": "https://a.test"}
    body, status = mod.screenshot_web()
    # Callers treat non-200 as "skip silently"; failures keep the 200 + success:false shape.
    assert status == 200 and body["success"] is False
    assert "unavailable" in body["error"]


# --- deployment artifacts ---------------------------------------------------

def _unit():
    return (WORKER_DIR / "kali-screenshot.service").read_text()


@pytest.mark.parametrize("directive", [
    "User=athena-shot", "NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "ProtectSystem=strict",
    "ProtectHome=yes", "PrivateTmp=yes", "MemoryMax=",
])
def test_unit_hardening_present(directive):
    assert directive in _unit()


def test_unit_denies_local_networks():
    deny = re.search(r"^IPAddressDeny=(.*)$", _unit(), re.M).group(1).split()
    for net in ["localhost", "link-local", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
        assert net in deny


def test_unit_does_not_restrict_namespaces():
    # Chromium's sandbox needs user namespaces; RestrictNamespaces would silently break it.
    assert not re.search(r"^RestrictNamespaces=", _unit(), re.M)


def test_egress_blocks_own_addresses_before_anything_else():
    # The own-box reject must come first: --allow-cidr opens private ranges in systemd,
    # and nothing may open the box's own services.
    rules = [l.strip() for l in (WORKER_DIR / "egress.nft.in").read_text().splitlines()
             if l.strip().startswith("meta skuid")]
    assert rules[0] == 'meta skuid "athena-shot" fib daddr type local counter reject'
    assert rules[-1].endswith("counter reject")


def test_no_site_specific_addresses_committed():
    # Resolver address is rendered at install time; nothing site-specific in the repo.
    assert not re.search(r"^IPAddressAllow=", _unit(), re.M)
    nft = (WORKER_DIR / "egress.nft.in").read_text()
    assert "@RESOLVER@" in nft
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", nft)
