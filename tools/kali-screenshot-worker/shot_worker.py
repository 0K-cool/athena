"""
ATHENA screenshot worker (isolated)
===================================
Runs as the unprivileged `athena-shot` user under kali-screenshot.service.
Chromium launches WITH its sandbox. Listens on a Unix socket only; the root
kali_server proxies /api/tools/screenshot{,_terminal} to it
(see tools/athena-dashboard/kali-screenshot-endpoints.py).

Protocol: client sends one JSON object {"kind": "web"|"terminal", "data": {...}},
then shuts down its write side. Worker replies {"status": int, "body": {...}}
and closes. Request size is capped.
"""

import base64
import html
import json
import os
import re
import socketserver
import sys
import threading
from datetime import datetime
from pathlib import Path

SOCKET_PATH = os.environ.get("SHOT_SOCKET", "/run/athena-shot/shot.sock")
TEMPLATE_PATH = Path(__file__).parent / "terminal-template.html"
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_CONCURRENT = 3
# Callers time out at 15s; a queued request must fail fast in that shape, not hang.
QUEUE_WAIT_S = 10
MAX_WAIT_MS = 15000
MIN_DIM, MAX_DIM = 200, 3840
MAX_LINES_CAP = 2000

_slots = threading.BoundedSemaphore(MAX_CONCURRENT)

_ANSI_CODE_MAP = {
    "1": "ansi-bold", "2": "ansi-dim", "31": "ansi-red", "32": "ansi-green",
    "33": "ansi-yellow", "34": "ansi-blue", "35": "ansi-magenta", "36": "ansi-cyan",
}


def ansi_to_html(text: str) -> str:
    """Convert ANSI colour codes in already-escaped text to <span> elements."""
    open_spans: list[str] = []

    def _replace(match: re.Match) -> str:
        parts: list[str] = []
        for code in match.group(1).split(";"):
            if code in ("0", ""):
                parts.append("</span>" * len(open_spans))
                open_spans.clear()
            elif code in _ANSI_CODE_MAP:
                parts.append(f'<span class="{_ANSI_CODE_MAP[code]}">')
                open_spans.append(code)
        return "".join(parts)

    converted = re.sub(r"\x1b\[([0-9;]*)m", _replace, text)
    converted += "</span>" * len(open_spans)
    return re.sub(r"\x1b\[[^a-zA-Z]*[a-zA-Z]", "", converted)


def parse_web_request(data: dict):
    """Validate a web screenshot request. Returns (error, params)."""
    url = str(data.get("url", "")).strip()
    viewport = str(data.get("viewport", "1280x900"))
    if not (url.startswith("http://") or url.startswith("https://")):
        return "url must start with http:// or https://", None
    try:
        width, height = (int(v) for v in viewport.split("x", 1))
        wait_ms = int(data.get("wait_ms", 2000))
    except (ValueError, TypeError):
        return f"Invalid viewport '{viewport}' or wait_ms. Expected WIDTHxHEIGHT.", None
    if not (MIN_DIM <= width <= MAX_DIM and MIN_DIM <= height <= MAX_DIM):
        return f"viewport dimensions must be {MIN_DIM}-{MAX_DIM}", None
    return None, {
        "url": url, "viewport": viewport, "width": width, "height": height,
        "wait_ms": max(0, min(wait_ms, MAX_WAIT_MS)),
        "full_page": bool(data.get("full_page", False)),
    }


def render_terminal_html(data: dict, template: str):
    """Build the terminal page. Every injected value is HTML-escaped. Returns (error, html)."""
    command = str(data.get("command", "")).strip()
    output = data.get("output", "")
    if not command:
        return "'command' is required", None
    if output is None:
        return "'output' is required", None
    try:
        max_lines = max(1, min(int(data.get("max_lines", 200)), MAX_LINES_CAP))
    except (ValueError, TypeError):
        return "max_lines must be an integer", None
    tool_name = str(data.get("tool_name", "Terminal"))
    timestamp = str(data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    lines = str(output).splitlines()
    if len(lines) > max_lines:
        remaining = len(lines) - max_lines
        lines = lines[:max_lines] + [f"\n[... {remaining} more lines truncated]"]

    return None, (template
                  .replace("{{TOOL_NAME}}", html.escape(tool_name))
                  .replace("{{TIMESTAMP}}", html.escape(timestamp))
                  .replace("{{COMMAND}}", html.escape(command))
                  .replace("{{OUTPUT}}", ansi_to_html(html.escape("\n".join(lines)))))


def _friendly_error(exc: Exception) -> str:
    msg = str(exc)
    if "Executable doesn't exist" in msg:
        return ("Chromium is not installed for the worker. Run: "
                "PLAYWRIGHT_BROWSERS_PATH=/opt/athena-shot/ms-playwright playwright install chromium")
    return msg


def _launch(p):
    # chromium_sandbox=True: re-enable Chromium's sandbox (Playwright disables it by default).
    return p.chromium.launch(headless=True, chromium_sandbox=True)


def _png_result(png: bytes, viewport: str) -> dict:
    return {"success": True, "image_b64": base64.b64encode(png).decode(),
            "file_size": len(png), "viewport": viewport}


def shot_web(data: dict):
    err, req = parse_web_request(data)
    if err:
        return 400, {"success": False, "error": err}
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = _launch(p)
        try:
            page = browser.new_page(viewport={"width": req["width"], "height": req["height"]})
            page.goto(req["url"], wait_until="networkidle", timeout=20000)
            if req["wait_ms"]:
                page.wait_for_timeout(req["wait_ms"])
            png = page.screenshot(full_page=req["full_page"])
        finally:
            browser.close()
    return 200, _png_result(png, req["viewport"])


def shot_terminal(data: dict):
    try:
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return 200, {"success": False, "error": f"terminal-template.html not found at {TEMPLATE_PATH}"}
    err, rendered = render_terminal_html(data, template)
    if err:
        return 400, {"success": False, "error": err}
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = _launch(p)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            # set_content instead of a file:// temp file: no filesystem origin for the page.
            page.set_content(rendered, wait_until="load")
            page.wait_for_timeout(500)
            png = page.screenshot()
        finally:
            browser.close()
    return 200, _png_result(png, "1280x900")


HANDLERS = {"web": shot_web, "terminal": shot_terminal}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            return self._reply(413, {"success": False, "error": "request too large"})
        try:
            req = json.loads(raw)
            handler = HANDLERS[req["kind"]]
            data = req.get("data") or {}
            if not isinstance(data, dict):
                raise TypeError("data must be an object")
        except (ValueError, KeyError, TypeError) as exc:
            return self._reply(400, {"success": False, "error": f"bad request: {exc}"})
        if not _slots.acquire(timeout=QUEUE_WAIT_S):
            return self._reply(200, {"success": False, "error": "screenshot worker busy, retry"})
        try:
            status, body = handler(data)
        except Exception as exc:  # surface browser errors to the caller, like upstream
            status, body = 200, {"success": False, "error": _friendly_error(exc)}
        finally:
            _slots.release()
        self._reply(status, body)

    def _reply(self, status: int, body: dict):
        self.wfile.write(json.dumps({"status": status, "body": body}).encode())


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def make_server(path: str) -> Server:
    """Bind the worker socket and set it owner-only (0600).

    chmod follows bind, so the socket briefly has umask permissions. Under the unit this
    window is closed by UMask=0077 and the 0700 RuntimeDirectory; outside it, it is not.
    """
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = Server(path, Handler)
    os.chmod(path, 0o600)
    return srv


def main():
    with make_server(SOCKET_PATH) as srv:
        print(f"athena-shot worker listening on {SOCKET_PATH}", file=sys.stderr, flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
