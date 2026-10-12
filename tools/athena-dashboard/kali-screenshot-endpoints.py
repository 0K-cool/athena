"""
ATHENA Kali Screenshot Endpoints (proxy)
========================================
Flask Blueprint registered in the root kali_server. It no longer runs a
browser itself: requests are forwarded over a Unix socket to the isolated
worker (kali-screenshot.service, user athena-shot, Chromium sandbox on).
Routes and response fields are unchanged. Inputs are now bounded (viewport 200-3840,
wait_ms <= 15000, max_lines <= 2000) and every failure uses the existing
HTTP 200 + {"success": false, "error": ...} shape that callers already handle.

Endpoints:
  POST /api/tools/screenshot          - Web page screenshot
  POST /api/tools/screenshot_terminal - Terminal output rendered as styled HTML screenshot

Pre-isolation version: kali_screenshot_endpoints.py.pre-isolation
"""

import json
import os
import pwd
import socket
import struct
import time

from flask import Blueprint, jsonify, request

screenshot_bp = Blueprint("screenshot", __name__)

SHOT_SOCKET = os.environ.get("SHOT_SOCKET", "/run/athena-shot/shot.sock")
WORKER_USER = os.environ.get("SHOT_WORKER_USER", "athena-shot")
WORKER_TIMEOUT_S = 90
# This process is root and the worker is the less-trusted side: bound what it can send back.
MAX_REPLY_BYTES = 64 * 1024 * 1024


class WorkerUntrusted(OSError):
    """The socket peer is not the worker user, or its reply broke the limits."""


def _peer_uid(sock: socket.socket) -> int:
    # Linux only (the deployment target). Elsewhere this raises, and the proxy fails closed.
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


def _expected_uid() -> int:
    return pwd.getpwnam(WORKER_USER).pw_uid


def _forward(kind: str):
    data = request.get_json(force=True, silent=True) or {}
    payload = json.dumps({"kind": kind, "data": data}).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(WORKER_TIMEOUT_S)
            sock.connect(SHOT_SOCKET)
            # The socket directory belongs to the worker user. After a browser escape it could
            # be swapped for a link to another root-reachable socket; refuse any other peer.
            if _peer_uid(sock) != _expected_uid():
                raise WorkerUntrusted("socket peer is not the worker user")
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + WORKER_TIMEOUT_S
            chunks, size = [], 0
            while chunk := sock.recv(65536):
                size += len(chunk)
                if size > MAX_REPLY_BYTES or time.monotonic() > deadline:
                    raise WorkerUntrusted("worker reply exceeded size or time limit")
                chunks.append(chunk)
        reply = json.loads(b"".join(chunks))
        return jsonify(reply["body"]), reply["status"]
    except (OSError, ValueError, KeyError) as exc:
        # Same failure shape as every other screenshot error, so callers degrade the same way.
        return jsonify({
            "success": False,
            "error": f"screenshot worker unavailable ({type(exc).__name__}); check: systemctl status kali-screenshot",
        }), 200


@screenshot_bp.route("/api/tools/screenshot", methods=["POST"])
def screenshot_web():
    return _forward("web")


@screenshot_bp.route("/api/tools/screenshot_terminal", methods=["POST"])
def screenshot_terminal():
    return _forward("terminal")
