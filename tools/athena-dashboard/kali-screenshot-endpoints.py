"""
ATHENA Kali Screenshot Endpoints (proxy)
========================================
Flask Blueprint registered in the root kali_server. It no longer runs a
browser itself: requests are forwarded over a Unix socket to the isolated
worker (kali-screenshot.service, user athena-shot, Chromium sandbox on).
Routes and request/response JSON are unchanged.

Endpoints:
  POST /api/tools/screenshot          - Web page screenshot
  POST /api/tools/screenshot_terminal - Terminal output rendered as styled HTML screenshot

Pre-isolation version: kali_screenshot_endpoints.py.pre-isolation
"""

import json
import os
import socket

from flask import Blueprint, jsonify, request

screenshot_bp = Blueprint("screenshot", __name__)

SHOT_SOCKET = os.environ.get("SHOT_SOCKET", "/run/athena-shot/shot.sock")
WORKER_TIMEOUT_S = 90


def _forward(kind: str):
    data = request.get_json(force=True, silent=True) or {}
    payload = json.dumps({"kind": kind, "data": data}).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(WORKER_TIMEOUT_S)
            sock.connect(SHOT_SOCKET)
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while chunk := sock.recv(65536):
                chunks.append(chunk)
        reply = json.loads(b"".join(chunks))
        return jsonify(reply["body"]), reply["status"]
    except (OSError, ValueError, KeyError) as exc:
        return jsonify({
            "success": False,
            "error": f"screenshot worker unavailable ({type(exc).__name__}); check: systemctl status kali-screenshot",
        }), 503


@screenshot_bp.route("/api/tools/screenshot", methods=["POST"])
def screenshot_web():
    return _forward("web")


@screenshot_bp.route("/api/tools/screenshot_terminal", methods=["POST"])
def screenshot_terminal():
    return _forward("terminal")
