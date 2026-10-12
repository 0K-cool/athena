#!/usr/bin/env bash
# Prove the screenshot isolation works by its effect, not its config. Run as root on the Kali box.
# Exit status is the number of failed checks.
set -uo pipefail

SOCK=/run/athena-shot/shot.sock
FAIL=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAIL=$((FAIL + 1)); }
# check NAME CMD...: PASS when CMD succeeds.
check() { local name="$1"; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }
# shellcheck disable=SC2329  # invoked indirectly through check
refused() { [[ "$1" == False* ]]; }
# shellcheck disable=SC2329
nft_rejected() { [[ "$1" == *ERR_CONNECTION_REFUSED* ]]; }

# One request to the worker socket; prints "<success> <error>".
shot() {
  python3 - "$1" "$2" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(90); s.connect("/run/athena-shot/shot.sock")
s.sendall(json.dumps({"kind": sys.argv[1], "data": json.loads(sys.argv[2])}).encode())
s.shutdown(socket.SHUT_WR)
b = b""
while c := s.recv(65536): b += c
body = json.loads(b)["body"]
print(body.get("success"), (body.get("error") or "").splitlines()[0][:80] if body.get("error") else "")
EOF
}

check "worker service active" systemctl is-active --quiet kali-screenshot
check "socket owned by athena-shot, mode 600" [ "$(stat -c '%U %a' "$SOCK" 2>/dev/null)" = "athena-shot 600" ]

# Browser identity and sandbox, sampled during a capture.
shot web '{"url":"https://example.com","wait_ms":6000}' >/tmp/.shotv 2>&1 &
sleep 4
# shellcheck disable=SC2009  # need full args (sandbox flags), which pgrep -a truncates per process
procs="$(ps -eo user:20,args | grep -E '[c]hrom')"
if [ -n "$procs" ] && ! grep -qv '^athena-shot ' <<<"$procs"; then pass "all Chromium processes run as athena-shot"; else fail "all Chromium processes run as athena-shot"; fi
# No processes observed proves nothing about the sandbox: that must fail, not pass.
if [ -n "$procs" ] && ! grep -q -- '--no-sandbox' <<<"$procs"; then pass "Chromium sandbox on"; else fail "Chromium sandbox on"; fi
wait
check "internet screenshot works" grep -q '^True' /tmp/.shotv
rm -f /tmp/.shotv

r="$(shot web '{"url":"http://127.0.0.1:5000/health","wait_ms":0}')"
check "loopback unreachable from browser" refused "$r"

lan="$(hostname -I | awk '{print $1}')"
r="$(shot web "{\"url\":\"http://$lan:5000/health\",\"wait_ms\":0}")"
check "own LAN address unreachable from browser" refused "$r"

resolver="$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /etc/athena-shot/egress.nft | head -1)"
r="$(shot web "{\"url\":\"http://$resolver/\",\"wait_ms\":0}")"
check "resolver reachable on DNS only (port 80 rejected by nft)" nft_rejected "$r"

# Each write must fail with EROFS specifically; any other failure (no worker, nsenter
# error) proves nothing and must not count as read-only.
pid="$(systemctl show -p MainPID --value kali-screenshot)"
ro=0
if [ -n "$pid" ] && [ "$pid" != 0 ]; then
  ro=1
  for p in /opt/athena-shot/probe /etc/probe /usr/probe; do
    out="$(nsenter -t "$pid" -m touch "$p" 2>&1)"
    [[ "$out" == *"Read-only file system"* ]] || { ro=0; rm -f "$p"; }
  done
fi
check "system paths read-only inside worker" [ "$ro" -eq 1 ]

code="$(curl -s -o /tmp/.shote -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d '{"command":"id","output":"uid=0(root)"}' http://127.0.0.1:5000/api/tools/screenshot_terminal)"
if [ "$code" = 200 ] && grep -q '"success": *true' /tmp/.shote; then pass "end-to-end through kali_server :5000"; else fail "end-to-end through kali_server :5000 (HTTP $code)"; fi
rm -f /tmp/.shote

echo "$FAIL check(s) failed"
exit "$FAIL"
