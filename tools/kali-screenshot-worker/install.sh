#!/usr/bin/env bash
# Install the isolated ATHENA screenshot worker on a Kali box running MCP-Kali-Server.
#
# Usage (as root, from a checkout of this directory):
#   sudo ./install.sh [--resolver IPV4] [--server-dir DIR]
#
# --resolver    DNS resolver the worker may reach (port 53 only). Default: first
#               nameserver in /etc/resolv.conf. Loopback resolvers are refused,
#               because allowing loopback would reopen the box's local services.
# --server-dir  MCP-Kali-Server directory. Default: /opt/MCP-Kali-Server
#
# Idempotent. The original blueprint is kept as kali_screenshot_endpoints.py.pre-isolation.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASH="$SRC/../athena-dashboard"
SERVER_DIR=/opt/MCP-Kali-Server
RESOLVER=""
WORKER_DIR=/opt/athena-shot
UNIT=/etc/systemd/system/kali-screenshot.service
DROPIN=/etc/systemd/system/kali-screenshot.service.d

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --resolver) RESOLVER="${2:-}"; shift 2 ;;
    --server-dir) SERVER_DIR="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -f "$SERVER_DIR/kali_server.py" ] || die "kali_server.py not found in $SERVER_DIR"
command -v nft >/dev/null || die "nft (nftables) is required"

if [ -z "$RESOLVER" ]; then
  RESOLVER="$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf)"
fi
[[ "$RESOLVER" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "resolver must be an IPv4 address, got '$RESOLVER'"
case "$RESOLVER" in
  127.*) die "resolver $RESOLVER is loopback; pass the upstream resolver with --resolver" ;;
esac
[ "$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1)" = "1" ] \
  || die "kernel.unprivileged_userns_clone=0: Chromium's sandbox cannot start"

echo "==> user athena-shot"
id athena-shot >/dev/null 2>&1 || useradd --system --home-dir /var/lib/athena-shot \
  --no-create-home --shell /usr/sbin/nologin --user-group athena-shot

echo "==> venv $SERVER_DIR/.venv"
[ -x "$SERVER_DIR/.venv/bin/python" ] || python3 -m venv "$SERVER_DIR/.venv"
"$SERVER_DIR/.venv/bin/pip" install -q -r "$SRC/requirements.txt"

echo "==> worker files"
install -d -o root -g root -m 0755 "$WORKER_DIR"
install -o root -g root -m 0644 "$SRC/shot_worker.py" "$WORKER_DIR/shot_worker.py"
install -o root -g root -m 0644 "$SERVER_DIR/terminal-template.html" "$WORKER_DIR/terminal-template.html"
PLAYWRIGHT_BROWSERS_PATH="$WORKER_DIR/ms-playwright" "$SERVER_DIR/.venv/bin/playwright" install chromium
chmod -R a+rX "$WORKER_DIR"

echo "==> egress pin (resolver $RESOLVER, port 53 only)"
install -d -m 0755 /etc/athena-shot
sed "s/@RESOLVER@/$RESOLVER/g" "$SRC/egress.nft.in" > /etc/athena-shot/egress.nft
chmod 0644 /etc/athena-shot/egress.nft
nft -c -f /etc/athena-shot/egress.nft || die "rendered egress.nft failed to parse"

echo "==> systemd units"
install -o root -g root -m 0644 "$SRC/kali-screenshot.service" "$UNIT"
install -d -m 0755 "$DROPIN"
cat > "$DROPIN/resolver.conf" <<EOF
[Service]
# Rendered by install.sh. Allow wins over Deny in systemd; nft pins this host to port 53.
IPAddressAllow=$RESOLVER/32
ExecStartPre=+/usr/sbin/nft -f /etc/athena-shot/egress.nft
ExecStopPost=-+/usr/sbin/nft delete table inet athena_shot
EOF
install -d -m 0755 /etc/systemd/system/kali_server.service.d
cat > /etc/systemd/system/kali_server.service.d/venv.conf <<EOF
[Service]
ExecStart=
ExecStart=$SERVER_DIR/.venv/bin/python $SERVER_DIR/kali_server.py
EOF

echo "==> proxy blueprint"
BP="$SERVER_DIR/kali_screenshot_endpoints.py"
[ -f "$BP.pre-isolation" ] || cp -p "$BP" "$BP.pre-isolation"
install -o root -g root -m 0644 "$DASH/kali-screenshot-endpoints.py" "$BP"

systemctl daemon-reload
systemctl enable kali-screenshot >/dev/null
systemctl restart kali-screenshot
systemctl restart kali_server
sleep 3
systemctl is-active --quiet kali-screenshot || die "kali-screenshot failed: journalctl -u kali-screenshot"
systemctl is-active --quiet kali_server || die "kali_server failed: journalctl -u kali_server"
echo "==> done. Verify with the checks in README.md."
