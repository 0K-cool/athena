#!/usr/bin/env bash
# Install the isolated ATHENA screenshot worker on a Kali box running MCP-Kali-Server.
#
# Usage (as root, from a checkout of this repo):
#   sudo ./install.sh [--resolver IPV4] [--allow-cidr CIDR]... [--server-dir DIR]
#
# --resolver    DNS resolver the worker may reach (port 53 only). Default: first
#               nameserver in /etc/resolv.conf. Loopback resolvers are refused,
#               because the worker must not reach the box's own services.
# --allow-cidr  Private range the browser may load (repeatable). Private ranges are
#               denied by default, which fits external engagements; an internal
#               backend passes its in-scope ranges here. The box's own addresses
#               stay blocked regardless (egress.nft).
# --server-dir  MCP-Kali-Server directory. Default: /opt/MCP-Kali-Server
#
# Every check runs before anything is changed. Idempotent; the original blueprint
# is kept once as kali_screenshot_endpoints.py.pre-isolation.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASH="$SRC/../athena-dashboard"
SERVER_DIR=/opt/MCP-Kali-Server
RESOLVER=""
ALLOW_CIDRS=()
WORKER_DIR=/opt/athena-shot
UNIT=/etc/systemd/system/kali-screenshot.service
DROPIN=/etc/systemd/system/kali-screenshot.service.d
SERVER_DROPIN=/etc/systemd/system/kali_server.service.d

die() { echo "install.sh: $*" >&2; exit 1; }
# Under set -e an unexpected failure would otherwise exit with no message at all.
trap 'echo "install.sh: failed at line $LINENO: $BASH_COMMAND" >&2' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --resolver) RESOLVER="${2:-}"; shift 2 ;;
    --allow-cidr) ALLOW_CIDRS+=("${2:-}"); shift 2 ;;
    --server-dir) SERVER_DIR="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# ---------------------------------------------------------------- preflight
[ "$(id -u)" -eq 0 ] || die "run as root"
[ -f "$SERVER_DIR/kali_server.py" ] || die "kali_server.py not found in $SERVER_DIR"
[ -f "$SERVER_DIR/kali_screenshot_endpoints.py" ] || die "kali_screenshot_endpoints.py not found in $SERVER_DIR"
[ -f "$DASH/terminal-template.html" ] || die "terminal-template.html missing from the repo checkout"
command -v nft >/dev/null || die "nft (nftables) is required"
[ "$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1)" = "1" ] \
  || die "kernel.unprivileged_userns_clone=0: Chromium's sandbox cannot start"

if [ -z "$RESOLVER" ]; then
  RESOLVER="$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf)"
fi
[[ "$RESOLVER" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "resolver must be an IPv4 address, got '$RESOLVER'"
case "$RESOLVER" in
  127.*) die "resolver $RESOLVER is loopback; pass the upstream resolver with --resolver" ;;
esac
for c in "${ALLOW_CIDRS[@]}"; do
  [[ "$c" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ || "$c" =~ ^[0-9a-fA-F:]+/[0-9]{1,3}$ ]] \
    || die "--allow-cidr must be an IPv4 or IPv6 CIDR, got '$c'"
done

# kali_server's ExecStart is rewritten to the venv interpreter; keep its original arguments.
FRAGMENT="$(systemctl show -p FragmentPath --value kali_server.service)"
[ -n "$FRAGMENT" ] && [ -f "$FRAGMENT" ] || die "kali_server.service not found"
# systemd accepts leading whitespace; `|| true` so a no-match reaches the explicit die
# below instead of exiting silently under set -e/pipefail.
ORIG_EXEC="$(grep -m1 -E '^[[:space:]]*ExecStart=' "$FRAGMENT" | sed -E 's/^[[:space:]]*ExecStart=//' || true)"
[ -n "$ORIG_EXEC" ] || die "no ExecStart= line in $FRAGMENT"
ORIG_INTERP="${ORIG_EXEC%% *}"
ORIG_ARGS="${ORIG_EXEC#* }"
[[ "$(basename "$ORIG_INTERP")" == python3* && "$ORIG_ARGS" == *kali_server.py* ]] \
  || die "unexpected kali_server ExecStart '$ORIG_EXEC'; expected 'pythonX ... kali_server.py ...'"

echo "==> venv $SERVER_DIR/.venv"
[ -x "$SERVER_DIR/.venv/bin/python" ] || python3 -m venv "$SERVER_DIR/.venv"
"$SERVER_DIR/.venv/bin/pip" install -q -r "$SRC/requirements.txt"

# Import kali_server with the new proxy under the venv, in a scratch copy, before touching
# the live service: a missing dependency fails here instead of after a root restart.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp "$SERVER_DIR"/*.py "$STAGE/"
cp "$DASH/kali-screenshot-endpoints.py" "$STAGE/kali_screenshot_endpoints.py"
(cd "$STAGE" && "$SERVER_DIR/.venv/bin/python" -c "import kali_server") \
  || die "kali_server does not import under the venv with the proxy blueprint; nothing was changed"

# ---------------------------------------------------------------- install
echo "==> user athena-shot"
id athena-shot >/dev/null 2>&1 || useradd --system --home-dir /var/lib/athena-shot \
  --no-create-home --shell /usr/sbin/nologin --user-group athena-shot

echo "==> worker files"
install -d -o root -g root -m 0755 "$WORKER_DIR"
install -o root -g root -m 0644 "$SRC/shot_worker.py" "$WORKER_DIR/shot_worker.py"
install -o root -g root -m 0644 "$DASH/terminal-template.html" "$WORKER_DIR/terminal-template.html"
PLAYWRIGHT_BROWSERS_PATH="$WORKER_DIR/ms-playwright" "$SERVER_DIR/.venv/bin/playwright" install chromium
chmod -R a+rX "$WORKER_DIR"

echo "==> egress rules (own addresses blocked; resolver $RESOLVER on port 53 only)"
install -d -m 0755 /etc/athena-shot
sed "s/@RESOLVER@/$RESOLVER/g" "$SRC/egress.nft.in" > /etc/athena-shot/egress.nft
chmod 0644 /etc/athena-shot/egress.nft
nft -c -f /etc/athena-shot/egress.nft || die "rendered egress.nft failed to parse"

echo "==> systemd units (allowed private ranges: ${ALLOW_CIDRS[*]:-none})"
install -o root -g root -m 0644 "$SRC/kali-screenshot.service" "$UNIT"
install -d -m 0755 "$DROPIN"
rm -f "$DROPIN/resolver.conf"  # name used by earlier versions of this installer
{
  echo "[Service]"
  echo "# Rendered by install.sh. Allow wins over Deny in systemd; egress.nft still blocks"
  echo "# this box's own addresses and pins the resolver to port 53."
  echo "IPAddressAllow=$RESOLVER/32"
  for c in "${ALLOW_CIDRS[@]}"; do echo "IPAddressAllow=$c"; done
  echo "ExecStartPre=+/usr/sbin/nft -f /etc/athena-shot/egress.nft"
  echo "ExecStopPost=-+/usr/sbin/nft delete table inet athena_shot"
} > "$DROPIN/scope.conf"
install -d -m 0755 "$SERVER_DROPIN"
cat > "$SERVER_DROPIN/venv.conf" <<EOF
[Service]
# Rendered by install.sh: original ExecStart, interpreter swapped for the pinned venv.
ExecStart=
ExecStart=$SERVER_DIR/.venv/bin/python $ORIG_ARGS
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
echo "==> done. Prove it with: sudo $SRC/verify.sh"
