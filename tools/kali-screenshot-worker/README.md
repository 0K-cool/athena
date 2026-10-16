# Kali screenshot worker (isolated)

Screenshots of target web pages run in a dedicated, unprivileged service instead of
inside the root `kali_server` process. A page that exploits the browser lands as
`athena-shot`, inside Chromium's sandbox, with a read-only system and no network path
to the box's own addresses (any address, any family) or, by default, to private ranges.

```
ATHENA ──HTTP──► kali_server (root, :5000)
                   /api/tools/screenshot{,_terminal}  → forwards JSON only
                        │ Unix socket /run/athena-shot/shot.sock (0600)
                        ▼
                 kali-screenshot.service  (user athena-shot)
                   └─ Chromium, sandbox on → internet + any --allow-cidr ranges
```

Routes and response fields are unchanged. Inputs are now bounded (viewport 200-3840,
`wait_ms` up to 15000, `max_lines` up to 2000), and every failure, including a stopped
or busy worker, keeps the existing HTTP 200 + `{"success": false, "error": ...}` shape.

## Files

| File | Installed to | Purpose |
| --- | --- | --- |
| `shot_worker.py` | `/opt/athena-shot/` | Worker: validation, rendering, Chromium |
| `../athena-dashboard/kali-screenshot-endpoints.py` | `<server-dir>/kali_screenshot_endpoints.py` | Root-side proxy blueprint |
| `kali-screenshot.service` | `/etc/systemd/system/` | Hardened unit |
| `egress.nft.in` | `/etc/athena-shot/egress.nft` | Pins the resolver host to port 53 |
| `requirements.txt` | `<server-dir>/.venv` | Pinned runtime (pip Playwright bundles its own Node driver) |
| `install.sh` / `verify.sh` | — | Install, then prove the effect |

## Controls

| Control | Stops |
| --- | --- |
| `User=athena-shot`, `NoNewPrivileges`, empty `CapabilityBoundingSet` | Exploit code inheriting admin rights |
| `chromium_sandbox=True` | A compromised tab leaving Chromium's sandbox (needs unprivileged user namespaces) |
| `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices` | Writes to the system, reads of home dirs and keys |
| `IPAddressDeny` loopback, RFC1918, CGNAT, link-local, ULA | A page redirecting the browser to the LAN or other private networks |
| `egress.nft`: `fib daddr type local` reject | The browser reaching any address of the box itself, whatever `--allow-cidr` opens |
| `egress.nft`: resolver pin | Reaching anything on the resolver host except DNS (`IPAddressAllow` is IP-level only) |
| Socket file, mode 0600 | Anything on the network reaching the worker |
| `MemoryMax`, `TasksMax`, 3 concurrent jobs (10 s queue), request and parameter caps | Resource exhaustion |
| HTML-escape of every terminal field, `set_content` instead of `file://` | Scan output injecting markup into evidence images |

Private ranges are denied by default, which fits external engagements. The internal
backend screenshots private targets, so install it with each in-scope range:
`--allow-cidr 10.20.0.0/16`. The box's own addresses stay blocked either way, because
nft evaluates that rule before anything else.

### Residual risk

- The own-address block lives in nft. If another tool runs `nft flush ruleset` while the
  worker is up, that block is gone until the worker restarts; `IPAddressDeny` still covers
  loopback and private ranges, but not the box's public addresses.
- `--allow-cidr` ranges that cover a container or VM bridge on the box (Docker, libvirt)
  make those guests reachable: their addresses are not local to the box, so nft does not
  block them. Keep in-scope ranges off local bridges.
- After a full sandbox escape the browser shares the host network namespace and can reach
  world-connectable Unix sockets. The root proxy only talks to a peer running as
  `athena-shot` (`SO_PEERCRED`) and bounds what it reads back.

## Install

```bash
sudo ./install.sh                      # resolver from /etc/resolv.conf
sudo ./install.sh --resolver <IPv4>    # explicit; loopback resolvers are refused
sudo ./install.sh --allow-cidr <CIDR>  # internal backend: repeat per in-scope range
sudo ./verify.sh                       # exit status = number of failed checks
```

The installer runs every check first, including importing `kali_server` under the venv
with the new proxy in a scratch copy. A failure there leaves the running services, units
and blueprint untouched (only the venv packages may have been installed).

`verify.sh` tests effects, not config. Each check fails when there is nothing to observe
(stopped worker, no browser processes), so a stopped service reports 10 of 10 failures.
Network blocks pass only if the probe fails AND the nft rule that blocks it counts the
packet, so a closed port or a crash cannot pass as "blocked".

## Rollback

```bash
cd /opt/MCP-Kali-Server && cp -p kali_screenshot_endpoints.py.pre-isolation kali_screenshot_endpoints.py
.venv/bin/playwright install chromium   # the in-process blueprint uses root's browser cache
systemctl disable --now kali-screenshot
rm -rf /etc/systemd/system/kali-screenshot.service* /etc/athena-shot /opt/athena-shot
systemctl daemon-reload && systemctl restart kali_server
```

This restores in-process screenshots (as root, no sandbox) on the pinned venv. The
`kali_server.service.d/venv.conf` drop-in stays: without it the server falls back to the
system Playwright package. The `athena-shot` user remains and can be removed with
`userdel athena-shot`.
