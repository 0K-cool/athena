# Kali screenshot worker (isolated)

Screenshots of target web pages run in a dedicated, unprivileged service instead of
inside the root `kali_server` process. A page that exploits the browser lands as
`athena-shot`, inside Chromium's sandbox, with a read-only system and no network path
to the box or its LAN.

```
ATHENA ──HTTP──► kali_server (root, :5000)
                   /api/tools/screenshot{,_terminal}  → forwards JSON only
                        │ Unix socket /run/athena-shot/shot.sock (0600)
                        ▼
                 kali-screenshot.service  (user athena-shot)
                   └─ Chromium, sandbox on → public internet only
```

The API is unchanged: same routes, same request and response JSON.

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
| `IPAddressDeny` loopback, RFC1918, CGNAT, link-local | A page redirecting the browser to `:5000`, local databases or the LAN |
| `egress.nft` (`meta skuid athena-shot`) | Reaching anything on the resolver host except DNS (`IPAddressAllow` is IP-level only) |
| Socket file, mode 0600 | Anything on the network reaching the worker |
| `MemoryMax`, `TasksMax`, 2 concurrent jobs, request and parameter caps | Resource exhaustion |
| HTML-escape of every terminal field, `set_content` instead of `file://` | Scan output injecting markup into evidence images |

The deny list blocks all private ranges, which fits external engagements. For an
internal engagement, allow the in-scope ranges in a drop-in.

## Install

```bash
sudo ./install.sh                      # resolver from /etc/resolv.conf
sudo ./install.sh --resolver <IPv4>    # explicit; loopback resolvers are refused
sudo ./verify.sh                       # exit status = number of failed checks
```

`verify.sh` tests effects, not config. Each check fails when there is nothing to observe
(stopped worker, no browser processes), so a stopped service reports 10 of 10 failures.
The resolver check expects nft's reject; on a resolver with nothing listening on port 80
it passes without proving the pin.

## Rollback

```bash
cd /opt/MCP-Kali-Server && cp -p kali_screenshot_endpoints.py.pre-isolation kali_screenshot_endpoints.py
systemctl disable --now kali-screenshot
rm -rf /etc/systemd/system/kali-screenshot.service* /etc/athena-shot /opt/athena-shot
systemctl daemon-reload && systemctl restart kali_server
```

The `kali_server.service.d/venv.conf` drop-in can stay; it only switches the server to
the pinned venv.
