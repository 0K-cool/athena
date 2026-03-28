# RESEARCH: Evidence Capture System — Client-Grade Exploit Evidence

**Date:** March 28, 2026
**Priority:** HIGH — Core deliverable quality. Without reproducible evidence, reports are claims not proof.
**Status:** DEEP RESEARCH NEEDED — Dedicated session

## The Standard

Every confirmed exploit in a client report MUST have evidence that lets the client **reproduce the exploit independently** to confirm it's real. This means:

1. **Exact command used** (copy-paste ready)
2. **Full output showing success** (uid=0, shell banner, data accessed)
3. **Screenshot of the exploit in action** (terminal for CLI exploits, browser for web exploits)
4. **The specific vulnerable URL/endpoint/port** (not just the IP)
5. **Before/after state** where applicable (e.g., "unauthenticated → admin access")

## Current State (eng-8899fe, March 28, 2026)

| Metric | Count | Quality |
|---|---|---|
| Command output artifacts | 61 | GOOD — has commands + results |
| Screenshots | 1 | POOR — one web homepage screenshot |
| VF nmap screenshots | Sometimes | EXCELLENT when they fire (like the vsftpd nmap NSE proof) |

## Gap Analysis

### Terminal Exploits (FTP, SSH, Samba, MySQL, bindshell)
- **What we have:** Command output text (good)
- **What we need:** Screenshot of terminal showing the exploit command + result (e.g., `nc 10.1.1.25 6200` → `uid=0(root) gid=0(root)`)
- **Current behavior:** Server auto-screenshot SKIPS terminal ports (Bug #8 fix — correct, web screenshot is useless for terminal exploits)
- **Gap:** No alternative terminal screenshot mechanism

### Web Exploits (Tomcat, phpMyAdmin, WebDAV, PHP injection)
- **What we have:** 1 auto-screenshot of the homepage (useless)
- **What we need:** Screenshot of the ACTUAL vulnerable page:
  - Tomcat manager: `http://10.1.1.25:8180/manager/html` (logged in as tomcat:tomcat)
  - phpMyAdmin: `http://10.1.1.25/phpMyAdmin/` (no-auth root access)
  - WebDAV: `http://10.1.1.25/dav/` (showing PUT succeeded)
  - PHP CGI: The actual RCE output page
- **Current behavior:** Auto-screenshot hits `http://10.1.1.25` (port 80 homepage) regardless of what was exploited
- **Gap:** No URL path awareness. The finding says "Tomcat Manager on port 8180" but the screenshot captures `:80/`

### Evidence Linking
- **What we have:** Artifacts loosely linked to findings by finding_id
- **What we need:** Each finding → ordered evidence chain: (1) discovery screenshot, (2) exploitation command, (3) exploitation output, (4) proof screenshot
- **Gap:** No evidence ordering or chain concept

## Research Questions

1. **Can Kali screenshot endpoints capture terminal state?** Does the Kali backend have a `screenshot_terminal` endpoint that captures the current terminal session? If not, can we add one?

2. **Can agents capture their own evidence?** EX/VF know exactly what they just did. Can we make screenshot capture a MANDATORY step in the agent workflow (not optional prompt compliance)?

3. **How do other pentest platforms handle evidence?** Research Cobalt Strike, PlexTrac, Dradis, Faraday — what evidence do they capture per finding?

4. **Can we extract URL paths from finding data?** When WV finds Tomcat default creds at `:8180/manager/html`, is the full URL stored anywhere we can use for screenshot targeting?

5. **Can Playwright/agent-browser capture web evidence?** Use playwright-cli to open the actual vulnerable URL and screenshot it — would need the URL from the finding data.

## Proposed Architecture (To Be Validated by Research)

### Tier 1: Agent-Driven Evidence (Best Quality)
- **EX mandatory:** After each exploit, EX MUST capture:
  - `screenshot_terminal` of the shell/output
  - The exact command used (already in tool output)
  - Upload as evidence artifact linked to finding
- **VF mandatory:** After each verification:
  - Screenshot of the independent verification (nmap NSE, manual test)
  - The verification command + output
- **WV mandatory:** After each web vuln:
  - `screenshot_web` of the VULNERABLE PAGE (not homepage)
  - The full URL that was tested
  - Request/response pair

### Tier 2: Server-Side Auto-Capture (Fallback)
- When finding is confirmed and agent didn't capture evidence:
  - Web findings: screenshot the specific port + path from finding data
  - Terminal findings: capture last N lines of agent tool output as a formatted "terminal screenshot" image
  - Triggered by confirmation event (existing `_trigger_auto_screenshot` pattern)

### Tier 3: Kali Backend Enhancement
- Add `screenshot_terminal` endpoint to Kali backend if it doesn't exist
- Endpoint captures the current terminal state (last command + output) as a PNG
- Agents call it after successful exploits

## Success Criteria

After this research + implementation:
- Every confirmed exploit has ≥2 evidence artifacts (command + screenshot)
- Web exploits show the actual vulnerable page (correct URL + port + path)
- Terminal exploits show the shell/output (terminal screenshot or formatted command output)
- Evidence is ordered: discovery → exploitation → proof
- Client can read the report and reproduce every finding

## Files That Will Need Changes

- `agent_configs.py` — EX/VF/WV prompts (mandatory evidence capture)
- `server.py` — `_trigger_auto_screenshot` (URL path awareness)
- `kali_client.py` or Kali backend — `screenshot_terminal` endpoint
- `index.html` — Evidence Gallery improvements (ordering, chains)
- Kali backend (`mcp_server.py`) — new screenshot endpoint

## Comparable Products to Research

- **PlexTrac** — How do they handle evidence per finding?
- **Cobalt Strike** — Beacon screenshots + keystrokes
- **Dradis** — Evidence attachment workflow
- **Faraday** — Evidence linking model
- **Burp Suite** — Request/response pair storage
- **Metasploit** — Session screenshots + loot
