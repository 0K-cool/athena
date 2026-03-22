# ATHENA 0-Day Research & Bug Bounty Training Roadmap

**Created:** 2026-03-22
**Status:** Roadmap
**Owner:** Kelvin Lomboy / ZeroK Labs

## Current Capability vs Target

| Capability | Current | Target for Bug Bounty |
|-----------|---------|----------------------|
| Known CVE exploitation | ✅ Strong | ✅ Keep |
| Misconfiguration detection | ✅ Strong | ✅ Keep |
| Logic bugs (IDOR, auth bypass) | ⚠️ DA hypothesizes but weak probes | ✅ Must improve |
| SSRF / SSJI / Deserialization | ❌ No specialized testing | ✅ Critical for bounties |
| Race conditions | ❌ No timing-based testing | ✅ High-value bugs |
| API testing (GraphQL, REST) | ❌ No API-specific scanning | ✅ Common bounty target |
| Source code review | ❌ No SAST capability | ✅ Open source targets |
| Fuzzing | ❌ No fuzzing infrastructure | ✅ Crash → vuln → exploit |
| Client-side JS analysis | ❌ No browser-based testing | ⚠️ Nice to have |

## Training Data to Index into RAG

### Priority 1 — Bug Bounty Patterns (Index ASAP)

| Source | What It Provides | Size |
|--------|-----------------|------|
| **HackerOne Hacktivity** (public disclosures) | Real bugs that got paid — targets, techniques, payloads | Scrape top 500 reports |
| **PortSwigger Web Academy** | All web vuln categories with detailed explanations + labs | ~200 topics |
| **Bug bounty writeups** (top hunters' blogs) | Creative attack chains, edge cases scanners miss | Curate 100 best writeups |
| **HackTricks** (book.hacktricks.xyz) | Comprehensive pentest methodology wiki | Full site |
| **OWASP Testing Guide v5** | Systematic testing methodology for every vuln class | Full guide |

### Priority 2 — Exploit Development

| Source | What It Provides |
|--------|-----------------|
| **PayloadsAllTheThings** | ✅ Already in RAG — payload collections for every vuln class |
| **InternalAllTheThings** | ✅ Already in RAG — internal network attack techniques |
| **Atomic Red Team** | ✅ Already in RAG — TTPs mapped to MITRE ATT&CK |
| **GTFOBins** | Unix binaries for privilege escalation |
| **LOLBAS** | ✅ Already in RAG — Windows living-off-the-land binaries |
| **WADComs** | Windows/AD post-exploitation commands |
| **SecLists** | Wordlists for fuzzing, passwords, directories |

### Priority 3 — Advanced Techniques

| Source | What It Provides |
|--------|-----------------|
| **Frida scripts collection** | Mobile/desktop app instrumentation |
| **Nuclei community templates** | Custom vuln detection templates |
| **Semgrep rules** | Source code vulnerability patterns |
| **CodeQL queries** | GitHub security analysis queries |
| **Snyk vulnerability DB** | Dependency vulnerability data |

## New Tools to Add to Kali

### For Logic Bugs
- **Autorize** (Burp extension concept) — automated auth testing
- **paraminer** — hidden parameter discovery
- **Arjun** — HTTP parameter discovery

### For Fuzzing
- **ffuf** — already in registry ✅
- **wfuzz** — web application fuzzer
- **Boofuzz** — network protocol fuzzer
- **radamsa** — mutation-based fuzzer

### For API Testing
- **Kiterunner** — already in registry ✅
- **GraphQL Voyager** — schema introspection
- **Postman/Newman** — API test automation

### For Race Conditions
- **turbo-intruder** concept — parallel request racing
- Custom Python scripts via execute_command

### For Source Code
- **Semgrep** — SAST scanning
- **CodeQL** — deep code analysis
- **trufflehog** — secret scanning in repos

## New Agent: SAST Agent (SA)

For open-source bug bounty targets where source code is available:

```
SA — Source Code Analysis Agent
  - Clone target repo from GitHub
  - Run Semgrep with security rulesets
  - Run trufflehog for leaked secrets
  - Identify sinks (SQL queries, exec, file ops)
  - Trace user input to sinks (taint analysis)
  - Generate findings for EX to validate
  - CC ST with source-level vulnerability map
```

## DA Enhancement: Hypothesis Templates

Give DA structured hypothesis templates for common bug bounty patterns:

```
HYPOTHESIS TEMPLATES:
1. IDOR: "If endpoint /api/users/{id} returns user data, can I access other users
   by incrementing the ID? Test with authenticated session for user A, request user B's data."

2. AUTH BYPASS: "If /admin requires authentication, does /Admin, /ADMIN, /admin/,
   /admin;, /admin%00, or /admin..;/ bypass the check?"

3. SSRF: "If the app fetches URLs (webhooks, image proxy, PDF gen), can I make it
   request internal services? Test: http://127.0.0.1, http://169.254.169.254,
   http://[::1], http://0x7f000001"

4. RACE CONDITION: "If the app has a one-time action (coupon redemption, vote),
   can I send 10 parallel requests and get it applied multiple times?"

5. MASS ASSIGNMENT: "If POST /api/user accepts {name, email}, does it also accept
   {name, email, role: 'admin', is_admin: true}?"

6. JWT BYPASS: "If JWT is used, test: alg:none, alg:HS256 with public key,
   expired token, modified claims, kid injection"
```

## Success Metrics

| Metric | Current | Target (3 months) | Target (6 months) |
|--------|---------|-------------------|-------------------|
| HackerOne CTF score | Not tested | 50% | 70% (match XBOW) |
| Logic bugs found | 0 | 5/engagement | 10/engagement |
| Bug bounty submissions | 0 | 5/month | 20/month |
| Acceptance rate | N/A | 30% | 50% |
| Monthly bounty revenue | $0 | $2K | $10K |

## Phased Implementation

### Phase 1: Data (Weeks 1-2)
- Scrape + index HackerOne Hacktivity (top 500 reports)
- Index HackTricks, OWASP Testing Guide
- Index PortSwigger Web Academy topics
- Curate 100 best bug bounty writeups → RAG

### Phase 2: Tools (Weeks 3-4)
- Add wfuzz, Arjun, paraminer to Kali + tool registry
- Add race condition testing scripts
- Add GraphQL introspection tools
- Test on DVWA, Juice Shop, HackTheBox

### Phase 3: DA Enhancement (Weeks 5-6)
- Add hypothesis templates to DA prompt
- Add IDOR/auth bypass/SSRF/race condition probe patterns
- PX gets specialized probe execution for each pattern
- Benchmark against PortSwigger labs

### Phase 4: SAST Agent (Weeks 7-8)
- Build SA agent for source code analysis
- Semgrep + trufflehog on Kali
- Test against open-source bug bounty targets
- Integrate SA findings into EX pipeline

### Phase 5: Benchmark + Launch (Weeks 9-12)
- Run HackerOne CTF challenges
- Measure: accuracy, speed, false positive rate
- Compare against XBOW published benchmarks
- Launch Bug Bounty Autopilot (Phase 2 from autopilot doc)

## The Vision

```
6 AM: ATHENA finishes overnight bug bounty run
7 AM: Kelvin wakes up, reviews 5 submissions over coffee
7:30 AM: Submits 3 valid bugs to HackerOne
8 AM: Checks surf at Pine Grove — waves are firing
8:30 AM: Paddles out
10 AM: $3,500 bounty notification on phone
```

ATHENA works while Kelvin lives. 🦖⚡🏄‍♂️🇵🇷
