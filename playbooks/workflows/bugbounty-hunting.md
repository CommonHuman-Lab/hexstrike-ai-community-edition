# HexStrike Bug Bounty Hunting Playbook

Systematic bug bounty methodology optimized for maximum impact findings.
Every technique maps to exact HexStrike MCP tool calls with parameters.

---

## Pre-Hunt Setup

```
# Create a session to track all findings
create_scan_session(target="target.com",
                    metadata={"type": "bugbounty", "program": "HackerOne/Bugcrowd"})

# Check past experience with this target
get_scan_recommendations(target="target.com")
```

**Scope checklist before starting:**
- Confirm in-scope domains/IPs (wildcard vs explicit)
- Note out-of-scope assets
- Check program policy for: rate limits, automated scanning rules, no-DoS
- Identify bounty tiers (what pays the most)

---

## Phase 1: Attack Surface Discovery

### 1a. Subdomain Enumeration (Cast Wide Net)

```
# Layer 1: Passive subdomain sources
subfinder_scan(target="target.com")
amass_enum(target="target.com", mode="passive")

# Layer 2: Historical URLs (finds forgotten endpoints)
waybackurls_fetch(target="target.com")
gau_fetch(target="target.com")

# Layer 3: Deduplicate and filter
anew_deduplicate(input=<combined_subdomains>)

# Layer 4: Probe for live HTTP services
httpx_probe(targets=<deduplicated_subdomains>)
```

**Why layered approach**: Each tool has different data sources. subfinder uses
passive DNS, amass uses certificate transparency + DNS brute, waybackurls/gau
find archived endpoints that may still be live.

### 1b. Subdomain Takeover Check

```
# Quick check for dangling DNS records
subjack_takeover(target="target.com", wordlist=<subdomains>)
```

**High-value finding**: Subdomain takeovers are typically P2/High severity
on most programs. If `subjack_takeover` finds a dangling CNAME pointing to
an unclaimed cloud service (S3, Heroku, GitHub Pages), this is immediately
exploitable.

### 1c. Technology Fingerprinting

```
detect_technologies_ai(target="target.com")
→ Returns: backend language, framework, CMS, WAF, CDN

# Check for WAF (critical for payload selection later)
wafw00f_scan(target="https://target.com")
```

**Decision tree based on tech stack:**
```
IF WordPress detected → wpscan_analyze(enumerate="vp,vt,u")
IF Joomla detected   → nuclei_scan(tags="joomla")
IF Node.js detected  → Focus on prototype pollution, SSRF
IF PHP detected      → Focus on SQLi, LFI, type juggling
IF Java detected     → Focus on deserialization, SSTI (Freemarker/Thymeleaf)
IF .NET detected     → Focus on ViewState deserialization, path traversal
```

---

## Phase 2: Content & Parameter Discovery

### 2a. Directory Bruteforce

```
# Fast initial pass
ffuf_scan(url="https://target.com/FUZZ",
          wordlist="common.txt", mc="200,301,302,403")

# Deep pass on interesting paths
feroxbuster_scan(target="https://target.com",
                 extensions="php,asp,aspx,jsp,json,xml,bak,old",
                 depth=3)

# Backup/config file hunting
gobuster_scan(target="https://target.com",
              wordlist="backup-files.txt",
              extensions="bak,old,sql,zip,tar.gz,swp,config")
```

### 2b. Parameter Discovery (Where Bugs Live)

```
# Automated parameter discovery
arjun_parameter_discovery(url="https://target.com/api/search")
x8_parameter_discovery(url="https://target.com/endpoint")

# Mine parameters from historical URLs
paramspider_mining(target="target.com")

# Optimize URL list (remove duplicates, normalize)
uro_optimize(urls=<paramspider_output>)

# Pattern matching for interesting parameters
gf_pattern_match(pattern="sqli", input=<url_list>)
gf_pattern_match(pattern="xss", input=<url_list>)
gf_pattern_match(pattern="ssrf", input=<url_list>)
gf_pattern_match(pattern="redirect", input=<url_list>)
```

### 2c. JavaScript Analysis

```
# Deep crawl including JavaScript
katana_crawl(target="https://target.com", depth=3, js_crawl=True)

# Look for:
# - API endpoints in JS files
# - Hardcoded secrets (API keys, tokens)
# - Hidden admin panels
# - WebSocket endpoints
# - GraphQL endpoints
```

---

## Phase 3: Vulnerability Hunting (Priority Order)

Hunt in order of bounty impact: Critical → High → Medium.

### 3a. Critical Impact — RCE, SQLi, SSRF

**SQL Injection** (read `hexstrike://ttp/web-injection` for deep guide):
```
# Test parameters identified by gf_pattern_match
sqlmap_scan(target="https://target.com/page?id=1",
            level=5, risk=3, tamper="space2comment")

# If WAF detected, use tamper scripts:
# Cloudflare: tamper="charunicodeescape"
# ModSecurity: tamper="space2comment,between"
# AWS WAF: tamper="randomcase,percentage"
```

**Server-Side Request Forgery (SSRF)**:
```
# Test URL/redirect parameters
http_repeater(url="https://target.com/fetch",
              method="POST",
              body={"url": "http://169.254.169.254/latest/meta-data/"})

# AWS metadata endpoint — if response contains IAM data, critical SSRF
# Also test: http://127.0.0.1, http://[::1], http://0x7f000001
```

**Remote Code Execution**:
```
commix_scan(target="https://target.com/ping?host=127.0.0.1")
tplmap_scan(target="https://target.com/render?name=test")

# Template injection detection payloads:
# {{7*7}} → 49 means Jinja2/Twig SSTI
# ${7*7} → 49 means EL injection
# #{7*7} → 49 means Ruby ERB
```

### 3b. High Impact — XSS, IDOR, Auth Bypass

**Cross-Site Scripting** (read `hexstrike://ttp/web-injection#xss`):
```
dalfox_xss_scan(target="https://target.com/search?q=test")
xsser_scan(target="https://target.com/search", parameter="q")

# Manual verification via http_repeater:
http_repeater(url="https://target.com/search",
              params={"q": "<img src=x onerror=alert(1)>"})
```

**IDOR** (read `hexstrike://ttp/auth-attacks#idor`):
```
# Test with http_repeater — change ID values
http_repeater(url="https://target.com/api/users/123",
              headers={"Authorization": "Bearer <your_token>"})
# Then try /api/users/124, /api/users/1, /api/users/0

# Test with different HTTP methods
http_method_scanner(url="https://target.com/api/users/123")
```

**Authentication Bypass** (read `hexstrike://ttp/auth-attacks`):
```
jwt_toolkit_analyze(token="<captured_jwt>")
→ Tests: alg:none, key confusion, brute force

# Test for broken access control
http_repeater(url="https://target.com/admin",
              headers={"Authorization": "Bearer <regular_user_token>"})
```

### 3c. Medium Impact — Open Redirect, Info Disclosure, CORS

```
# Open redirect
http_redirect_tracer(url="https://target.com/redirect?url=https://evil.com")

# CORS misconfiguration
cors_misconfiguration_scan(target="https://target.com")

# Information disclosure
http_header_analysis(url="https://target.com")
→ Check for: X-Powered-By, Server version, debug headers

# Secrets in source
trufflehog_scan(target="https://github.com/target-org")
```

---

## Phase 4: Automated Scanning (Supplement Manual Testing)

```
# Nuclei with bug bounty relevant templates
nuclei_scan(target="https://target.com",
            severity="critical,high",
            tags="cve,takeover,exposure,misconfig")

# Full vulnerability assessment
ai_vulnerability_assessment(target="target.com",
                           scope=<in_scope_domains>)
```

---

## Phase 5: Report & Submit

```
# Correlate all findings
correlate_session_findings(session_id="<session_id>")

# Generate bug bounty report format
generate_report(session_id="<session_id>", format="markdown")
```

**Bug bounty report template:**
```
Title: [Vuln Type] in [endpoint] allows [impact]

## Summary
Brief description of the vulnerability.

## Steps to Reproduce
1. Navigate to https://target.com/endpoint
2. Inject payload: [payload]
3. Observe: [result]

## Impact
What can an attacker do? Data theft, account takeover, RCE?

## Proof of Concept
[Screenshot/response showing exploitation]

## Remediation
Recommended fix.
```

```
# Save to memory for future reference
complete_scan_session(session_id="<session_id>")
add_scan_learning(target="target.com",
                  learning="WAF bypass required Cloudflare tamper scripts")
```

---

## High-Value Target Patterns

| Target Type | Highest Impact Bugs | Primary Tools |
|------------|-------------------|---------------|
| REST API | IDOR, mass assignment, broken auth | `arjun_scan`, `http_repeater`, `jwt_toolkit_analyze` |
| GraphQL | Introspection, injection, DoS | `graphql_introspection`, `nuclei_scan` |
| WordPress | Plugin RCE, SQLi, auth bypass | `wpscan_analyze`, `nuclei_scan` |
| Single Page App | XSS, API abuse, JWT attacks | `dalfox_xss_scan`, `katana_crawl` |
| Mobile API | IDOR, broken auth, rate limit bypass | `http_repeater`, `ffuf_scan` |
| Cloud Assets | S3 misconfig, SSRF to metadata | `subjack_takeover`, `http_repeater` |
