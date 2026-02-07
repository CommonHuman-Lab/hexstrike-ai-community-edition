# TTP: Reconnaissance & OSINT

Techniques for passive and active reconnaissance, subdomain takeover,
Google dorking, breach intelligence pivoting, certificate transparency
mining, and GitHub secret scanning.

**MITRE ATT&CK**: T1592 (Gather Victim Host Info), T1589 (Gather Victim Identity Info),
T1593 (Search Open Websites/Domains), T1596 (Search Open Technical Databases)

---

## Quick Decision Tree

```
IF target is a domain:
  → Subdomain enumeration → httpx probe → technology fingerprint
IF target is an IP:
  → shodan/censys lookup → port scan → service fingerprint
IF target is a person/username:
  → sherlock_investigate → social media mapping
IF target is an email:
  → hibp_breach_check → credential exposure
IF target is an organization:
  → All of the above + GitHub secret scanning + cert transparency
```

---

## 1. Subdomain Enumeration

### 1a. Passive Sources (No Direct Contact)

```
# Layer 1: Fast passive DNS
subfinder_scan(target="target.com")
→ Sources: SecurityTrails, Shodan, VirusTotal, Censys, etc.
→ Typical yield: 50-500 subdomains for medium orgs

# Layer 2: Comprehensive passive + light brute
amass_enum(target="target.com", mode="passive")
→ Certificate transparency + passive DNS + web archives
→ Slower but more thorough than subfinder

# Layer 3: Historical URLs (discover forgotten endpoints)
waybackurls_fetch(target="target.com")
→ URLs from Wayback Machine archives
→ Finds: old endpoints, removed pages, test environments

gau_fetch(target="target.com")
→ URLs from multiple archive sources (Wayback, CommonCrawl, URLScan)

# Deduplicate combined results
anew_deduplicate(input=<combined_subdomains>)
```

### 1b. Active Enumeration (Direct Contact)

```
# DNS brute force
dnsenum_enumeration(target="target.com")
→ Zone transfer attempt + dictionary brute force

# DNS resolution and filtering
dnsx_resolution(domains=<subdomain_list>)
→ Resolve all discovered subdomains
→ Filter: live vs dead, A records, CNAME records

# Wildcard detection
# If *.target.com resolves to the same IP = wildcard DNS
# Filter out wildcard responses to avoid false positives
```

### 1c. HTTP Service Probing

```
# Find live web services on discovered subdomains
httpx_probe(targets=<resolved_subdomains>)
→ Returns: status code, title, technology, content length
→ Critical for filtering down to actual web applications

# Screenshot all live hosts
aquatone_screenshot(targets=<live_hosts>)
→ Visual overview of all web applications
→ Quickly spot: login pages, admin panels, default installs
```

### 1d. Processing Pipeline

```
Complete recon pipeline:
  subfinder_scan → subdomains
  amass_enum → more subdomains
  anew_deduplicate → unique subdomains
  dnsx_resolution → resolved subdomains
  httpx_probe → live HTTP services
  aquatone_screenshot → visual inventory
  detect_technologies_ai → tech fingerprints
```

---

## 2. Subdomain Takeover

### 2a. Detection

```
subjack_takeover(target="target.com", wordlist=<subdomains>)
→ Checks CNAME records against known takeover-vulnerable services

# Manual CNAME check via dnsx:
dnsx_resolution(domains=<subdomains>, record_type="CNAME")
→ Look for CNAMEs pointing to: *.s3.amazonaws.com, *.herokuapp.com,
  *.github.io, *.azurewebsites.net, *.cloudfront.net
```

### 2b. Vulnerable Services

| Service | CNAME Pattern | Takeover Indicator |
|---------|--------------|-------------------|
| AWS S3 | `*.s3.amazonaws.com` | "NoSuchBucket" in response |
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| Heroku | `*.herokuapp.com` | "No such app" |
| Azure | `*.azurewebsites.net` | "404 Web Site not found" |
| Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Fastly | CNAME to Fastly | "Fastly error: unknown domain" |
| Ghost | `*.ghost.io` | "The thing you were looking for is no longer here" |
| Tumblr | `*.tumblr.com` | "There's nothing here" |
| WordPress.com | `*.wordpress.com` | "Do you want to register" |
| Pantheon | `*.pantheonsite.io` | "404 error unknown site" |

### 2c. Exploitation

```
# If dangling CNAME found:
# 1. Register the claimed resource on the service
#    (e.g., create S3 bucket with matching name)
# 2. Host content on the claimed resource
# 3. The subdomain now points to your content

# Severity: HIGH (P2 on most bug bounty programs)
# Enables: phishing, cookie theft, malware distribution
```

---

## 3. Infrastructure Intelligence

### 3a. Shodan (Device/Service Intelligence)

```
# Host lookup — what does the internet see?
shodan_host_lookup(target="target.com")
→ Returns: open ports, banners, OS, organization, ISP, cloud provider

# Search for all org assets
shodan_search_query(query="org:\"Target Corp\"")
shodan_search_query(query="hostname:target.com")
shodan_search_query(query="ssl:\"target.com\"")
→ Finds: all internet-facing assets for the organization

# Exploit search
shodan_exploit_search(query="apache 2.4.49")
→ Returns: known exploits for the identified service version
```

**Shodan search operators:**
```
hostname:target.com         — assets by hostname
org:"Target Corp"           — assets by organization name
net:203.0.113.0/24         — assets in IP range
port:22                     — specific port
ssl:"target.com"           — SSL certificate subjects
http.title:"Admin Panel"    — HTTP response title
product:nginx              — specific product
vuln:CVE-2021-44228        — assets vulnerable to specific CVE
country:US                 — geographic filter
```

### 3b. Censys (Certificate & Host Intelligence)

```
# Host lookup
censys_host_lookup(target="target.com")
→ Returns: services, TLS config, protocols, certificates

# Certificate transparency search
censys_certificate_search(query="target.com")
→ Finds ALL certificates ever issued for the domain
→ Reveals: subdomains, internal hostnames, email addresses
→ Often finds hostnames not in DNS (internal services with certs)

# Host search
censys_search_hosts(query="services.tls.certificates.leaf.names: target.com")
→ All hosts with certificates mentioning target.com
```

### 3c. Certificate Transparency Mining

```
# Certificates reveal hidden infrastructure:
censys_certificate_search(query="target.com")

# Look for:
# - Internal hostnames: vpn.internal.target.com, dc01.target.local
# - Development/staging: dev.target.com, staging.target.com
# - Wildcard certs: *.target.com (confirms scope)
# - Email addresses in cert subjects
# - Organization structure from OU fields
```

---

## 4. Breach Intelligence

### 4a. Email/Domain Breach Check

```
# Check if domain users appear in breaches
hibp_domain_search(domain="target.com")
→ Returns: list of breaches affecting the domain
→ Shows: which data was exposed (passwords, emails, phones)

# Check specific email
hibp_breach_check(email="admin@target.com")
→ Returns: specific breaches this email appears in

# Check paste sites
hibp_paste_check(email="admin@target.com")
→ Returns: paste sites where email was found
→ Often contains: leaked credentials, internal documents
```

### 4b. Breach Intelligence Pivoting

```
# From breach data, pivot to:

IF breached passwords found:
  → Credential stuffing attack (users reuse passwords)
  → hydra_brute_force with known passwords

IF employee emails found:
  → Password spraying with common patterns
  → Social engineering (phishing, vishing)

IF breach reveals internal structure:
  → Email format reveals naming convention
  → admin@, dev@, support@ reveal roles
  → Subdomain patterns from breached URLs

# Record findings:
add_scan_learning(target="target.com",
                  learning="Admin emails use first.last@target.com format")
```

---

## 5. Personnel & Username OSINT

### 5a. Username Investigation

```
sherlock_investigate(username="targetuser")
→ Checks 400+ social media platforms
→ Returns: list of platforms where username exists
→ Build social profile: interests, location, connections
```

### 5b. Email Harvesting

```
theharvester_scan(target="target.com", source="all")
→ Sources: Google, Bing, LinkedIn, Twitter, etc.
→ Returns: emails, subdomains, hosts, employee names

# From harvested emails:
# - Derive naming convention (john.doe, jdoe, johnd)
# - Build username list for password spraying
# - Map organizational structure
```

### 5c. Social Engineering Prep

```
# From OSINT findings, build target profile:
# 1. Employee names → LinkedIn for role/department
# 2. Email format → generate valid email list
# 3. Social media → interests, recent posts, out-of-office
# 4. Breach data → previous passwords, security awareness
# 5. Technology stack → internal tools, VPN provider
```

---

## 6. Source Code & Secret Scanning

### 6a. GitHub/GitLab Scanning

```
trufflehog_scan(target="https://github.com/target-org")
→ Deep scan of git history for secrets
→ Finds: API keys, passwords, tokens, private keys
→ Checks: all commits, including deleted ones

# What to look for:
# - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
# - GitHub personal access tokens (ghp_...)
# - Slack webhooks (https://hooks.slack.com/...)
# - Database connection strings
# - JWT signing secrets
# - TLS/SSL private keys
# - .env files committed by accident
```

### 6b. GitHub Dorking

```
# Manual GitHub search queries:
# target.com password
# target.com secret
# target.com api_key
# "target.com" filename:.env
# "target.com" filename:config
# org:target-org password
# org:target-org AWS_SECRET_ACCESS_KEY

# SpiderFoot for automated OSINT
spiderfoot_scan(target="target.com")
→ Comprehensive automated OSINT across 200+ data sources
```

---

## 7. Google Dorking

### 7a. Common Dorks

```
# These searches are done via browser or automated tools.
# HexStrike doesn't have a Google dorking tool, but these dorks
# inform what to look for with other tools.

# Sensitive files:
site:target.com filetype:pdf
site:target.com filetype:xls
site:target.com filetype:sql
site:target.com filetype:env
site:target.com filetype:log
site:target.com filetype:bak

# Exposed directories:
site:target.com intitle:"Index of"
site:target.com intitle:"Directory listing"

# Login pages:
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:wp-admin
site:target.com intitle:"Login"

# Configuration exposure:
site:target.com inurl:config
site:target.com inurl:phpinfo
site:target.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf

# Error messages (reveals technology):
site:target.com "mysql_fetch_array"
site:target.com "SQL syntax"
site:target.com "Warning:" "on line"
site:target.com intext:"Stack Trace"
```

### 7b. Dork-Informed Tool Usage

```
# Based on Google dork findings:

IF login pages found:
  → nuclei_scan(target=<login_url>, tags="default-login")
  → hydra_brute_force for credential testing

IF directory listing found:
  → browser_navigate(url=<directory_url>)
  → Look for: backup files, config files, source code

IF phpinfo found:
  → Reveals: PHP version, loaded modules, server paths
  → Informs: which exploit techniques to use

IF SQL errors found:
  → Confirmed SQL injection surface
  → sqlmap_scan on those endpoints
```

---

## 8. Network Reconnaissance

### 8a. Port Scanning Strategy

```
# Phase 1: Fast discovery
rustscan_scan(target="target.com", ports="1-65535")
→ Ultra-fast port discovery, then feed to nmap

# Phase 2: Service fingerprinting
nmap_scan(target="target.com",
          scan_type="-sV -sC",
          ports=<discovered_ports>)
→ Version detection + default NSE scripts

# Phase 3: OS detection
nmap_scan(target="target.com",
          scan_type="-O",
          additional_args="--osscan-guess")

# Phase 4: Vulnerability scripts (targeted)
nmap_scan(target="target.com",
          scan_type="-sV",
          ports=<interesting_ports>,
          additional_args="--script vuln")
```

### 8b. Network Mapping

```
# Discover network topology
arp_scan_discovery(interface="eth0", target="10.0.0.0/24")
→ Layer 2 discovery (faster than ping sweep)

nbtscan_netbios(target="10.0.0.0/24")
→ NetBIOS names reveal: hostnames, workgroups, domains

# DNS enumeration
dnsenum_enumeration(target="target.com")
→ Zone transfer attempt + brute force
→ If zone transfer succeeds = full DNS inventory (critical finding)
```

---

## 9. Modern Recon Techniques (2025–2026)

### 9a. Supply Chain Reconnaissance (OWASP 2025 #3)

```
# Mapping an organization's software supply chain:

# 1. Dependency enumeration via public repos
trufflehog_scan(target="https://github.com/target-org")
→ Not just secrets — also reveals: package managers, internal package names,
  CI/CD pipeline configs, Docker base images, cloud providers used

# 2. Dependency confusion discovery
# Find internal package names in:
# - package.json, requirements.txt, go.mod, Gemfile
# - CI/CD configs referencing private registries
# - Error messages revealing internal module names
# IF internal package name is not registered on public registry:
#   → Register it on npm/PyPI → dependency confusion attack

# 3. GitHub Actions supply chain mapping
# Check: which third-party Actions are used?
# Unpinned actions (uses: org/action@main) are hijackable
# Compromised action = code execution in target's CI pipeline

# 4. Container image provenance
# Check: are images from Docker Hub / public registries?
# Base image compromise affects all downstream builds
# Look for: images without pinned digests (tag-only)
```

### 9b. Cloud Asset Discovery (2025)

```
# Modern cloud recon goes beyond traditional subdomain enumeration:

# 1. Certificate Transparency for cloud endpoints
censys_certificate_search(query="target.com")
→ Reveals: *.internal.target.com, *.staging.target.com
→ Cloud-specific patterns:
  - *.execute-api.*.amazonaws.com (API Gateway)
  - *.cloudfront.net (CloudFront distributions)
  - *.azurewebsites.net (Azure App Service)
  - *.appspot.com (GCP App Engine)
  - *.netlify.app, *.vercel.app (Serverless platforms)

# 2. Cloud storage enumeration
# S3 bucket naming patterns: target-com-backup, target-prod, target-dev
# Azure blob: target.blob.core.windows.net
# GCP: storage.googleapis.com/target-bucket

# 3. Serverless function discovery
# Lambda URLs: *.lambda-url.*.on.aws
# Azure Functions: *.azurewebsites.net/api/*
# Cloud Run: *.run.app

# 4. Kubernetes/container registry exposure
# Look for: exposed Docker registries, Helm chart repos
# harbor.target.com, registry.target.com
nuclei_scan(target="https://target.com",
            tags="exposure,docker,kubernetes")
```

### 9c. Modern Subdomain Takeover (2025)

```
# Beyond classic CNAME takeovers — new vectors:

# 1. Dangling DNS with cloud providers
# Azure Traffic Manager profiles
# AWS Elastic Beanstalk environments
# GCP Cloud Run services (*.run.app)
# Vercel / Netlify deployments (custom domains)

# 2. NS delegation takeover
# If NS records point to a nameserver you can claim
# Full DNS control over the subdomain
# More impactful than CNAME — can create any record type

# 3. Wildcard DNS + XSS
# If *.target.com resolves, any subdomain works
# Combine with: cookie scoping, CORS, CSP bypass
# evil.target.com can set cookies for .target.com

# 4. Expired SaaS integrations
# Slack, Zendesk, Freshdesk, HelpScout custom domains
# Previous integrations with expired subscriptions
# Custom domain still points to the service

# Updated detection:
subjack_takeover(target="target.com", wordlist=<subdomains>)
→ Updated fingerprint database includes 2025 services
```

### 9d. AI-Enhanced OSINT (2025+)

```
# Using AI capabilities in reconnaissance:

# 1. Automated correlation
analyze_target_intelligence(target="target.com")
→ AI correlates findings across: Shodan, Censys, HIBP, DNS, certs
→ Identifies: attack surface clusters, technology relationships

# 2. Natural language CVE matching
correlate_threat_intelligence(target="target.com")
→ Matches discovered technologies against latest CVE feeds
→ Prioritizes: actively exploited, public PoC available

# 3. Pattern extraction from scan memory
get_scan_recommendations(target="target.com")
→ If similar targets scanned before:
  - What tools worked best?
  - What vulnerabilities were found?
  - What attack chains succeeded?

# 4. Generate exploit intelligence
generate_exploit_from_cve(cve_id="CVE-2025-XXXXX")
→ Searches: Exploit-DB, GitHub PoCs, NVD references
→ Returns: exploit code, affected versions, remediation
```

---

## Recon Pipeline: Complete Workflow

```
Step 1: Passive Intelligence
  shodan_host_lookup + censys_host_lookup → infrastructure overview
  hibp_domain_search → breach exposure
  trufflehog_scan → leaked secrets

Step 2: Subdomain Discovery
  subfinder_scan + amass_enum → subdomain list
  anew_deduplicate → unique list
  dnsx_resolution → resolved list

Step 3: Service Discovery
  httpx_probe → live web services
  nmap_scan → all service fingerprints
  aquatone_screenshot → visual inventory

Step 4: Technology Profiling
  detect_technologies_ai → tech stack per host
  wafw00f_scan → WAF detection

Step 5: Vulnerability Surface Mapping
  subjack_takeover → subdomain takeovers
  nuclei_scan(tags="exposure,misconfig") → low-hanging fruit

Step 6: Record Everything
  analyze_tool_results → structure findings
  correlate_session_findings → deduplicated report
  complete_scan_session → save to memory
```
