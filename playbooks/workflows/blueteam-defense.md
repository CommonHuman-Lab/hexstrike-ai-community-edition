# HexStrike Blue Team Defense Playbook

Defensive security assessment, hardening review, and incident response
preparation using HexStrike tools from a defender's perspective.

---

## Use Case

Blue team operators use HexStrike to:
- Assess their own infrastructure before attackers do
- Validate security controls and configurations
- Identify misconfigurations and exposures
- Verify patch effectiveness
- Prepare incident response playbooks

---

## Phase 1: Asset Discovery & Inventory

### External Attack Surface Mapping

```
# What does the internet see?
shodan_host_lookup(target="your-org.com")
→ All exposed ports, services, banners visible to attackers

censys_host_lookup(target="your-org.com")
→ TLS certificates, service fingerprints

censys_certificate_search(query="your-org.com")
→ Find ALL certificates issued to your org (reveals shadow IT)

# Subdomain inventory
subfinder_scan(target="your-org.com")
amass_enum(target="your-org.com", mode="passive")
→ Compare against your known asset inventory
→ Unknown subdomains = shadow IT or forgotten infrastructure
```

### Internal Network Discovery
```
# Map the internal network
nmap_scan(target="10.0.0.0/24",
          scan_type="-sn",
          additional_args="--max-rate 500")
→ Discover all live hosts

# Service enumeration
nmap_scan(target="10.0.0.0/24",
          scan_type="-sV -sC",
          ports="21,22,23,25,53,80,88,135,139,389,443,445,636,1433,3306,3389,5432,5985,8080,8443",
          additional_args="-O")
→ Services + OS detection

# Check for default credentials on discovered services
# (document, don't exploit)
```

### Breach Exposure Check
```
# Check if org emails appear in breaches
hibp_domain_search(domain="your-org.com")
→ List of breached accounts

# For high-value accounts
hibp_breach_check(email="ceo@your-org.com")
hibp_paste_check(email="admin@your-org.com")
```

---

## Phase 2: Vulnerability Assessment

### Automated Scanning
```
# Create defensive assessment session
create_scan_session(target="your-org.com",
                    metadata={"type": "blueteam", "assessment": "quarterly"})

# Comprehensive vulnerability scan
nuclei_scan(target="https://your-org.com",
            severity="critical,high,medium",
            tags="cve,misconfig,exposure,default-login")

# Web server misconfiguration
nikto_scan(target="https://your-org.com")

# SSL/TLS configuration audit
sslyze_scan(target="your-org.com:443")
→ Check for: weak ciphers, expired certs, missing HSTS
```

### Security Header Analysis
```
http_header_analysis(url="https://your-org.com")

# Expected headers (flag missing ones):
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY or SAMEORIGIN
# Content-Security-Policy: <policy>
# X-XSS-Protection: 0 (deprecated, CSP preferred)
# Referrer-Policy: strict-origin-when-cross-origin
# Permissions-Policy: <policy>
```

### CORS Configuration Audit
```
cors_misconfiguration_scan(target="https://your-org.com")
→ Check for: wildcard origins, null origin reflection, credential exposure
```

### DNS Security
```
dnsenum_enumeration(target="your-org.com")
→ Check for: zone transfers allowed, missing SPF/DKIM/DMARC

# Verify SPF, DKIM, DMARC records exist
dnsx_resolution(domain="your-org.com", record_type="TXT")
```

---

## Phase 3: Cloud Security Posture

### AWS Assessment
```
# CIS Benchmark compliance
prowler_scan(profile="default", region="us-east-1",
             checks="cis_level1")

# Multi-cloud assessment
scout_suite_scan(provider="aws")
→ Comprehensive findings across all AWS services

# Infrastructure-as-Code scanning
checkov_iac_scan(directory="/path/to/terraform")
terrascan_iac_scan(directory="/path/to/terraform")
```

### Container Security
```
# Scan container images for vulnerabilities
trivy_scan(target="your-registry/app:latest")
clair_vulnerability_scan(image="your-registry/app:latest")

# Docker host security
docker_bench_security_scan()
→ CIS Docker Benchmark

# Kubernetes security
kube_bench_cis()
→ CIS Kubernetes Benchmark

kube_hunter_scan(target="kubernetes-api:6443")
→ Penetration testing perspective on K8s
```

### Runtime Monitoring
```
falco_runtime_monitoring(rules="default")
→ Detect: shell in container, sensitive file access,
  unexpected network connections
```

---

## Phase 4: Internal Security Validation

### Password Policy Verification
```
# Test password strength against common lists
# Use on known test accounts or obtained hashes (with authorization)
john_crack(hash_file="test_hashes.txt",
           wordlist="rockyou.txt",
           rules="best64")
→ Any cracks = password policy too weak
```

### SMB/AD Security
```
# Check for common AD misconfigurations
enum4linux_ng_advanced(target="domain-controller.local")
→ Flags: null sessions allowed, guest access, weak password policy

smbmap_scan(target="domain-controller.local")
→ Check for: world-readable shares, sensitive data exposure

# LLMNR/NBT-NS poisoning vulnerability
# If responder captures hashes on your own network = vulnerable
responder_credential_harvest(interface="eth0", options="-A")
# -A = Analyze mode (passive, no poisoning)
```

### Web Application Security
```
# Test your own web apps
sqlmap_scan(target="https://internal-app.local/search?q=test",
            level=3, risk=2)
→ Any findings = input validation failure

dalfox_xss_scan(target="https://internal-app.local/search?q=test")
→ XSS findings = output encoding failure

# API security
api_security_scan(target="https://api.your-org.com")
jwt_toolkit_analyze(token="<sample_jwt>")
→ Check for: weak signing, missing expiry, excessive claims
```

---

## Phase 5: Hardening Checklist

### Network Hardening
- [ ] No unnecessary ports exposed externally (`shodan_host_lookup` baseline)
- [ ] SSL/TLS properly configured (`sslyze_scan` — no weak ciphers)
- [ ] DNS zone transfers disabled (`dnsenum_enumeration`)
- [ ] LLMNR/NBT-NS disabled internally (`responder` analyze mode)
- [ ] SMB signing enforced (`enum4linux_ng_advanced`)
- [ ] Network segmentation verified (`nmap_scan` from different VLANs)

### Web Application Hardening
- [ ] Security headers present (`http_header_analysis`)
- [ ] CORS properly restricted (`cors_misconfiguration_scan`)
- [ ] No SQL injection (`sqlmap_scan`)
- [ ] No XSS (`dalfox_xss_scan`)
- [ ] No directory listing (`gobuster_scan` / `feroxbuster_scan`)
- [ ] No sensitive files exposed (`.git`, `.env`, `backup.sql`)
- [ ] Rate limiting on auth endpoints

### Cloud Hardening
- [ ] CIS Benchmarks passing (`prowler_scan`, `kube_bench_cis`)
- [ ] No public S3 buckets / storage
- [ ] Container images scanned (`trivy_scan`)
- [ ] IaC security validated (`checkov_iac_scan`)
- [ ] Runtime monitoring active (`falco_runtime_monitoring`)
- [ ] MFA enforced on all admin accounts

### Credential Hygiene
- [ ] No breached credentials in use (`hibp_domain_search`)
- [ ] Password policy enforced (14+ chars, complexity)
- [ ] No secrets in source code (`trufflehog_scan`)
- [ ] Service accounts have unique passwords
- [ ] API keys rotated on schedule

---

## Phase 6: Continuous Monitoring

### Scheduled Assessments
```
# Run monthly — external attack surface
iterative_smart_scan(target="your-org.com",
                     objective="comprehensive")

# Run weekly — critical web apps
nuclei_scan(target="https://critical-app.com",
            severity="critical,high")

# Run daily — breach monitoring
hibp_domain_search(domain="your-org.com")

# Save to memory for trend analysis
complete_scan_session(session_id="<session_id>")
consolidate_scan_memory()
→ Extract patterns from past assessments
→ Identify recurring issues
```

### Metrics to Track
```
get_learned_patterns()
→ Tool effectiveness over time
→ Recurring vulnerability categories
→ Time-to-remediation trends

search_scan_memory(query="critical", target="your-org.com")
→ Historical critical findings
```

---

## Incident Response Preparation

### Pre-built Scan Templates

**Compromised Web Server:**
```
create_scan_session(target="compromised.your-org.com",
                    metadata={"type": "incident_response"})
nmap_scan(target="compromised-ip", scan_type="-sV -sC", ports="1-65535")
nuclei_scan(target="https://compromised.your-org.com", severity="critical,high")
http_header_analysis(url="https://compromised.your-org.com")
```

**Suspected Breach:**
```
hibp_breach_check(email="affected-user@your-org.com")
shodan_host_lookup(target="your-org.com")
→ Check for new exposed services
trufflehog_scan(target="https://github.com/your-org")
→ Check for leaked credentials
```

**Ransomware/Malware:**
```
volatility3_analyze(target="memory_dump.dmp", plugin="windows.pslist")
volatility3_analyze(target="memory_dump.dmp", plugin="windows.netscan")
volatility3_analyze(target="memory_dump.dmp", plugin="windows.malfind")
→ Identify malicious processes, network connections, injected code
```
