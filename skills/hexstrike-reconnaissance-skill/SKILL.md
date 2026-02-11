---
name: hexstrike-reconnaissance-skill
description: Perform comprehensive network reconnaissance and target discovery using HexStrike AI tools. Use when user asks to "recon target", "scan network", "enumerate services", "discover hosts", or "perform reconnaissance".
metadata:
  author: HexStrike AI
  version: "1.0.0"
  mcp-server: hexstrike-ai-mcp
  category: reconnaissance
---

# HexStrike AI Reconnaissance Skill

## Purpose

Execute comprehensive network reconnaissance and target discovery using HexStrike AI's integrated security tools. Provides systematic information gathering, service enumeration, and vulnerability identification for penetration testing engagements.

## Prerequisites

- Target IP address, domain, or network range
- HexStrike AI MCP server connection
- Appropriate permissions for target scanning

## Core Workflow

### Phase 1: Target Discovery

**Host Discovery**

```bash
# Ping sweep for network ranges
nmap_scan(target="192.168.1.0/24", scan_type="-sn")

# ARP scan for local networks
nmap_scan(target="192.168.1.1-254", scan_type="-PR")

# DNS enumeration for domains
gobuster_scan(url="target.com", mode="dns", wordlist="/usr/share/wordlists/dns/subdomains-top1million-5000.txt")
```

**Service Discovery**

```bash
# Quick port scan
nmap_scan(target="192.168.1.100", scan_type="-sS -T4")

# Service version detection
nmap_scan(target="192.168.1.100", scan_type="-sV -sC")

# OS detection
nmap_scan(target="192.168.1.100", scan_type="-A")
```

### Phase 2: Web Application Discovery

**Directory Enumeration**

```bash
# Web directory brute forcing
gobuster_scan(url="http://target.com", mode="dir", wordlist="/usr/share/wordlists/dirb/common.txt")

# Virtual host discovery
gobuster_scan(url="target.com", mode="vhost", wordlist="/usr/share/wordlists/dns/subdomains-top1million-5000.txt")
```

**Technology Detection**

```bash
# Web technology fingerprinting
httpx_probe(target="target.com", tech_detect=true, status_code=true, title=true)

# SSL/TLS analysis
nmap_scan(target="target.com", scan_type="-sV --script ssl-enum-ciphers")
```

### Phase 3: Vulnerability Discovery

**Automated Scanning**

```bash
# Nuclei vulnerability scanning
nuclei_scan(target="target.com", severity="high,critical", output_format="json")

# Web vulnerability scanning
nikto_scan(target="http://target.com")

# SQL injection testing
sqlmap_scan(url="http://target.com/page.php?id=1")
```

**Specialized Scanning**

```bash
# WordPress vulnerability assessment
wpscan_analyze(url="http://target.com")

# SMB enumeration
enum4linux_scan(target="192.168.1.100")

# SMB vulnerability scanning
nmap_scan(target="192.168.1.100", scan_type="-sV --script smb-vuln*")
```

### Phase 4: Cloud and Container Discovery

**Cloud Infrastructure**

```bash
# AWS security assessment
prowler_scan(provider="aws", profile="default", output_format="json")

# Azure security assessment
prowler_scan(provider="azure", profile="default", output_format="json")

# GCP security assessment
prowler_scan(provider="gcp", profile="default", output_format="json")
```

**Container Security**

```bash
# Docker security scanning
docker_bench_security_scan(output_file="/tmp/docker-scan-results.json")

# Kubernetes security assessment
kube_bench_cis(targets="master,node", output_format="json")

# Container vulnerability scanning
trivy_scan(scan_type="image", target="nginx:latest", severity="HIGH,CRITICAL")
```

### Phase 5: Advanced Reconnaissance

**Intelligence Gathering**

```bash
# OSINT domain analysis
amass_scan(domain="target.com", mode="enum")

# Subdomain discovery
subfinder_scan(domain="target.com", all_sources=true)

# URL discovery
gau_discovery(domain="target.com", include_subs=true)

# Historical data analysis
waybackurls_discovery(domain="target.com", get_versions=true)
```

**Parameter Discovery**

```bash
# HTTP parameter discovery
arjun_scan(url="http://target.com/search", method="GET")

# Parameter mining
paramspider_mining(domain="target.com", level=2)

# Advanced parameter discovery
x8_parameter_discovery(url="http://target.com/api", wordlist="/usr/share/wordlists/x8/params.txt")
```

## HexStrike AI Integration

### Tool Selection Strategy

**Automatic Tool Selection**

- **Network targets**: nmap, masscan, rustscan
- **Web targets**: gobuster, httpx, nuclei, nikto
- **Cloud targets**: prowler, scout-suite, cloudmapper
- **Container targets**: trivy, docker-bench, kube-bench

**Smart Parameter Optimization**

- Automatically adjust scan timing based on target responsiveness
- Use appropriate wordlists for different target types
- Apply stealth techniques for sensitive environments

### AI-Powered Analysis

**Intelligent Correlation**

- Cross-reference findings across multiple tools
- Identify attack paths and privilege escalation opportunities
- Prioritize vulnerabilities based on exploitability

**Context-Aware Recommendations**

- Suggest next steps based on discovered services
- Recommend specific exploitation techniques
- Provide remediation guidance

## Output Format

### Reconnaissance Report Structure

1. **Executive Summary**
   - Target overview
   - Key findings
   - Risk assessment

2. **Technical Findings**
   - Host discovery results
   - Service enumeration details
   - Vulnerability assessment
   - Attack surface analysis

3. **Recommendations**
   - Immediate security concerns
   - Long-term security improvements
   - Specific remediation steps

### Example Output

```json
{
  "target": "example.com",
  "discovery": {
    "hosts": ["192.168.1.100", "192.168.1.101"],
    "services": [
      {"port": 80, "service": "HTTP", "version": "Apache 2.4.54"},
      {"port": 443, "service": "HTTPS", "version": "Apache 2.4.54"}
    ],
    "vulnerabilities": [
      {"cve": "CVE-2022-22965", "severity": "CRITICAL", "service": "Apache"}
    ]
  },
  "recommendations": [
    "Update Apache to latest version",
    "Implement WAF protection",
    "Review exposed services"
  ]
}
```

## Constraints and Limitations

### Legal and Ethical

- **Authorization Required**: Only scan authorized targets
- **Scope Compliance**: Stay within defined testing boundaries
- **Data Protection**: Handle discovered data responsibly

### Technical Limitations

- **Network Access**: Requires connectivity to target systems
- **Tool Dependencies**: Depends on HexStrike AI MCP server availability
- **Rate Limiting**: May trigger IDS/IPS systems on aggressive scans

### Performance Considerations

- **Scan Duration**: Comprehensive scans may take 30+ minutes
- **Resource Usage**: Multiple concurrent scans consume system resources
- **Network Impact**: Large scans may affect target performance

## Troubleshooting

### Common Issues

**Scan Timeout**

- Reduce scan concurrency
- Increase timeout values
- Use stealth scanning techniques

**Tool Failures**

- Verify MCP server connection
- Check tool availability
- Review error logs

**Incomplete Results**

- Adjust scan parameters
- Use multiple scanning techniques
- Verify target accessibility

### Optimization Tips

**Speed Optimization**

- Use parallel scanning where possible
- Implement smart timing adjustments
- Cache results for repeated scans

**Accuracy Improvement**

- Cross-validate findings with multiple tools
- Use specialized tools for specific services
- Apply context-aware analysis

## Integration Examples

### Bug Bounty Workflow

```bash
# 1. Initial reconnaissance
hexstrike-reconnaissance-skill --target "bugbounty-target.com"

# 2. Deep web application analysis
hexstrike-reconnaissance-skill --target "bugbounty-target.com" --mode "web-app"

# 3. API security assessment
hexstrike-reconnaissance-skill --target "api.bugbounty-target.com" --mode "api"
```

### Red Team Operations

```bash
# 1. External perimeter reconnaissance
hexstrike-reconnaissance-skill --target "company.com" --mode "external"

# 2. Internal network discovery
hexstrike-reconnaissance-skill --target "192.168.1.0/24" --mode "internal"

# 3. Cloud environment assessment
hexstrike-reconnaissance-skill --target "company-aws" --mode "cloud"
```
