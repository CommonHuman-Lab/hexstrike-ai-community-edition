# HexStrike Adaptive Scan Planning

How HexStrike's `iterative_smart_scan` automatically adjusts scan depth
and tool selection based on target complexity, engagement type, and time
constraints.

---

## Target Complexity Classification

The decision engine classifies targets before selecting tools:

### Simple Target
- Single IP or hostname
- Few open ports (< 10)
- No WAF detected
- Standard technology stack

**Tool selection**: Minimal set, fast execution.
```
iterative_smart_scan(target="10.0.0.1", objective="quick")
→ nmap_scan → nuclei_scan → correlate
→ Estimated time: 5-10 minutes
```

### Medium Target
- Domain with 5-20 subdomains
- 10-50 open ports/services
- Standard WAF (ModSecurity, CloudFlare)
- Multiple technology stacks

**Tool selection**: Balanced depth/speed.
```
iterative_smart_scan(target="target.com", objective="comprehensive")
→ subfinder → httpx → nmap → nuclei → gobuster → sqlmap (on findings)
→ Estimated time: 30-60 minutes
```

### Complex Target
- Large organization with 50+ subdomains
- Multiple /24 networks in scope
- Advanced WAF/CDN
- Diverse technology stacks (cloud + on-prem)

**Tool selection**: Full depth, parallel execution where possible.
```
iterative_smart_scan(target="big-corp.com", objective="comprehensive")
→ Full recon suite → technology-specific tools → exploitation tools
→ Estimated time: 2-4 hours
→ Multiple iterations with progressive refinement
```

---

## Classification Algorithm

The decision engine uses these signals:

| Signal | Simple | Medium | Complex |
|--------|--------|--------|---------|
| Subdomains found | 0-5 | 5-20 | 20+ |
| Open ports | 1-10 | 10-50 | 50+ |
| Technology stacks | 1 | 2-3 | 4+ |
| WAF presence | None | Standard | Advanced/multiple |
| Cloud services | None | 1 provider | Multi-cloud |
| Historical scans | None | Some data | Rich history |

```
analyze_target_intelligence(target="target.com")
→ Returns: target_type, complexity_score, recommended_depth
→ Used internally by iterative_smart_scan
```

---

## Scan Depth Profiles

### Quick Scan (objective="quick")
**When**: Time-limited, initial triage, known target.
```
Tools selected: Top 3 by effectiveness for target type
Max iterations: 1
Time budget: < 15 minutes
```

### Comprehensive Scan (objective="comprehensive")
**When**: Full assessment, no time pressure.
```
Tools selected: All relevant for target type + findings-driven additions
Max iterations: 5 (or until convergence)
Time budget: Unlimited
Convergence: No new findings in last iteration
```

### Stealth Scan (objective="stealth")
**When**: Red team, avoid detection.
```
Tools selected: Passive only (no active scanning)
  → shodan_host_lookup, censys_host_lookup, subfinder_scan (passive),
    waybackurls_fetch, gau_fetch, hibp_domain_search
Max iterations: 2
Rate limiting: Enforced on all tools
```

---

## Time-Based Adaptation

When a time budget is specified:

```
iterative_smart_scan(target="target.com",
                     objective="comprehensive",
                     metadata={"time_budget_minutes": 30})
```

**Adaptation strategy:**
```
IF time_remaining < 25%:
  → Stop adding new tools
  → Focus on correlating existing findings
IF time_remaining < 10%:
  → Force convergence
  → Generate report with current findings
IF slow_tool detected (estimated > 50% of remaining time):
  → Skip that tool
  → Use faster alternative if available
```

---

## Scan Memory Integration

Before every scan, the engine checks past experience:

```
get_scan_recommendations(target="target.com")
→ Returns:
  - Tools that were effective on this target before
  - Tools that found nothing (skip or deprioritize)
  - Attack patterns that worked
  - Severity distribution from past scans
```

**How it affects tool selection:**
```
IF past_scan found SQLi on this target:
  → Prioritize sqlmap_scan earlier in the chain
IF past_scan found nothing with nikto:
  → Deprioritize nikto_scan
IF past_scan detected Cloudflare WAF:
  → Pre-configure WAF evasion tamper scripts
```

After every scan, save the experience:
```
complete_scan_session(session_id="<id>")
→ Episodic memory trace saved
→ Future get_scan_recommendations calls will use this data
```

---

## Manual Override

The LLM can always override the adaptive planner:

```
# Force specific tools regardless of adaptive planning
select_optimal_tools_ai(target="target.com",
                        objective="custom",
                        required_tools=["nmap_scan", "sqlmap_scan", "nuclei_scan"])
```
