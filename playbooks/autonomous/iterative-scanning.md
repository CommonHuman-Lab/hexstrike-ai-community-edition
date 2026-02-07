# HexStrike Iterative Scanning Pattern

How `iterative_smart_scan` implements a multi-pass scan loop that refines
scope based on previous findings until convergence.

---

## Core Concept

Instead of running all tools at once, iterative scanning:
1. **DISPATCH** — Run an initial broad scan
2. **EVALUATE** — Assess findings, identify new attack surface
3. **REFINE** — Select follow-up tools based on what was discovered
4. **LOOP** — Repeat until no new findings emerge (convergence)

This mirrors how a skilled pentester works: scan → analyze → go deeper → repeat.

---

## How to Use It

### Basic Usage
```
# Iteration 1 — initial broad scan
result = iterative_smart_scan(target="target.com",
                              objective="comprehensive")
# Returns:
#   session_id: "abc123"
#   findings: [{severity, type, description, tool}...]
#   recommended_tools: ["sqlmap_scan", "dalfox_xss_scan"]
#   has_more_iterations: true
#   iteration: 1

# Iteration 2+ — follow-up based on findings
result = iterative_smart_scan(target="target.com",
                              session_id="abc123")
# Uses the session to know what was already run
# Only runs NEW tools recommended by the analysis

# Continue until converged
WHILE result.has_more_iterations:
  result = iterative_smart_scan(target="target.com",
                                session_id="abc123")

# Final correlation
correlate_session_findings(session_id="abc123")
complete_scan_session(session_id="abc123")
```

### With Objective Modes

**Comprehensive** (default):
```
iterative_smart_scan(target="target.com", objective="comprehensive")
→ Max iterations: 5
→ Convergence: no new findings in last iteration
→ Tool selection: all relevant categories
```

**Quick**:
```
iterative_smart_scan(target="target.com", objective="quick")
→ Max iterations: 1
→ Tool selection: top 3 most effective for target type
→ Best for: initial triage, time-limited assessments
```

**Stealth**:
```
iterative_smart_scan(target="target.com", objective="stealth")
→ Max iterations: 2
→ Tool selection: passive only (no direct scanning)
→ Best for: red team, avoiding detection
```

---

## Iteration Flow Detail

### Iteration 1: Broad Discovery
```
Tools typically selected:
  - subfinder_scan (subdomains)
  - nmap_scan (ports/services)
  - httpx_probe (live HTTP services)
  - detect_technologies_ai (tech fingerprinting)
  - wafw00f_scan (WAF detection)

Analysis after iteration 1:
  - Target type classified (web app, network host, API, cloud)
  - Technology stack identified
  - Attack surface score calculated
  - WAF presence noted
```

### Iteration 2: Targeted Enumeration
```
Based on iteration 1 findings:

IF web application detected:
  → nuclei_scan, gobuster_scan, nikto_scan
  → arjun_parameter_discovery (on discovered endpoints)
  → katana_crawl (JavaScript-aware crawling)

IF network services found:
  → enum4linux_scan (if SMB)
  → hydra_brute_force (if weak auth suspected)
  → sslyze_scan (if TLS services)

IF WordPress detected:
  → wpscan_analyze (plugins, themes, users)

IF cloud assets found:
  → prowler_scan, trivy_scan
```

### Iteration 3: Exploitation Probing
```
Based on iteration 2 findings:

IF parameters discovered:
  → sqlmap_scan (on injectable parameters)
  → dalfox_xss_scan (on reflective parameters)
  → commix_scan (on command-like parameters)

IF vulnerable software versions found:
  → searchsploit_lookup (match CVEs)
  → cve_exploit_check (verify exploitability)

IF credentials found:
  → john_crack or hashcat_crack
  → hydra_brute_force with found credentials
```

### Iteration 4+: Deep Dive
```
Based on iteration 3 findings:

IF SQLi confirmed:
  → sqlmap_scan with --os-shell, --file-read
  → create_attack_chain_ai for exploitation path

IF XSS confirmed:
  → Verify impact (cookie theft, account takeover)

IF RCE confirmed:
  → Document proof of exploitation
  → create_attack_chain_ai for post-exploitation
```

---

## Convergence Heuristics

The scan converges (stops iterating) when:

| Condition | Action |
|-----------|--------|
| No new findings in last iteration | **Converge** — nothing more to find |
| All recommended tools already run | **Converge** — exhausted tool chain |
| Max iterations reached (5) | **Force converge** — present current findings |
| No new attack surface discovered | **Converge** — scope fully explored |
| All findings are info/low severity | **Converge** (unless objective=comprehensive) |

---

## Session State

Every iteration updates the session:

```
get_scan_session(session_id="abc123")
→ Returns:
  target: "target.com"
  findings: [all findings across all iterations]
  tools_executed: ["subfinder_scan", "nmap_scan", ...]
  iteration_count: 3
  status: "active" | "converged" | "completed"
  metadata: {target_type, complexity, tech_stack, waf}
```

The session ensures:
- No tool runs twice on the same target
- Findings accumulate across iterations
- The decision engine has full context for tool selection
- Everything persists across MCP calls

---

## Manual Intervention Points

The LLM can intervene at any iteration:

```
# Skip a recommended tool
"The scan recommends sqlmap but the target is out of scope for SQLi testing.
Skip it and continue with the next iteration."

# Add a specific tool
"Also run wpscan_analyze — I suspect this is WordPress based on the
/wp-content/ paths found in iteration 1."

# Change objective mid-scan
"Switch to stealth mode — the IDS is starting to flag our scans."

# Force convergence
"We have enough findings. Correlate and generate the report."
→ correlate_session_findings(session_id="abc123")
→ complete_scan_session(session_id="abc123")
```

---

## Integration With Scan Memory

```
# BEFORE scanning: check what we know
get_scan_recommendations(target="target.com")
→ Influences iteration 1 tool selection

# AFTER scanning: save the experience
complete_scan_session(session_id="abc123")
→ Saves episodic trace to memory

# LATER: recall past experience
search_scan_memory(target="target.com")
→ All past scans against this target

# PERIODIC: extract patterns
consolidate_scan_memory()
→ Tool effectiveness patterns
→ Common vulnerability types per target
→ Attack chain patterns that worked
```
