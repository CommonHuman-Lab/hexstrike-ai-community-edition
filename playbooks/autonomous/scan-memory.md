# HexStrike Scan Memory System

How HexStrike learns from past engagements and uses accumulated knowledge
to improve future scans. Built on episodic + semantic memory architecture.

---

## Overview

HexStrike maintains two memory layers:

1. **Episodic Memory** — Raw scan traces (what tools ran, what they found)
2. **Semantic Memory** — Extracted patterns (tool effectiveness, attack chains)

Together they enable the recommendation engine: "Last time we scanned this
target, nuclei found critical CVEs but nikto found nothing. Prioritize nuclei."

---

## Using Scan Memory

### Before a Scan: Get Recommendations

```
get_scan_recommendations(target="target.com")
→ Returns:
  recommended_tools: ["nuclei_scan", "sqlmap_scan"]
  deprioritized_tools: ["nikto_scan"]  # found nothing last time
  known_technologies: ["PHP", "MySQL", "Cloudflare"]
  past_findings_summary: "3 critical, 7 high from last scan"
  attack_patterns: ["SQLi on /api/search was effective"]
  time_since_last_scan: "45 days"
```

**How to use recommendations:**
```
IF recommendations available:
  → Pass to iterative_smart_scan as context
  → The decision engine will factor them into tool selection

IF no recommendations (first time scanning this target):
  → Normal adaptive scanning applies
  → Memory will be built from this scan
```

### During a Scan: Checkpoint Progress

```
checkpoint_scan_session(session_id="abc123")
→ Saves current state to disk
→ Survives server restarts
→ Can resume with get_scan_session(session_id="abc123")
```

### After a Scan: Save to Memory

```
# Step 1: Correlate findings
correlate_session_findings(session_id="abc123")
→ Deduplicated, severity-ranked report

# Step 2: Complete and archive
complete_scan_session(session_id="abc123")
→ Session moves to completed archive
→ Episodic memory trace created
→ Future get_scan_recommendations will use this data
```

### Add Manual Learnings

```
add_scan_learning(target="target.com",
                  learning="Cloudflare WAF blocks sqlmap without tamper scripts. Use charunicodeescape tamper.")

add_scan_learning(target="target.com",
                  learning="Admin panel at /wp-admin protected by IP whitelist. Cannot test from external.")
```

---

## Querying Past Scans

### List All Past Scans
```
list_past_scans()
→ Returns: [{target, date, finding_count, severity_summary}...]
```

### Get Full Scan Details
```
get_past_scan(scan_id="abc123")
→ Returns: complete scan trace with all findings, tools, timeline
```

### Search Memory
```
# By target
search_scan_memory(target="target.com")
→ All scans against this target

# By tool
search_scan_memory(tool="sqlmap_scan")
→ All scans where sqlmap was used

# By finding type
search_scan_memory(query="sql injection")
→ All SQLi findings across all targets
```

---

## Pattern Extraction

### Consolidate Memory
```
consolidate_scan_memory()
→ Analyzes all episodic memories
→ Extracts semantic patterns:
  - Tool effectiveness per target type
  - Common tool chains that produce results
  - Severity distribution patterns
  - Technology-specific vulnerability patterns
```

### View Learned Patterns
```
get_learned_patterns()
→ Returns:
  tool_effectiveness: {
    "nuclei_scan": {"web_application": 0.95, "network_host": 0.6},
    "sqlmap_scan": {"web_application": 0.85, "api_endpoint": 0.9}
  }
  effective_chains: [
    ["subfinder_scan", "httpx_probe", "nuclei_scan"],
    ["nmap_scan", "enum4linux_scan", "smbmap_scan"]
  ]
  severity_profiles: {
    "web_application": {"critical": 5%, "high": 15%, "medium": 30%},
    "network_host": {"critical": 2%, "high": 10%, "medium": 25%}
  }
```

---

## Memory Architecture

### Episodic Memory (per-scan traces)
```
Location: .hexstrike_data/memory/episodic/
Format: JSON files, one per completed scan
Contents:
  - Target and scope
  - Tools executed with parameters
  - Findings with severity
  - Timeline (start, end, duration per tool)
  - Session metadata (objective, complexity)
Retention: Configurable, default unlimited
```

### Semantic Memory (extracted patterns)
```
Location: .hexstrike_data/memory/
Files:
  - patterns.json — Tool effectiveness, chains, severity profiles
  - learnings.json — Manual observations and tips
Updated: On consolidate_scan_memory() calls
Used by: get_scan_recommendations(), decision engine
```

### Session Store (active/completed scans)
```
Location: .hexstrike_data/sessions/
Active sessions: JSON files with 2-hour TTL
Completed sessions: Archived to completed/ subdirectory
Auto-prune: Expired sessions cleaned on access
```

---

## Best Practices

1. **Always call `get_scan_recommendations` before starting** — even if no
   past data exists, it primes the session.

2. **Always call `complete_scan_session` when done** — this is what saves
   the experience to memory.

3. **Add manual learnings for non-obvious insights** — things like WAF
   bypass tricks, scope restrictions, time-of-day effects.

4. **Run `consolidate_scan_memory` periodically** — after every 5-10 scans
   to keep semantic patterns fresh.

5. **Use `search_scan_memory` for cross-target patterns** — "show me all
   targets where we found SQLi" reveals systemic issues.
