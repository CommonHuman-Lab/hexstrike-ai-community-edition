# HexStrike AI Community Edition - Changelog

## Intelligence Upgrade

Closes the loop between scanning and reporting with verification, learning, and attack surface mapping.

- **Finding Verification** — Multi-strategy confirmation (rescan, cross-tool, HTTP probe, CVE lookup) to eliminate false positives before reporting
- **Knowledge Graph** — Entity-relationship graph (Host, Service, Vulnerability, Credential) with BFS attack path discovery across findings
- **Effectiveness Tracker** — Learned tool scores from scan memory patterns. Decision engine now improves tool selection based on past results
- **Parallel Tool Execution** — Batch up to 10 tools simultaneously via `parallel_execute_tools()`
- **Security Middleware** — Flask-layer rate limiting (30/10 req/min), input validation, private IP blocking (strict mode), auto tool annotations (`readOnlyHint`/`destructiveHint`)
- **HTTP Transport** — `--transport http --mcp-port 3000` for non-stdio deployments
- 7 new MCP tools, 2 new Flask blueprints, 3 new API endpoint groups
- Pentest lifecycle playbook updated with verification and knowledge graph phases
- All MCP prompts and system instructions updated to guide LLMs through the full cycle

---

## TTP Playbook Engine

On-demand knowledge system for LLM agents — file-backed MCP resources with zero context cost until read.

- **16 playbooks** across `playbooks/workflows/`, `playbooks/autonomous/`, and `playbooks/ttps/`
- **MCP resources:** `hexstrike://playbook/{name}`, `hexstrike://ttp/{name}`, compact index at `hexstrike://playbook`
- **5 workflow playbooks:** pentest-lifecycle, bugbounty-hunting, ctf-challenges, redteam-ops, blueteam-defense
- **3 autonomous playbooks:** adaptive-scanning, iterative-scanning, scan-memory
- **7 TTP deep guides** with real payloads, decision trees, and HexStrike tool calls:
  - web-injection (SQLi, XSS, SSTI, NoSQLi, command injection, GraphQL)
  - auth-attacks (JWT, IDOR, OAuth, session hijacking, credential attacks)
  - network-exploit (SMB, Kerberoasting, pass-the-hash, lateral movement)
  - cloud-attacks (metadata SSRF, IAM privesc, container escape, K8s)
  - binary-exploit (BOF, ROP, heap, format strings, pwntools)
  - recon-osint (subdomain takeover, Shodan/Censys, breach pivoting, dorking)
  - waf-evasion (per-WAF bypass tables, sqlmap tamper mapping, HTTP smuggling)
- **2025–2026 techniques** integrated: ORM leaks, error-based blind SSTI, Unicode normalization bypass, ADCS ESC1–ESC16, NTLM coercion chains, IMDSv2 bypass, supply chain attacks (OWASP 2025 #3), K8s ingress CVEs, AI/LLM infrastructure attacks
- Decision engine annotated with TTP references across all 15 attack pattern groups
- 5 MCP prompts updated to reference playbooks/TTPs with correct tool names

---

## Dynamic Tool Loading & Profile System

Conditional tool registration to reduce LLM context window usage — only load what you need.

- **`core/tool_profiles.py`** — 196 tools mapped to 21 categories, 8 preset profiles
- **`core/tool_selector.py`** — Interactive startup: `--profile`, `--categories` CLI flags, or TTY menu
- **`register_tool()` closure** — skipped tools have zero LLM context cost

| Profile | Tools | Use Case |
|---------|-------|----------|
| minimal | ~28 | AI-driven smart scanning |
| web | ~93 | Web app pentesting |
| network | ~75 | Network assessments |
| bugbounty | ~104 | Bug bounty hunting |
| ctf | ~116 | CTF competitions |
| cloud | ~71 | Cloud security audits |
| redteam | ~146 | Red team operations |
| full | 196 | Everything loaded |

---

## Scan Memory & Persistence Engine

Persistent scan intelligence that survives server restarts and learns from past engagements.

- 9 new MCP tools for scan memory management
- `core/session_store.py` — JSON file persistence with checkpoint/resume
- `core/scan_memory.py` — Episodic + semantic memory with pattern extraction
- Memory-based recommendations: suggests tools based on past similar scans
- Memory consolidation: episodic traces → semantic patterns (tool effectiveness, chains, severity profiles)

---

## Scan Intelligence Engine

AI-powered adaptive scanning with iterative decision-making.

- 10 OSINT API tools (Shodan, Censys, HIBP) + 6 scan intelligence tools
- Iterative adaptive scanning: Think → Decide → Act → Observe agent loop
- Persistent scan sessions with finding accumulation and cross-tool correlation
- Structured findings with severity/confidence scoring and deduplication
- 5 MCP prompt templates for guided assessments

---

## [1.0.1]

- 170 MCP tools, 111 tool executors, 176 API routes, 23 Flask blueprints
- Major refactoring to modular architecture (87+ Python modules)
- Security hardening with path traversal protection
- Dockerfile expanded with 30+ tools and HEALTHCHECK

Check [Wiki](https://github.com/CommonHuman-Lab/hexstrike-ai-community-edition/wiki) for all the new documentation.

---
