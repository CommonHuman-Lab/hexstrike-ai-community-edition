# HexStrike Intelligence Upgrade

Transforms HexStrike from an AI-assisted scanner into an AI-driven pentester with finding verification, learned effectiveness, knowledge graphs, parallel execution, and security middleware.

## Why This Upgrade

The previous scan pipeline was fire-and-forget: scan, parse, correlate, report. Three blind spots:

1. **No verification** — every finding was treated as ground truth. False positives went straight into reports.
2. **No learning** — the decision engine used hardcoded tool scores. Scan memory stored patterns but nothing consumed them to improve future decisions.
3. **No relationship mapping** — findings were isolated data points. The LLM couldn't see that a breach credential, an open admin panel, and a CVE chain together into a multi-step attack path.

This upgrade closes those gaps with five interconnected components.

---

## How It Fits Together

```
                    ┌─────────────────────┐
                    │  Effectiveness      │
                    │  Tracker            │
                    │  (learned scores)   │
                    └──────┬──────────────┘
                           │ informs
                           v
┌──────────┐     ┌─────────────────┐     ┌──────────────────┐
│ Security │────>│ Decision Engine │────>│ Parallel Execute │
│ Layer    │     │ (tool selection)│     │ (batch tools)    │
└──────────┘     └────────┬────────┘     └────────┬─────────┘
                          │                        │
                          v                        v
                 ┌─────────────────┐     ┌──────────────────┐
                 │ Result Analyzer │     │ Finding Verifier │
                 │ (parse output)  │     │ (confirm real)   │
                 └────────┬────────┘     └────────┬─────────┘
                          │                        │
                          v                        v
                 ┌─────────────────────────────────────────┐
                 │         Knowledge Graph                  │
                 │  (entities, relationships, attack paths) │
                 └─────────────────────────────────────────┘
```

**Scan cycle:**
1. `get_tool_effectiveness()` — check learned scores before starting
2. `create_scan_session()` + `iterative_smart_scan()` — decision engine uses effectiveness data
3. `parallel_execute_tools()` — batch independent tools simultaneously
4. Security middleware validates every request (rate limits, input format)
5. `batch_verify_findings()` — confirm findings are real via rescan/cross-tool/HTTP probe
6. `ingest_to_knowledge_graph()` + `find_attack_paths()` — map attack surface
7. `complete_scan_session()` — saves to memory, feeds step 1 next time

Every component feeds the next. The effectiveness tracker makes the decision engine smarter. Parallel execution makes scanning faster. Verification makes findings trustworthy. The knowledge graph makes relationships visible. The security layer keeps the API stable.

---

## What Changed

### New Modules

| Module | Purpose |
|--------|---------|
| `core/security/` | Input validation, rate limiting, tool risk classification |
| `core/verification/` | Multi-strategy finding verification engine |
| `core/effectiveness_tracker.py` | Read adapter over ScanMemory patterns — learned tool scores |
| `core/knowledge_graph.py` | Entity-relationship graph for attack path discovery |
| `api/routes/verification.py` | Verification API endpoints |
| `api/routes/knowledge_graph.py` | Knowledge graph API endpoints |

### Modified Files

| File | Changes |
|------|---------|
| `hexstrike_server.py` | New component wiring, 2 new blueprints, `@app.before_request` security middleware |
| `hexstrike_mcp.py` | 7 new MCP tools, `--transport`/`--mcp-port`/`--strict-mode` flags, auto tool annotations, updated system instructions + workflow prompts |
| `agents/decision_engine.py` | Optional `effectiveness_tracker` parameter for learned tool scores |
| `api/routes/scan_intelligence.py` | Extracted shared `_execute_single_tool`, new `/parallel-execute` endpoint |
| `core/tool_profiles.py` | 7 new tool entries in TOOL_REGISTRY (intelligence category) |
| `playbooks/tool-categories.md` | Updated AI Intelligence Engine section (9 to 16 tools) |
| `playbooks/workflows/pentest-lifecycle.md` | Added Phase 6 (Verification), Phase 7 (Knowledge Graph), parallel execution |
| `core/__init__.py` | Exports EffectivenessTracker, KnowledgeGraph |
| `api/routes/__init__.py` | Exports verification_bp, knowledge_graph_bp |

---

## New CLI Flags

```bash
# HTTP transport (instead of stdio)
python hexstrike_mcp.py --transport http --mcp-port 3000

# Strict security mode (blocks private IPs, enforces rate limits)
python hexstrike_mcp.py --strict-mode

# Combined
python hexstrike_mcp.py --transport http --mcp-port 3000 --strict-mode --profile web
```

---

## New MCP Tools

### Finding Verification

| Tool | Description |
|------|-------------|
| `verify_finding(session_id, finding_index, methods)` | Verify a single finding via rescan/cross-tool/HTTP probe/CVE lookup |
| `batch_verify_findings(session_id, min_severity, methods)` | Batch-verify all findings above a severity threshold |

**Verification strategies:**
- **Rescan** — re-run the same tool 3 times, check if finding reproduces (majority vote)
- **Cross-tool** — run a different tool covering the same vulnerability class (e.g., verify nuclei XSS with dalfox)
- **HTTP probe** — lightweight HEAD request for web-based findings (port open? endpoint responding?)
- **CVE lookup** — cross-reference CVE ID against detected service versions

### Knowledge Graph

| Tool | Description |
|------|-------------|
| `ingest_to_knowledge_graph(session_id)` | Convert session findings to Host/Service/Vulnerability/Credential entities |
| `find_attack_paths(source_entity_id, target_type)` | Discover multi-step attack chains via BFS traversal |
| `query_knowledge_graph(entity_type, name_filter)` | Search entities by type and name |

**Entity types:** Host, Service, Vulnerability, Credential
**Relationship types:** HOSTS, HAS_VULN, OBTAINED_FROM, LEADS_TO

### Effectiveness & Execution

| Tool | Description |
|------|-------------|
| `get_tool_effectiveness(target_type)` | Show learned vs default tool scores for a target type |
| `parallel_execute_tools(tools, target, session_id)` | Execute up to 10 tools simultaneously |

---

## New API Endpoints

### Verification (`/api/verification`)

- `POST /verify-finding` — Verify single finding
- `POST /batch-verify` — Batch verify findings above severity threshold

### Knowledge Graph (`/api/knowledge-graph`)

- `POST /ingest` — Ingest session findings into graph
- `GET /entities` — List/filter entities by type and name
- `GET /paths` — Find attack paths between entities
- `GET /related/<entity_id>` — Get neighbors of an entity
- `GET /summary` — Graph statistics (entity/relationship counts by type)

### Scan Intelligence (new endpoint)

- `POST /api/scan-intelligence/parallel-execute` — Execute multiple tools in parallel

---

## Security Features

### Rate Limiting
- Applied at Flask layer via `@app.before_request`
- 30 requests/minute for general `/api/` endpoints
- 10 requests/minute for scan intelligence and verification endpoints
- Sliding window implementation (in-memory)

### Input Validation (Strict Mode)
- Target format validation (IP, CIDR, domain, URL)
- Private IP blocking (RFC1918, loopback, link-local)
- Enabled via `--strict-mode` flag or `HEXSTRIKE_STRICT_MODE=1` env var

### Tool Annotations
- All 196+ tools auto-annotated with `readOnlyHint` / `destructiveHint`
- Derived from category-based risk classification in `core/security/risk_classifier.py`
- LLMs can use annotations to avoid running destructive tools without confirmation

---

## Architecture

```
AI Agent (Claude, GPT, etc.)
    |
    v
hexstrike_mcp.py (MCP/stdio or HTTP)
    |-- verify_finding() ---------> /api/verification/verify-finding
    |-- find_attack_paths() ------> /api/knowledge-graph/paths
    |-- parallel_execute_tools() -> /api/scan-intelligence/parallel-execute
    |-- iterative_smart_scan() ---> /api/scan-intelligence/iterative-scan
    |-- get_tool_effectiveness() --> reads ScanMemory patterns directly
    |
    v
hexstrike_server.py (Flask, port 8888)
    |-- @app.before_request ------> RateLimiter + InputValidator (strict mode)
    |
    |-- FindingVerifier ----------> RescanStrategy, CrossToolStrategy,
    |                               HttpProbeStrategy, CveLookupStrategy
    |
    |-- KnowledgeGraph -----------> .hexstrike_data/knowledge/graph.json
    |
    |-- EffectivenessTracker -----> ScanMemory.patterns.json (read adapter)
    |
    |-- Decision Engine ----------> Queries tracker for learned scores
    |
    |-- RiskClassifier -----------> TOOL_RISK_MAP -> MCP tool annotations
```

---

## LLM Integration

All new tools are integrated into HexStrike's LLM guidance:

- **System instructions** — MCP server instructions mention verification, knowledge graph, and effectiveness
- **`hexstrike://playbook` resource** — Quick decision guide includes all new tools
- **MCP prompts** — `full_pentest()` and `web_app_assessment()` include verification and knowledge graph steps
- **`pentest-lifecycle.md` playbook** — Phases 6-7 cover verification and attack surface mapping
- **`tool-categories.md`** — All 7 new tools listed under AI Intelligence Engine (16 tools total)
- **Tool annotations** — `readOnlyHint`/`destructiveHint` auto-applied so LLMs know tool risk before execution
