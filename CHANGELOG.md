# HexStrike AI Community Edition - Changelog

## Scan Memory & Persistence Engine

**Additions:**
- 195 MCP tools (+9: scan memory/persistence tools)
- 194 API routes (+11 scan memory endpoints)
- 114 tool executors (+3: Shodan, Censys, HIBP)
- 25 Flask blueprints (+1: scan_memory_bp)
- 2 new core modules: `core/session_store.py` (JSON file persistence), `core/scan_memory.py` (episodic + semantic memory)
- Scan sessions now survive server restarts (checkpoint/resume via SessionStore)
- Episodic memory: completed scans saved as traces for future reference
- Semantic memory: automatic pattern extraction (tool effectiveness, tool chains, severity profiles)
- Memory-based scan recommendations: suggests tools based on past similar scans
- Memory consolidation: episodic → semantic pattern learning
- Manual learnings: record observations from scan engagements
- 9 new MCP tools: complete_scan_session, checkpoint_scan_session, get_scan_recommendations, list_past_scans, get_past_scan, search_scan_memory, get_learned_patterns, consolidate_scan_memory, add_scan_learning

## Scan Intelligence Engine

**Additions:**
- 10 OSINT API tools + 6 scan intelligence tools
- 7 scan intelligence API endpoints
- 3 new core modules: `core/scan_session.py`, `core/result_analyzer.py`, `core/finding_correlator.py`
- `ApiBaseTool` base class for REST API-based tools (`tools/base_api.py`)
- Shodan, Censys, HIBP OSINT tool wrappers in `tools/recon/`
- Iterative adaptive scanning with Think→Decide→Act→Observe agent loop
- Follow-up tool selection rules in `IntelligentDecisionEngine.adapt_tools_from_findings()`
- Persistent scan sessions with TTL eviction and finding accumulation
- Result parsing into structured findings with severity/confidence scoring
- Finding deduplication and cross-tool correlation with confidence boosting
- LLM guidance: FastMCP instructions, 2 MCP resources, 5 MCP prompt templates

---

## [1.0.1]

**Changes:**
- 170 MCP tools (20 new tools added from the original README's tool list)
- 111 tool executors with working execute_command (critical bug fixed)
- 176 API routes across 23 Flask blueprints
- Major refactoring to modular architecture (87+ Python modules)
- fastmcp updated to >=2.14.0
- mitmproxy updated to >=12.1.2
- TTY detection skips health checks in MCP host mode
- Security hardening with path traversal protection
- httpx_probe duplicate definition removed
- Endpoint naming conventions (underscore to dash)
- 4 broken test imports fixed
- 6 missing blueprint imports added
- 33 unused imports removed from hexstrike_server.py
- All v5.0/v6.0 version references cleaned up
- Dockerfile expanded with 30+ tools and HEALTHCHECK

Check [Wiki](https://github.com/CommonHuman-Lab/hexstrike-ai-community-edition/wiki) for all the new documentation.

---
