# HexStrike AI Community Edition - Changelog

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
