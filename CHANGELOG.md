# HexStrike AI Community Edition - Changelog

## [1.0.1]

**Changes:**
- 151 MCP tools available
- Major refactoring to modular architecture
   - 87+ Python modules
- fastmcp updated to >=2.14.0
- mitmproxy updated to >=12.1.2
- TTY detection skips health checks in MCP host mode
- Security hardening with path traversal protection
- httpx_probe duplicate definition - fix
- Endpoint naming conventions (underscore to dash)
- Performance profiling and optimization

---

### 🔄 For Developers

**New Import Pattern:**

```python
# Old (everything from main file)
from hexstrike_server import IntelligentErrorHandler

# New (from organized modules)
from core.error_handler import IntelligentErrorHandler
from agents.decision_engine import IntelligentDecisionEngine
from api.routes import files_bp, visual_bp, core_bp
```

**Blueprint Registration:**

```python
# All blueprints initialized with dependencies
files_routes.init_app(file_manager)
core_routes.init_app(execute_command, cache, telemetry, file_manager)
intelligence_routes.init_app(decision_engine, tool_executors)

# Then registered with Flask app
app.register_blueprint(files_bp)
app.register_blueprint(core_bp)
app.register_blueprint(intelligence_bp)
```

---
