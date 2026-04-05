"""
Built-in session templates shipped with the server.

These templates are code-defined (not persisted in data/sessions/templates)
and are intended for operator-provided defaults.
"""

from __future__ import annotations

import copy
import time
from typing import Any, Dict, List, Optional


SERVER_TEMPLATE_ORIGIN = "server"


_NOW = int(time.time())

_SERVER_TEMPLATES: List[Dict[str, Any]] = [
    {
        "template_id": "server-intelligence",
        "name": "Intelligence",
        "workflow_steps": [
            {"tool": "analyze-target", "parameters": {}},
            {"tool": "smart-scan", "parameters": {}},
            {"tool": "technology-detection", "parameters": {}},
            {"tool": "create-attack-chain", "parameters": {}},
        ],
        "source_session_id": "",
        "template_origin": SERVER_TEMPLATE_ORIGIN,
        "read_only": True,
        "created_at": _NOW,
        "updated_at": _NOW,
    }
]


def list_server_templates() -> List[Dict[str, Any]]:
    """Return all code-defined server templates."""
    return [copy.deepcopy(template) for template in _SERVER_TEMPLATES]


def load_server_template(template_id: str) -> Optional[Dict[str, Any]]:
    """Load one code-defined server template by id."""
    for template in _SERVER_TEMPLATES:
        if template.get("template_id") == template_id:
            return copy.deepcopy(template)
    return None
