"""
Risk Classifier — Maps tool function names to risk levels.

Provides risk classification for every HexStrike tool, derived from
the category assignments in core/tool_profiles.py. Used by:
  - Flask security middleware (blocking destructive ops in strict mode)
  - MCP tool annotations (readOnlyHint / destructiveHint)
  - Finding verification engine (skip cross-tool verify for exploit tools)

Design notes (senior-engineering/clean-code):
  - Single source of truth: category → risk mapping, not per-tool hardcoding
  - New tools auto-classified by their category in TOOL_REGISTRY
"""

import logging
from typing import Dict

from core.tool_profiles import TOOL_REGISTRY

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────

# Risk levels from least to most dangerous
RISK_READ_ONLY = "read_only"
RISK_ACTIVE_SCAN = "active_scan"
RISK_EXPLOIT = "exploit"
RISK_DESTRUCTIVE = "destructive"

# Map tool categories (from tool_profiles.py) to risk levels
CATEGORY_RISK_MAP: Dict[str, str] = {
    "intelligence": RISK_READ_ONLY,
    "session": RISK_READ_ONLY,
    "memory": RISK_READ_ONLY,
    "reporting": RISK_READ_ONLY,
    "admin": RISK_READ_ONLY,
    "recon": RISK_READ_ONLY,
    "breach": RISK_READ_ONLY,
    "cve": RISK_READ_ONLY,
    "network": RISK_ACTIVE_SCAN,
    "web": RISK_ACTIVE_SCAN,
    "cloud": RISK_ACTIVE_SCAN,
    "api_security": RISK_ACTIVE_SCAN,
    "http_testing": RISK_ACTIVE_SCAN,
    "browser": RISK_ACTIVE_SCAN,
    "binary": RISK_READ_ONLY,
    "forensics": RISK_READ_ONLY,
    "utility": RISK_READ_ONLY,
    "fileops": RISK_ACTIVE_SCAN,
    "bugbounty": RISK_ACTIVE_SCAN,
    "exploit": RISK_EXPLOIT,
    "ai_payload": RISK_EXPLOIT,
}

# Per-tool overrides for tools that don't match their category risk
TOOL_RISK_OVERRIDES: Dict[str, str] = {
    # Recon tools that are passive / read-only
    "shodan_host_lookup": RISK_READ_ONLY,
    "shodan_search_query": RISK_READ_ONLY,
    "censys_host_lookup": RISK_READ_ONLY,
    "censys_search_hosts": RISK_READ_ONLY,
    "censys_certificate_search": RISK_READ_ONLY,
    # Exploit tools that are destructive (actively attack targets)
    "metasploit_run": RISK_DESTRUCTIVE,
    "hydra_attack": RISK_DESTRUCTIVE,
    "medusa_attack": RISK_DESTRUCTIVE,
    "patator_attack": RISK_DESTRUCTIVE,
    "evil_winrm_connect": RISK_DESTRUCTIVE,
    "pacu_exploitation": RISK_DESTRUCTIVE,
    # Hash cracking is local-only, not destructive
    "john_crack": RISK_ACTIVE_SCAN,
    "hashcat_crack": RISK_ACTIVE_SCAN,
    "hash_identifier": RISK_READ_ONLY,
    "hashid_identify": RISK_READ_ONLY,
    # Server admin actions that modify state
    "clear_cache": RISK_ACTIVE_SCAN,
    "terminate_process": RISK_DESTRUCTIVE,
    "delete_file": RISK_DESTRUCTIVE,
    # Sqlmap with default risk is active scan, but can be destructive
    "sqlmap_scan": RISK_EXPLOIT,
    "commix_scan": RISK_EXPLOIT,
}


def _build_tool_risk_map() -> Dict[str, str]:
    """Build the complete tool → risk level map from categories + overrides."""
    risk_map = {}
    for tool_name, category in TOOL_REGISTRY.items():
        risk_map[tool_name] = CATEGORY_RISK_MAP.get(category, RISK_ACTIVE_SCAN)

    # Apply per-tool overrides
    risk_map.update(TOOL_RISK_OVERRIDES)
    return risk_map


# Pre-built lookup table
TOOL_RISK_MAP: Dict[str, str] = _build_tool_risk_map()


def classify_risk(tool_name: str) -> str:
    """Get the risk level for a tool. Defaults to active_scan for unknown tools."""
    return TOOL_RISK_MAP.get(tool_name, RISK_ACTIVE_SCAN)


def is_read_only(tool_name: str) -> bool:
    """Check if a tool is classified as read-only (safe to auto-run)."""
    return classify_risk(tool_name) == RISK_READ_ONLY


def is_destructive(tool_name: str) -> bool:
    """Check if a tool is classified as destructive (requires confirmation)."""
    return classify_risk(tool_name) == RISK_DESTRUCTIVE


def is_exploit(tool_name: str) -> bool:
    """Check if a tool is classified as an exploit tool."""
    return classify_risk(tool_name) in (RISK_EXPLOIT, RISK_DESTRUCTIVE)


class RiskClassifier:
    """Object wrapper for risk classification functions (for dependency injection)."""

    classify_risk = staticmethod(classify_risk)
    is_read_only = staticmethod(is_read_only)
    is_destructive = staticmethod(is_destructive)
    is_exploit = staticmethod(is_exploit)
    TOOL_RISK_MAP = TOOL_RISK_MAP
