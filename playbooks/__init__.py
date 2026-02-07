"""
HexStrike Playbook Loader — File-backed MCP resource provider.

Loads playbook and TTP markdown files from disk so the LLM can read
them on-demand via hexstrike://playbook/{name} and hexstrike://ttp/{name}
without bloating the default context window.
"""

from pathlib import Path
from typing import Optional

PLAYBOOKS_DIR = Path(__file__).parent
WORKFLOWS_DIR = PLAYBOOKS_DIR / "workflows"
AUTONOMOUS_DIR = PLAYBOOKS_DIR / "autonomous"
TTPS_DIR = PLAYBOOKS_DIR / "ttps"

# Subdirectories to search, in priority order
_SEARCH_DIRS = [PLAYBOOKS_DIR, WORKFLOWS_DIR, AUTONOMOUS_DIR, TTPS_DIR]


def load_playbook(name: str) -> str:
    """Load a playbook markdown file by short name.

    Args:
        name: Filename stem without extension (e.g. 'pentest-lifecycle').

    Returns:
        File contents as a string, or a not-found message.
    """
    for directory in _SEARCH_DIRS:
        path = directory / f"{name}.md"
        if path.is_file():
            return path.read_text(encoding="utf-8")
    return f"Playbook '{name}' not found. Available: {list_playbooks()}"


def load_ttp(name: str) -> str:
    """Load a TTP guide markdown file by short name.

    Args:
        name: Filename stem without extension (e.g. 'web-injection').

    Returns:
        File contents as a string, or a not-found message.
    """
    path = TTPS_DIR / f"{name}.md"
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return f"TTP guide '{name}' not found. Available: {list_ttps()}"


def list_playbooks() -> list[str]:
    """Return sorted list of available playbook names (all subdirs)."""
    names: list[str] = []
    for directory in _SEARCH_DIRS:
        if directory.is_dir():
            names.extend(p.stem for p in directory.glob("*.md"))
    return sorted(set(names))


def list_ttps() -> list[str]:
    """Return sorted list of available TTP guide names."""
    if TTPS_DIR.is_dir():
        return sorted(p.stem for p in TTPS_DIR.glob("*.md"))
    return []


def get_index() -> str:
    """Build a quick-reference index of all available playbooks and TTPs."""
    lines = ["# HexStrike Playbook Index", ""]
    lines.append("## Workflow Playbooks")
    lines.append("Read via: `hexstrike://playbook/{name}`\n")
    for name in _list_dir(WORKFLOWS_DIR):
        lines.append(f"- **{name}**")
    lines.append("")
    lines.append("## Autonomous Mode")
    lines.append("Read via: `hexstrike://playbook/{name}`\n")
    for name in _list_dir(AUTONOMOUS_DIR):
        lines.append(f"- **{name}**")
    lines.append("")
    lines.append("## TTP Deep Guides")
    lines.append("Read via: `hexstrike://ttp/{name}`\n")
    for name in list_ttps():
        lines.append(f"- **{name}**")
    return "\n".join(lines)


def _list_dir(directory: Path) -> list[str]:
    """List .md stems in a directory, sorted."""
    if directory.is_dir():
        return sorted(p.stem for p in directory.glob("*.md"))
    return []
