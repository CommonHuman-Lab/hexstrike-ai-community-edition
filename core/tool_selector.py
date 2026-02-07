"""
HexStrike AI — Interactive Tool Profile Selector

Provides three modes for selecting which MCP tools to load:
1. --profile <name>    CLI flag (non-interactive)
2. --categories <list> CLI flag (non-interactive)
3. Interactive TTY menu (when no flags and stdin is a TTY)

Non-TTY stdio mode (MCP client) defaults to 'full' profile.

Usage:
    from core.tool_selector import resolve_tools

    selected_tools = resolve_tools(args)  # → Set[str] of tool function names
"""

import sys
from typing import Optional, Set

from core.tool_profiles import (
    ALL_CATEGORIES,
    ALL_TOOLS,
    CATEGORY_INFO,
    PROFILES,
    TOOL_CATEGORIES,
    resolve_categories,
    resolve_profile,
)

# ANSI color codes matching HexStrike visual identity
_RED = "\033[38;5;196m"
_GREEN = "\033[38;5;46m"
_CYAN = "\033[38;5;51m"
_ORANGE = "\033[38;5;208m"
_PURPLE = "\033[38;5;129m"
_GRAY = "\033[38;5;240m"
_WHITE = "\033[97m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _print_banner() -> None:
    """Print the HexStrike profile selector banner."""
    print(
        f"""
{_RED}{_BOLD}╔══════════════════════════════════════════════════════════════════╗
║  🔥 HexStrike AI — Tool Profile Selector                        ║
╠══════════════════════════════════════════════════════════════════╣{_RESET}"""
    )

    profiles_ordered = ["minimal", "web", "network", "bugbounty", "ctf", "cloud", "redteam", "full"]
    for idx, name in enumerate(profiles_ordered, 1):
        profile = PROFILES[name]
        tool_count = len(resolve_profile(name))
        emoji = profile["emoji"]
        desc = profile["description"]
        count_str = f"({tool_count:>3} tools)"
        print(
            f"{_RED}║{_RESET}  {_WHITE}[{idx}]{_RESET} {emoji} "
            f"{_CYAN}{name:<12}{_RESET} {_GRAY}{count_str}{_RESET}  "
            f"— {_DIM}{desc}{_RESET}"
        )

    print(
        f"{_RED}║{_RESET}  {_WHITE}[9]{_RESET} 🔧 "
        f"{_ORANGE}{'custom':<12}{_RESET} {_GRAY}{'':>12}{_RESET}  "
        f"— {_DIM}Pick individual categories{_RESET}"
    )
    print(f"{_RED}{_BOLD}╚══════════════════════════════════════════════════════════════════╝{_RESET}")


def _print_category_menu() -> None:
    """Print the category selection sub-menu."""
    print(f"\n{_PURPLE}{_BOLD}  Available Categories:{_RESET}")
    sorted_cats = sorted(ALL_CATEGORIES)
    for idx, cat in enumerate(sorted_cats, 1):
        count = len(TOOL_CATEGORIES[cat])
        desc = CATEGORY_INFO.get(cat, "")
        print(
            f"  {_WHITE}[{idx:>2}]{_RESET} {_CYAN}{cat:<16}{_RESET} "
            f"{_GRAY}({count:>3} tools){_RESET}  {_DIM}{desc}{_RESET}"
        )
    print(f"\n  {_GRAY}Enter numbers separated by commas (e.g. 1,3,5) or category names:{_RESET}")


def _interactive_select() -> Set[str]:
    """Run interactive TTY profile selection. Returns set of tool function names."""
    _print_banner()
    print(f"\n  {_GRAY}Select a profile (1-9):{_RESET} ", end="", flush=True)

    profiles_ordered = ["minimal", "web", "network", "bugbounty", "ctf", "cloud", "redteam", "full"]

    try:
        choice = input().strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {_ORANGE}Defaulting to full profile.{_RESET}")
        return set(ALL_TOOLS)

    # Handle numeric choice
    if choice.isdigit():
        num = int(choice)
        if 1 <= num <= 8:
            profile_name = profiles_ordered[num - 1]
            tools = resolve_profile(profile_name)
            profile = PROFILES[profile_name]
            print(
                f"\n  {_GREEN}✓ Loaded {profile['emoji']} {profile_name} profile "
                f"— {len(tools)} tools active{_RESET}\n"
            )
            return tools
        elif num == 9:
            return _interactive_category_select()
        else:
            print(f"  {_ORANGE}Invalid choice. Defaulting to full profile.{_RESET}")
            return set(ALL_TOOLS)

    # Handle profile name typed directly
    if choice.lower() in PROFILES:
        tools = resolve_profile(choice.lower())
        profile = PROFILES[choice.lower()]
        print(
            f"\n  {_GREEN}✓ Loaded {profile['emoji']} {choice.lower()} profile "
            f"— {len(tools)} tools active{_RESET}\n"
        )
        return tools

    print(f"  {_ORANGE}Unrecognized input. Defaulting to full profile.{_RESET}")
    return set(ALL_TOOLS)


def _interactive_category_select() -> Set[str]:
    """Run interactive category selection sub-menu."""
    _print_category_menu()
    sorted_cats = sorted(ALL_CATEGORIES)

    try:
        raw = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {_ORANGE}Defaulting to full profile.{_RESET}")
        return set(ALL_TOOLS)

    selected_cats: Set[str] = set()
    for part in raw.replace(" ", "").split(","):
        part = part.strip()
        if not part:
            continue
        # Numeric index
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(sorted_cats):
                selected_cats.add(sorted_cats[idx])
        # Category name
        elif part.lower() in ALL_CATEGORIES:
            selected_cats.add(part.lower())

    if not selected_cats:
        print(f"  {_ORANGE}No valid categories selected. Defaulting to full profile.{_RESET}")
        return set(ALL_TOOLS)

    # Always include intelligence + session for core functionality
    selected_cats |= {"intelligence", "session"}

    tools = resolve_categories(selected_cats)
    print(
        f"\n  {_GREEN}✓ Loaded custom profile — {len(tools)} tools from "
        f"{len(selected_cats)} categories: {', '.join(sorted(selected_cats))}{_RESET}\n"
    )
    return tools


def resolve_tools(
    profile: Optional[str] = None,
    categories: Optional[str] = None,
) -> Set[str]:
    """
    Resolve which tools to load based on CLI args or interactive selection.

    Priority:
    1. --profile flag → use that preset
    2. --categories flag → resolve those categories
    3. TTY stdin → interactive menu
    4. Non-TTY (stdio MCP) → full profile (backward compatible)

    Args:
        profile: Profile name from --profile CLI flag (or None)
        categories: Comma-separated category names from --categories flag (or None)

    Returns:
        Set of tool function names to register
    """
    # 1. Explicit profile flag
    if profile:
        tools = resolve_profile(profile)
        _log_selection(profile, tools)
        return tools

    # 2. Explicit categories flag
    if categories:
        cat_list = {c.strip().lower() for c in categories.split(",") if c.strip()}
        # Always include core categories
        cat_list |= {"intelligence", "session"}
        tools = resolve_categories(cat_list)
        _log_selection(f"custom ({', '.join(sorted(cat_list))})", tools)
        return tools

    # 3. Interactive TTY mode
    if sys.stdin.isatty() and sys.stderr.isatty():
        return _interactive_select()

    # 4. Non-TTY default (MCP stdio mode) — full for backward compatibility
    return set(ALL_TOOLS)


def _log_selection(label: str, tools: Set[str]) -> None:
    """Log the profile selection to stderr (visible in MCP logs)."""
    import logging

    logger = logging.getLogger("hexstrike.tool_selector")
    logger.info(f"🔧 Tool profile: {label} ({len(tools)} tools loaded)")
