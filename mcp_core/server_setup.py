from typing import Optional
from mcp.server.fastmcp import FastMCP
from mcp_tools.gateway import register_gateway_tools
from mcp_core.tool_profiles import (
    TOOL_PROFILES,
    DEFAULT_PROFILE,
    FULL_PROFILE,
    resolve_profile_dependencies,
)

def setup_mcp_server(hexstrike_client, logger, compact: bool = False, profiles: Optional[list] = None) -> FastMCP:
    """
    Set up the MCP server with all enhanced tool functions

    Args:
        hexstrike_client: Initialized HexStrikeClient
        logger: Logger instance for logging
        compact: If True, register only classify_task and run_tool gateway tools
        profile: Optional list of tool profiles to load (e.g., ["core_network", "web_app"])

    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("hexstrike-ai-mcp")

    if compact:
        # Register gateway tools for task classification and tool execution
        register_gateway_tools(mcp, hexstrike_client)

        logger.info("Compact mode: only gateway tools registered (classify_task, run_tool)")
        return mcp

    # Determine which profiles to load
    if profiles:
        if "default" in profiles:
            selected_profiles = DEFAULT_PROFILE
        elif "full" in profiles:
            selected_profiles = FULL_PROFILE
        else:
            selected_profiles = profiles
    else:
        selected_profiles = DEFAULT_PROFILE

    # Register tools for each selected profile
    selected_profiles = resolve_profile_dependencies(selected_profiles)

    registered = set()
    for profile in selected_profiles:
        for reg_func in TOOL_PROFILES.get(profile, []):
            if reg_func not in registered:
                reg_func(mcp, hexstrike_client, logger)
                registered.add(reg_func)  

    return mcp
