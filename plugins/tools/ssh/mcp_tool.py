"""
Plugin: ssh_client — mcp_tool.py
FastMCP tool registration for the SSH metadata plugin.

This file is the MCP-side half of the plugin.
It must expose a module-level `register(mcp, api_client, logger)` function.
The plugin MCP loader calls it automatically during server setup.
"""

import asyncio
from typing import Dict, Any


def register(mcp, api_client, logger):
    """Register the ssh MCP tool."""

    @mcp.tool()
    async def ssh(
        host: str,
        port: int = 22,
        username: str = "",
    ) -> Dict[str, Any]:
        """
        SSH metadata tool.

        Args:
            host:     Target host to connect to
            port:     SSH port (default 22)
            username: Optional SSH username

        Returns:
            Structured metadata response from the SSH plugin endpoint.
        """
        try:
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: api_client.safe_post(
                    "api/plugins/ssh",
                    {"host": host, "port": port, "username": username},
                ),
            )
            return response
        except Exception as e:
            logger.error("ssh MCP tool failed: %s", e)
            return {"error": str(e), "success": False}
