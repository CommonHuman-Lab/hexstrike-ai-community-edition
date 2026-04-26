"""
Plugin: ssh_client — mcp_tool.py
FastMCP tool registration for the SSH metadata + execution-request plugin.
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
        command: str = "",
    ) -> Dict[str, Any]:
        """
        SSH execution-request tool.

        Args:
            host:     Target host
            port:     SSH port (default 22)
            username: Optional username
            command:  Optional command to request execution

        Returns:
            Structured execution-request payload from the plugin.
        """
        try:
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: api_client.safe_post(
                    "api/plugins/ssh",
                    {
                        "host": host,
                        "port": port,
                        "username": username,
                        "command": command,
                    },
                ),
            )
            return response
        except Exception as e:
            logger.error("ssh MCP tool failed: %s", e)
            return {"error": str(e), "success": False}
