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
        password: str = "",
        command: str = "",
    ) -> Dict[str, Any]:
        """
        SSH execution-request tool.
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
                        "password": password,
                        "command": command,
                    },
                ),
            )
            return response

        except Exception as e:
            logger.error("ssh MCP tool failed: %s", e)
            return {"error": str(e), "success": False}
