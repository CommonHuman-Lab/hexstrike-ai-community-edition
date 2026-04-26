"""
Plugin: ssh_client — mcp_tool.py
Auto-session SSH MCP tool (interactive, stateful)
"""

import asyncio
from typing import Dict, Any


def register(mcp, api_client, logger):
    """Register the ssh MCP tool."""

    # 🔐 In-memory session cache
    ssh_session_cache = {}

    @mcp.tool()
    async def ssh(
        host: str,
        port: int = 22,
        username: str = "",
        password: str = "",
        command: str = "",
        disconnect: bool = False,
    ) -> Dict[str, Any]:
        """
        Stateful SSH tool with automatic session handling.

        - Automatically connects if no session exists
        - Reuses session for subsequent commands
        - Optional disconnect flag to close session
        """

        try:
            loop = asyncio.get_running_loop()

            # unique connection key
            key = f"{username}@{host}:{port}"

            def call():
                # 🔌 Disconnect request
                if disconnect:
                    if key in ssh_session_cache:
                        session_id = ssh_session_cache.pop(key)

                        return api_client.safe_post(
                            "api/plugins/ssh/disconnect",
                            {"session_id": session_id},
                        )

                    return {"success": True, "message": "No active session"}

                # 🔗 Connect if not cached
                if key not in ssh_session_cache:
                    if not host:
                        return {"success": False, "error": "Missing host"}

                    resp = api_client.safe_post(
                        "api/plugins/ssh/connect",
                        {
                            "host": host,
                            "port": port,
                            "username": username,
                            "password": password,
                        },
                    )

                    if not resp.get("success"):
                        return resp

                    ssh_session_cache[key] = resp.get("session_id")

                session_id = ssh_session_cache[key]

                # 💻 Execute command
                if command:
                    resp = api_client.safe_post(
                        "api/plugins/ssh/send",
                        {
                            "session_id": session_id,
                            "command": command,
                        },
                    )

                    # 🔁 Auto-reconnect if session died
                    if not resp.get("success"):
                        # try reconnect once
                        reconnect = api_client.safe_post(
                            "api/plugins/ssh/connect",
                            {
                                "host": host,
                                "port": port,
                                "username": username,
                                "password": password,
                            },
                        )

                        if not reconnect.get("success"):
                            return reconnect

                        new_session_id = reconnect.get("session_id")
                        ssh_session_cache[key] = new_session_id

                        # retry command
                        return api_client.safe_post(
                            "api/plugins/ssh/send",
                            {
                                "session_id": new_session_id,
                                "command": command,
                            },
                        )

                    return resp

                # no command → just ensure connection exists
                return {
                    "success": True,
                    "message": "Connected (no command executed)",
                    "session_id": session_id,
                }

            return await loop.run_in_executor(None, call)

        except Exception as e:
            logger.error("ssh MCP tool failed: %s", e)
            return {"success": False, "error": str(e)}