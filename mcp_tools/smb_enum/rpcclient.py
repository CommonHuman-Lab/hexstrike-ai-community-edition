# mcp_tools/smb_enum/rpcclient.py

from typing import Dict, Any

def register_rpcclient_tool(mcp, hexstrike_client, logger):
    @mcp.tool()
    def rpcclient_enumeration(target: str, username: str = "", password: str = "",
                             domain: str = "", commands: str = "enumdomusers;enumdomgroups;querydominfo",
                             additional_args: str = "") -> Dict[str, Any]:
        """
        Execute rpcclient for RPC enumeration with enhanced logging.

        Args:
            target: The target IP address
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            commands: Semicolon-separated RPC commands
            additional_args: Additional rpcclient arguments

        Returns:
            RPC enumeration results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "commands": commands,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting rpcclient: {target}")
        result = hexstrike_client.safe_post("api/tools/rpcclient", data)
        if result.get("success"):
            logger.info(f"✅ rpcclient completed for {target}")
        else:
            logger.error(f"❌ rpcclient failed for {target}")
        return result


