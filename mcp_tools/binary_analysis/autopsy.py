# mcp_tools/binary_analysis/autopsy.py

from typing import Dict, Any

def register_autopsy_tools(mcp, hexstrike_client, logger):
    
    @mcp.tool()
    def autopsy_analysis() -> Dict[str, Any]:
        """
        Launch Autopsy and return access instructions.

        Returns:
            Access instructions for Autopsy web interface
        """

        logger.info("🔍 Launching Autopsy web server")
        result = hexstrike_client.safe_post("api/tools/binary_analysis/autopsy", {})
        if result.get("success"):
            logger.info(f"✅ Autopsy analysis completed")
        else:
            logger.error(f"❌ Autopsy analysis failed")
        return result