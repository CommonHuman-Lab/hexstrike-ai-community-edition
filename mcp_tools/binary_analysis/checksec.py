# mcp_tools/binary_analysis/checksec.py

from typing import Dict, Any

def register_checksec_tool(mcp, hexstrike_client, logger):

    @mcp.tool()
    def checksec_analyze(binary: str) -> Dict[str, Any]:
        """
        Check security features of a binary with enhanced logging.

        Args:
            binary: Path to the binary file

        Returns:
            Security features analysis results
        """
        data = {
            "binary": binary
        }
        logger.info(f"🔧 Starting Checksec analysis: {binary}")
        result = hexstrike_client.safe_post("api/tools/checksec", data)
        if result.get("success"):
            logger.info(f"✅ Checksec analysis completed for {binary}")
        else:
            logger.error(f"❌ Checksec analysis failed for {binary}")
        return result