# mcp_tools/recon/theharvester.py

from typing import Dict, Any

def register_theharvester_tool(mcp, hexstrike_client, logger):
    @mcp.tool()
    def theharvester_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute TheHarvester for passive information gathering with enhanced logging.

        Args:
            domain <string, required> : The target domain
            additional_args <string, optional> : Additional TheHarvester arguments

        Returns:
            Passive information gathering results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting TheHarvester: {domain}")
        result = hexstrike_client.safe_post("api/tools/recon/theharvester", data)
        if result.get("success"):
            logger.info(f"✅ TheHarvester completed for {domain}")
        else:
            logger.error(f"❌ TheHarvester failed for {domain}")
        return result