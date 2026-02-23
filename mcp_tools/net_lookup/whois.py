# mcp_tools/net_lookup/whois.py

from typing import Dict, Any

def register_whois(mcp, hexstrike_client, logger):
    @mcp.tool()
    def whois_lookup(target: str) -> Dict[str, Any]:
        """
        Perform a WHOIS lookup for a domain or IP address.

        Args:
            target: The domain or IP to query

        Returns:
            WHOIS lookup results
        """
        try:
            response = hexstrike_client.safe_post("api/tools/whois", {"target": target})
            return response
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return {"error": str(e)}
    