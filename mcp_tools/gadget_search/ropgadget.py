# mcp_tools/gadget_search/ropgadget.py

from typing import Dict, Any

def register_ropgadget_tool(mcp, hexstrike_client, logger):
    
    @mcp.tool()
    def ropgadget_search(binary: str, gadget_type: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Search for ROP gadgets in a binary using ROPgadget with enhanced logging.

        Args:
            binary: Path to the binary file
            gadget_type: Type of gadgets to search for
            additional_args: Additional ROPgadget arguments

        Returns:
            ROP gadget search results
        """
        data = {
            "binary": binary,
            "gadget_type": gadget_type,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting ROPgadget search: {binary}")
        result = hexstrike_client.safe_post("api/tools/ropgadget", data)
        if result.get("success"):
            logger.info(f"✅ ROPgadget search completed for {binary}")
        else:
            logger.error(f"❌ ROPgadget search failed for {binary}")
        return result
