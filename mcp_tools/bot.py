# mcp_tools/bot.py

def register_bot_tools(mcp, hexstrike_client):
    @mcp.tool()
    def bbot_scan(target: str, parameters: dict) -> dict:
        """
        Run BBot scan via HexStrike server.

        Endpoint:
            POST /api/bot/bbot

        Description:
            Interacts with the BBot module on the HexStrike server for reconnaissance and enumeration tasks.

        Parameters:
            target (str): The domain or IP address to scan.
            parameters (dict): BBot flags and module options.
                - f: Enable these flags (e.g. "subdomain-enum")
                - rf: Require modules to have this flag (e.g. "safe")
                - ef: Exclude these flags (e.g. "slow")
                - em: Exclude these individual modules (e.g. "ipneighbor")

        Returns:
            Query results as JSON

        Example:
            bbot_scan(
                target="example.com",
                parameters={
                    "f": "subdomain-enum",
                    "rf": "safe",
                    "ef": "slow",
                    "em": "ipneighbor"
                }
            )

        Usage:
            - Use for subdomain enumeration, module filtering, and safe/fast scanning.
            - Combine flags for advanced control.
            - Returns JSON with BBot response or error details.
        """
        return hexstrike_client.safe_post("api/bot/bbot", {
            "target": target,
            "parameters": parameters
        })
