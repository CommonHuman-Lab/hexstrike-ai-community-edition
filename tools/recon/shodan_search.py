"""
Shodan API tool implementation for internet-connected device intelligence.

Environment variable: SHODAN_API_KEY
Get your key at: https://account.shodan.io/
"""

from typing import Any, Dict, List

import requests

from tools.base_api import ApiBaseTool


class ShodanTool(ApiBaseTool):
    """
    Shodan - Search engine for internet-connected devices.

    Provides host intelligence, open port discovery, vulnerability detection,
    and banner grabbing across the entire IPv4 space.

    Example usage:
        tool = ShodanTool()
        result = tool.execute('8.8.8.8', {'action': 'host'}, None)
    """

    def __init__(self):
        super().__init__(
            name="Shodan",
            base_url="https://api.shodan.io",
            env_vars={"api_key": "SHODAN_API_KEY"},
            timeout=30,
        )

    def build_request(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build Shodan API request.

        Args:
            target: IP address, domain, or search query
            params: Dictionary containing:
                - api_key: Shodan API key (or set SHODAN_API_KEY env var)
                - action: API action to perform:
                    "host"     - Get host information (default)
                    "search"   - Search Shodan database
                    "resolve"  - DNS resolution
                    "reverse"  - Reverse DNS lookup
                    "exploits" - Search exploit database
                    "info"     - API info / credits remaining
                - page: Page number for search results
                - facets: Comma-separated facets for search
                - minify: Return minimal host info (default True)

        Returns:
            HTTP request specification dict
        """
        api_key = self.resolve_key("api_key", params)
        if not api_key:
            raise ValueError(
                "Shodan API key required. Set SHODAN_API_KEY environment variable " "or pass api_key parameter."
            )

        action = params.get("action", "host")
        query_params = {"key": api_key}

        if action == "host":
            url = f"{self.base_url}/shodan/host/{target}"
            if params.get("minify", True):
                query_params["minify"] = "true"

        elif action == "search":
            url = f"{self.base_url}/shodan/host/search"
            query_params["query"] = target
            if params.get("page"):
                query_params["page"] = str(params["page"])
            if params.get("facets"):
                query_params["facets"] = params["facets"]

        elif action == "resolve":
            url = f"{self.base_url}/dns/resolve"
            query_params["hostnames"] = target

        elif action == "reverse":
            url = f"{self.base_url}/dns/reverse"
            query_params["ips"] = target

        elif action == "exploits":
            url = f"{self.base_url}/api-ms/exploits/search"
            query_params["query"] = target
            if params.get("page"):
                query_params["page"] = str(params["page"])

        elif action == "info":
            url = f"{self.base_url}/api-info"

        else:
            raise ValueError(f"Unknown Shodan action: {action}")

        return {
            "method": "GET",
            "url": url,
            "params": query_params,
        }

    def parse_response(self, response: requests.Response) -> Dict[str, Any]:
        """Parse Shodan API response into structured data."""
        data = response.json()

        # Enrich host responses with summary info
        if isinstance(data, dict) and "ports" in data:
            data["summary"] = {
                "ip": data.get("ip_str", ""),
                "org": data.get("org", ""),
                "os": data.get("os", ""),
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else [],
                "hostnames": data.get("hostnames", []),
                "country": data.get("country_name", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "last_update": data.get("last_update", ""),
            }

        return data
