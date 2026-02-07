"""
Censys API tool implementation for internet-wide host and certificate intelligence.

Environment variables: CENSYS_API_ID, CENSYS_API_SECRET
Get your credentials at: https://search.censys.io/account/api
"""

from typing import Any, Dict

import requests

from tools.base_api import ApiBaseTool


class CensysTool(ApiBaseTool):
    """
    Censys - Internet-wide scan data and certificate transparency intelligence.

    Provides host discovery, certificate analysis, and exposure assessment
    using Censys' comprehensive internet scan database.

    Example usage:
        tool = CensysTool()
        result = tool.execute('8.8.8.8', {'action': 'host'}, None)
    """

    def __init__(self):
        super().__init__(
            name="Censys",
            base_url="https://search.censys.io/api",
            env_vars={
                "api_id": "CENSYS_API_ID",
                "api_secret": "CENSYS_API_SECRET",
            },
            timeout=30,
        )

    def build_request(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build Censys API request.

        Args:
            target: IP address, domain, or search query
            params: Dictionary containing:
                - api_id: Censys API ID (or set CENSYS_API_ID env var)
                - api_secret: Censys API secret (or set CENSYS_API_SECRET env var)
                - action: API action to perform:
                    "host"         - Get host details by IP (default)
                    "search_hosts" - Search hosts
                    "search_certs" - Search certificates
                    "aggregate"    - Aggregate host data
                - per_page: Results per page (default 25, max 100)
                - cursor: Pagination cursor for next page
                - virtual_hosts: Include virtual hosts ("INCLUDE", "EXCLUDE", "ONLY")

        Returns:
            HTTP request specification dict
        """
        api_id = self.resolve_key("api_id", params)
        api_secret = self.resolve_key("api_secret", params)

        if not api_id or not api_secret:
            raise ValueError(
                "Censys API credentials required. Set CENSYS_API_ID and "
                "CENSYS_API_SECRET environment variables or pass api_id/api_secret parameters."
            )

        action = params.get("action", "host")
        headers = {"Accept": "application/json"}

        if action == "host":
            url = f"{self.base_url}/v2/hosts/{target}"
            return {
                "method": "GET",
                "url": url,
                "headers": headers,
                "auth": (api_id, api_secret),
            }

        elif action == "search_hosts":
            url = f"{self.base_url}/v2/hosts/search"
            body = {"q": target}
            if params.get("per_page"):
                body["per_page"] = min(int(params["per_page"]), 100)
            if params.get("cursor"):
                body["cursor"] = params["cursor"]
            if params.get("virtual_hosts"):
                body["virtual_hosts"] = params["virtual_hosts"]
            return {
                "method": "POST",
                "url": url,
                "headers": headers,
                "json": body,
                "auth": (api_id, api_secret),
            }

        elif action == "search_certs":
            url = f"{self.base_url}/v2/certificates/search"
            body = {"q": target}
            if params.get("per_page"):
                body["per_page"] = min(int(params["per_page"]), 100)
            if params.get("cursor"):
                body["cursor"] = params["cursor"]
            return {
                "method": "POST",
                "url": url,
                "headers": headers,
                "json": body,
                "auth": (api_id, api_secret),
            }

        elif action == "aggregate":
            url = f"{self.base_url}/v2/hosts/aggregate"
            body = {
                "q": target,
                "field": params.get("field", "services.port"),
            }
            if params.get("num_buckets"):
                body["num_buckets"] = int(params["num_buckets"])
            return {
                "method": "POST",
                "url": url,
                "headers": headers,
                "json": body,
                "auth": (api_id, api_secret),
            }

        else:
            raise ValueError(f"Unknown Censys action: {action}")

    def parse_response(self, response: requests.Response) -> Dict[str, Any]:
        """Parse Censys API response into structured data."""
        data = response.json()

        # Enrich host detail responses
        result = data.get("result", data)
        if isinstance(result, dict) and "services" in result:
            services = result.get("services", [])
            result["summary"] = {
                "ip": result.get("ip", ""),
                "autonomous_system": result.get("autonomous_system", {}),
                "location": result.get("location", {}),
                "operating_system": result.get("operating_system", {}),
                "open_ports": [s.get("port") for s in services if s.get("port")],
                "service_names": [s.get("service_name", "") for s in services],
                "transport_protocols": list({s.get("transport_protocol", "") for s in services}),
                "last_updated": result.get("last_updated_at", ""),
            }

        return data
