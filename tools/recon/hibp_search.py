"""
Have I Been Pwned (HIBP) API tool implementation for breach intelligence.

Environment variable: HIBP_API_KEY
Get your key at: https://haveibeenpwned.com/API/Key
"""

from typing import Any, Dict

import requests

from tools.base_api import ApiBaseTool


class HIBPTool(ApiBaseTool):
    """
    Have I Been Pwned - Breach and paste intelligence for email addresses.

    Checks if email addresses or domains have appeared in known data breaches,
    credential dumps, or paste sites.

    Example usage:
        tool = HIBPTool()
        result = tool.execute('user@example.com', {'action': 'breaches'}, None)
    """

    def __init__(self):
        super().__init__(
            name="HaveIBeenPwned",
            base_url="https://haveibeenpwned.com/api/v3",
            env_vars={"api_key": "HIBP_API_KEY"},
            timeout=30,
        )

    def build_request(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build HIBP API request.

        Args:
            target: Email address, domain, or breach name
            params: Dictionary containing:
                - api_key: HIBP API key (or set HIBP_API_KEY env var)
                - action: API action to perform:
                    "breaches"       - Check breached accounts for email (default)
                    "pastes"         - Check paste appearances for email
                    "breach_detail"  - Get details of a specific breach by name
                    "all_breaches"   - List all breaches (optionally filter by domain)
                    "domain_search"  - Search breaches by domain
                - truncate: Return only breach names, not full details (default False)
                - include_unverified: Include unverified breaches (default True)

        Returns:
            HTTP request specification dict
        """
        api_key = self.resolve_key("api_key", params)
        if not api_key:
            raise ValueError(
                "HIBP API key required. Set HIBP_API_KEY environment variable "
                "or pass api_key parameter. Get a key at https://haveibeenpwned.com/API/Key"
            )

        action = params.get("action", "breaches")
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "HexStrike-CE",
            "Accept": "application/json",
        }
        query_params = {}

        if action == "breaches":
            url = f"{self.base_url}/breachedaccount/{target}"
            if params.get("truncate", False):
                query_params["truncateResponse"] = "true"
            if params.get("include_unverified", True):
                query_params["includeUnverified"] = "true"

        elif action == "pastes":
            url = f"{self.base_url}/pasteaccount/{target}"

        elif action == "breach_detail":
            url = f"{self.base_url}/breach/{target}"

        elif action == "all_breaches":
            url = f"{self.base_url}/breaches"
            if target and target != "all":
                query_params["domain"] = target

        elif action == "domain_search":
            url = f"{self.base_url}/breaches"
            query_params["domain"] = target

        else:
            raise ValueError(f"Unknown HIBP action: {action}")

        return {
            "method": "GET",
            "url": url,
            "headers": headers,
            "params": query_params,
        }

    def parse_response(self, response: requests.Response) -> Dict[str, Any]:
        """Parse HIBP API response into structured data."""
        # HIBP returns 404 for "not found" (clean email) - that's a success
        if response.status_code == 404:
            return {
                "found": False,
                "message": "No breaches or pastes found for this account.",
                "breaches": [],
                "breach_count": 0,
            }

        data = response.json()

        # If it's a list of breaches for an account
        if isinstance(data, list):
            breach_names = []
            total_pwn_count = 0
            data_classes = set()

            for breach in data:
                if isinstance(breach, dict):
                    breach_names.append(breach.get("Name", ""))
                    total_pwn_count += breach.get("PwnCount", 0)
                    for dc in breach.get("DataClasses", []):
                        data_classes.add(dc)
                elif isinstance(breach, str):
                    breach_names.append(breach)

            return {
                "found": True,
                "breaches": data,
                "breach_count": len(data),
                "breach_names": breach_names,
                "total_records_exposed": total_pwn_count,
                "data_classes": sorted(data_classes),
                "summary": f"Found in {len(data)} breach(es). "
                f"Total records exposed: {total_pwn_count:,}. "
                f"Data types: {', '.join(sorted(data_classes)[:10])}",
            }

        return data

    def execute(self, target: str, params: Dict[str, Any], execute_func=None) -> Dict[str, Any]:
        """Override to handle HIBP's 404 = not-found convention."""
        try:
            req = self.build_request(target, params)

            response = requests.request(
                method=req.get("method", "GET"),
                url=req["url"],
                headers=req.get("headers", {}),
                params=req.get("params", {}),
                timeout=self.timeout,
            )

            # HIBP returns 404 for clean accounts - not an error
            if response.status_code == 404:
                parsed = self.parse_response(response)
                return {
                    "success": True,
                    "tool": self.name,
                    "target": target,
                    "output": parsed,
                    "status_code": 404,
                    "cached": False,
                }

            if response.status_code == 401:
                return {
                    "success": False,
                    "tool": self.name,
                    "target": target,
                    "error": "HIBP API authentication failed. Set HIBP_API_KEY environment variable.",
                }

            if response.status_code == 429:
                retry_after = response.headers.get("retry-after", "unknown")
                return {
                    "success": False,
                    "tool": self.name,
                    "target": target,
                    "error": f"HIBP API rate limit exceeded. Retry after {retry_after} seconds.",
                }

            response.raise_for_status()
            parsed = self.parse_response(response)

            return {
                "success": True,
                "tool": self.name,
                "target": target,
                "output": parsed,
                "status_code": response.status_code,
                "cached": False,
            }

        except ValueError as e:
            return {
                "success": False,
                "tool": self.name,
                "target": target,
                "error": str(e),
            }

        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "tool": self.name,
                "target": target,
                "error": f"Cannot connect to HIBP API at {self.base_url}",
            }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "tool": self.name,
                "target": target,
                "error": f"HIBP API request timed out after {self.timeout}s",
            }

        except Exception as e:
            return {
                "success": False,
                "tool": self.name,
                "target": target,
                "error": str(e),
            }
