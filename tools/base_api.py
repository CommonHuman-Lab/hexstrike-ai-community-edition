"""
Base API Tool Abstraction Layer
For tools that query external REST APIs instead of running CLI commands.
Provides API key management via environment variables with parameter fallback.
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


class ApiBaseTool(ABC):
    """
    Abstract base class for API-based HexStrike security tools.

    Unlike BaseTool (which wraps CLI binaries), this class wraps external
    REST APIs that require authentication via API keys.

    API keys are resolved in order:
    1. Explicit ``api_key`` parameter passed at call time
    2. Environment variable (tool-specific, e.g. SHODAN_API_KEY)

    Subclasses must implement:
    - build_request(): Construct the HTTP request details
    - parse_response(): Parse the API response into structured data
    """

    def __init__(
        self,
        name: str,
        base_url: str,
        env_vars: Dict[str, str],
        timeout: int = 30,
    ):
        """
        Args:
            name: Human-readable tool name (e.g. "Shodan")
            base_url: API base URL (e.g. "https://api.shodan.io")
            env_vars: Mapping of key names to env var names
                      e.g. {"api_key": "SHODAN_API_KEY"}
            timeout: Default HTTP request timeout in seconds
        """
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.env_vars = env_vars
        self.timeout = timeout

    def resolve_key(self, key_name: str, params: Dict[str, Any]) -> Optional[str]:
        """
        Resolve an API credential by checking params first, then env vars.

        Args:
            key_name: Logical key name (e.g. "api_key", "api_id")
            params: Request parameters that may contain the key

        Returns:
            The resolved key value, or None if not found
        """
        # 1. Check explicit parameter
        value = params.get(key_name)
        if value:
            return value

        # 2. Check environment variable
        env_var = self.env_vars.get(key_name, "")
        if env_var:
            value = os.environ.get(env_var)
            if value:
                return value

        return None

    @abstractmethod
    def build_request(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build the HTTP request specification.

        Args:
            target: The query target (IP, domain, email, etc.)
            params: Tool-specific parameters

        Returns:
            Dict with keys: method, url, headers, params/json, auth (all optional except url)
        """
        pass

    def parse_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        Parse API response into structured data.

        Override for tool-specific parsing. Default returns JSON body.

        Args:
            response: The HTTP response object

        Returns:
            Parsed output dictionary
        """
        try:
            return response.json()
        except ValueError:
            return {"raw_output": response.text}

    def execute(self, target: str, params: Dict[str, Any], execute_func=None) -> Dict[str, Any]:
        """
        Execute the API request.

        Matches the BaseTool.execute() signature so it works seamlessly
        with create_tool_executor(). The execute_func argument is accepted
        but ignored (API tools don't run subprocesses).

        Args:
            target: The query target
            params: Tool-specific parameters
            execute_func: Ignored (kept for interface compatibility)

        Returns:
            Execution result dictionary
        """
        try:
            # Build request spec
            req = self.build_request(target, params)

            method = req.get("method", "GET").upper()
            url = req["url"]
            headers = req.get("headers", {})
            query_params = req.get("params", {})
            json_body = req.get("json")
            auth = req.get("auth")

            logger.info(f"Executing {self.name} API: {method} {url}")

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=query_params,
                json=json_body,
                auth=auth,
                timeout=self.timeout,
            )

            if response.status_code == 401:
                return {
                    "success": False,
                    "tool": self.name,
                    "target": target,
                    "error": f"{self.name} API authentication failed. "
                    f"Set environment variable(s): {', '.join(self.env_vars.values())}",
                }

            if response.status_code == 403:
                return {
                    "success": False,
                    "tool": self.name,
                    "target": target,
                    "error": f"{self.name} API access forbidden. Check your API key permissions.",
                }

            if response.status_code == 429:
                return {
                    "success": False,
                    "tool": self.name,
                    "target": target,
                    "error": f"{self.name} API rate limit exceeded. Try again later.",
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

        except requests.exceptions.ConnectionError:
            logger.error(f"{self.name} API connection failed")
            return {
                "success": False,
                "tool": self.name,
                "target": target,
                "error": f"Cannot connect to {self.name} API at {self.base_url}",
            }

        except requests.exceptions.Timeout:
            logger.error(f"{self.name} API request timed out")
            return {
                "success": False,
                "tool": self.name,
                "target": target,
                "error": f"{self.name} API request timed out after {self.timeout}s",
            }

        except requests.exceptions.HTTPError as e:
            logger.error(f"{self.name} API HTTP error: {e}")
            return {
                "success": False,
                "tool": self.name,
                "target": target,
                "error": f"{self.name} API error: {str(e)}",
            }

        except Exception as e:
            logger.error(f"{self.name} execution failed: {e}", exc_info=True)
            return {
                "success": False,
                "tool": self.name,
                "target": target,
                "error": str(e),
            }

    def __str__(self) -> str:
        return f"{self.name} (API: {self.base_url})"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name}>"
