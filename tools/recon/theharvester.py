"""
TheHarvester tool implementation for email and subdomain harvesting
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class TheHarvesterTool(BaseTool):
    """TheHarvester - Email and subdomain harvesting from multiple sources"""

    def __init__(self):
        super().__init__("TheHarvester", "theHarvester")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build theHarvester command with options

        Args:
            target: Target domain to harvest
            params: Dictionary containing:
                - source: Data source (google, bing, linkedin, etc.)
                - limit: Limit results
                - start: Start from result number
                - shodan: Use Shodan for additional info
                - dns_brute: Perform DNS brute force
                - virtual_host: Verify virtual hosts
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["theHarvester", "-d", target]

        # Data source
        source = params.get("source", "all")
        cmd_parts.extend(["-b", source])

        # Limit results
        limit = params.get("limit", 500)
        cmd_parts.extend(["-l", str(limit)])

        # Start position
        if params.get("start"):
            cmd_parts.extend(["-S", str(params["start"])])

        # Shodan integration
        if params.get("shodan", False):
            cmd_parts.append("-s")

        # DNS brute force
        if params.get("dns_brute", False):
            cmd_parts.append("-c")

        # Virtual host verification
        if params.get("virtual_host", False):
            cmd_parts.append("-v")

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse theHarvester output to extract emails and subdomains"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "emails": [],
            "subdomains": [],
            "hosts": []
        }

        lines = stdout.split('\n')
        section = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if "Emails found:" in line or "[*] Emails found:" in line:
                section = "emails"
            elif "Hosts found:" in line or "[*] Hosts found:" in line:
                section = "hosts"
            elif "subdomains" in line.lower():
                section = "subdomains"
            elif section == "emails" and "@" in line:
                result["emails"].append(line)
            elif section in ["hosts", "subdomains"] and line and not line.startswith("["):
                if ":" in line:
                    result["hosts"].append(line)
                else:
                    result["subdomains"].append(line)

        result["email_count"] = len(result["emails"])
        result["subdomain_count"] = len(result["subdomains"])
        result["host_count"] = len(result["hosts"])

        return result
