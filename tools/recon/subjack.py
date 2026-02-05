"""
Subjack tool implementation for subdomain takeover detection
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class SubjackTool(BaseTool):
    """Subjack - Subdomain takeover vulnerability checker"""

    def __init__(self):
        super().__init__("Subjack", "subjack")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build subjack command with options

        Args:
            target: Target file with subdomains or single subdomain
            params: Dictionary containing:
                - wordlist: Subdomain wordlist file
                - threads: Number of concurrent threads
                - timeout: Request timeout
                - ssl: Only check SSL
                - all: Check for all fingerprints
                - config: Path to fingerprints config
                - verbose: Verbose output
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["subjack"]

        # Input file or domain
        if params.get("input_file"):
            cmd_parts.extend(["-w", params["input_file"]])
        else:
            cmd_parts.extend(["-d", target])

        # Threads
        threads = params.get("threads", 10)
        cmd_parts.extend(["-t", str(threads)])

        # Timeout
        timeout = params.get("timeout", 30)
        cmd_parts.extend(["-timeout", str(timeout)])

        # SSL only
        if params.get("ssl", False):
            cmd_parts.append("-ssl")

        # Check all fingerprints
        if params.get("all", True):
            cmd_parts.append("-a")

        # Config file
        config = params.get("config", "")
        if config:
            cmd_parts.extend(["-c", config])

        # Verbose
        if params.get("verbose", True):
            cmd_parts.append("-v")

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse subjack output to extract vulnerable subdomains"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "vulnerable": [],
            "checked": []
        }

        lines = stdout.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            if "[Vulnerable]" in line or "vulnerable" in line.lower():
                result["vulnerable"].append(line)
            else:
                result["checked"].append(line)

        result["vulnerable_count"] = len(result["vulnerable"])
        result["checked_count"] = len(result["checked"])

        return result
