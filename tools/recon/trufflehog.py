"""
TruffleHog tool implementation for Git repository secret scanning
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class TruffleHogTool(BaseTool):
    """TruffleHog - Git repository secret scanning with entropy analysis"""

    def __init__(self):
        super().__init__("TruffleHog", "trufflehog")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build trufflehog command with options

        Args:
            target: Target repository URL or path
            params: Dictionary containing:
                - scan_type: Type of scan (git, github, gitlab, filesystem, etc.)
                - only_verified: Only show verified secrets
                - json_output: Output in JSON format
                - no_update: Don't update the tool
                - concurrency: Number of concurrent workers
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        scan_type = params.get("scan_type", "git")
        cmd_parts = ["trufflehog", scan_type, target]

        # Only verified secrets
        if params.get("only_verified", False):
            cmd_parts.append("--only-verified")

        # JSON output
        if params.get("json_output", True):
            cmd_parts.append("--json")

        # No update
        if params.get("no_update", True):
            cmd_parts.append("--no-update")

        # Concurrency
        concurrency = params.get("concurrency", 10)
        cmd_parts.extend(["--concurrency", str(concurrency)])

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse trufflehog output to extract secrets"""
        import json

        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "secrets": [],
            "verified_secrets": [],
            "unverified_secrets": []
        }

        # Parse JSON lines output
        lines = stdout.strip().split('\n')
        for line in lines:
            if not line.strip():
                continue
            try:
                secret = json.loads(line)
                result["secrets"].append(secret)
                if secret.get("Verified", False):
                    result["verified_secrets"].append(secret)
                else:
                    result["unverified_secrets"].append(secret)
            except json.JSONDecodeError:
                continue

        result["total_secrets"] = len(result["secrets"])
        result["verified_count"] = len(result["verified_secrets"])
        result["unverified_count"] = len(result["unverified_secrets"])

        return result
