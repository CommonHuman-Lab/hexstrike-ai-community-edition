"""
NoSQLMap tool implementation for NoSQL injection testing
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class NoSQLMapTool(BaseTool):
    """NoSQLMap - NoSQL injection testing for MongoDB, CouchDB, etc."""

    def __init__(self):
        super().__init__("NoSQLMap", "nosqlmap")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build nosqlmap command with options

        Args:
            target: Target URL
            params: Dictionary containing:
                - attack_type: Type of attack
                - database: Database type (mongodb, couchdb)
                - post_data: POST data
                - cookie: HTTP cookie
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["nosqlmap", "-u", target]

        # Attack type
        attack_type = params.get("attack_type", "")
        if attack_type:
            cmd_parts.extend(["--attack", attack_type])

        # Database type
        database = params.get("database", "mongodb")
        cmd_parts.extend(["--dbtype", database])

        # POST data
        post_data = params.get("post_data", "")
        if post_data:
            cmd_parts.extend(["--data", post_data])

        # Cookie
        cookie = params.get("cookie", "")
        if cookie:
            cmd_parts.extend(["--cookie", cookie])

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse nosqlmap output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "vulnerable": False,
            "injection_type": "",
            "databases": []
        }

        if "vulnerable" in stdout.lower() or "injection" in stdout.lower():
            result["vulnerable"] = True

        lines = stdout.split('\n')
        for line in lines:
            if "database" in line.lower() and ":" in line:
                result["databases"].append(line.strip())

        return result
