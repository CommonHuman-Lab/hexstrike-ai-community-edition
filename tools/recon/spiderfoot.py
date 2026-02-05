"""
SpiderFoot tool implementation for OSINT automation
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class SpiderFootTool(BaseTool):
    """SpiderFoot - OSINT automation with 200+ modules"""

    def __init__(self):
        super().__init__("SpiderFoot", "spiderfoot")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build spiderfoot command with options

        Args:
            target: Target to scan (domain, IP, email, etc.)
            params: Dictionary containing:
                - scan_type: Type of target (domain, ip, email, etc.)
                - modules: Specific modules to use
                - output_format: Output format (json, csv, etc.)
                - max_threads: Maximum threads
                - quiet: Quiet mode
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["spiderfoot", "-s", target]

        # Scan type
        scan_type = params.get("scan_type", "")
        if scan_type:
            cmd_parts.extend(["-t", scan_type])

        # Specific modules
        modules = params.get("modules", "")
        if modules:
            cmd_parts.extend(["-m", modules])

        # Output format
        output_format = params.get("output_format", "json")
        cmd_parts.extend(["-o", output_format])

        # Max threads
        max_threads = params.get("max_threads", 10)
        cmd_parts.extend(["--max-threads", str(max_threads)])

        # Quiet mode
        if params.get("quiet", True):
            cmd_parts.append("-q")

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse spiderfoot output"""
        import json

        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "findings": []
        }

        # Try to parse JSON output
        try:
            data = json.loads(stdout)
            result["findings"] = data
            result["finding_count"] = len(data) if isinstance(data, list) else 1
        except json.JSONDecodeError:
            # Fallback to raw parsing
            lines = stdout.split('\n')
            for line in lines:
                if line.strip():
                    result["findings"].append(line.strip())
            result["finding_count"] = len(result["findings"])

        return result
