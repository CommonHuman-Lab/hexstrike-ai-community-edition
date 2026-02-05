"""
Commix tool implementation for command injection exploitation
"""

from typing import Any, Dict, List

from tools.base import BaseTool


class CommixTool(BaseTool):
    """Commix - Command injection exploitation tool"""

    def __init__(self):
        super().__init__("Commix", "commix")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build commix command with options

        Args:
            target: Target URL
            params: Dictionary containing:
                - data: POST data
                - cookie: HTTP cookie
                - level: Test level (1-3)
                - technique: Injection technique
                - os: Operating system
                - delay: Delay between requests
                - batch: Non-interactive mode
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["commix", "-u", target]

        # POST data
        data = params.get("data", "")
        if data:
            cmd_parts.extend(["--data", data])

        # Cookie
        cookie = params.get("cookie", "")
        if cookie:
            cmd_parts.extend(["--cookie", cookie])

        # Level
        level = params.get("level", 1)
        cmd_parts.extend(["--level", str(level)])

        # Technique
        technique = params.get("technique", "")
        if technique:
            cmd_parts.extend(["--technique", technique])

        # Operating system
        os_type = params.get("os", "")
        if os_type:
            cmd_parts.extend(["--os", os_type])

        # Delay
        delay = params.get("delay", 0)
        if delay > 0:
            cmd_parts.extend(["--delay", str(delay)])

        # Batch mode
        if params.get("batch", True):
            cmd_parts.append("--batch")

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse commix output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "vulnerable": False,
            "injection_points": [],
            "os_detected": "",
        }

        if "is vulnerable" in stdout.lower():
            result["vulnerable"] = True

        lines = stdout.split("\n")
        for line in lines:
            if "injection point" in line.lower():
                result["injection_points"].append(line.strip())
            if "operating system" in line.lower():
                result["os_detected"] = line.strip()

        return result
