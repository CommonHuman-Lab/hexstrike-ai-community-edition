"""
Tplmap tool implementation for server-side template injection
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class TplmapTool(BaseTool):
    """Tplmap - Server-side template injection exploitation"""

    def __init__(self):
        super().__init__("Tplmap", "tplmap")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build tplmap command with options

        Args:
            target: Target URL with injectable parameter
            params: Dictionary containing:
                - data: POST data
                - cookie: HTTP cookie
                - engine: Template engine to test
                - level: Injection level
                - os_shell: Get OS shell
                - os_cmd: Execute OS command
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["tplmap", "-u", target]

        # POST data
        data = params.get("data", "")
        if data:
            cmd_parts.extend(["-d", data])

        # Cookie
        cookie = params.get("cookie", "")
        if cookie:
            cmd_parts.extend(["--cookie", cookie])

        # Template engine
        engine = params.get("engine", "")
        if engine:
            cmd_parts.extend(["-e", engine])

        # Level
        level = params.get("level", 1)
        cmd_parts.extend(["--level", str(level)])

        # OS shell
        if params.get("os_shell", False):
            cmd_parts.append("--os-shell")

        # OS command
        os_cmd = params.get("os_cmd", "")
        if os_cmd:
            cmd_parts.extend(["--os-cmd", os_cmd])

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse tplmap output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "vulnerable": False,
            "engine": "",
            "technique": ""
        }

        if "is vulnerable" in stdout.lower() or "injection point" in stdout.lower():
            result["vulnerable"] = True

        lines = stdout.split('\n')
        for line in lines:
            if "engine" in line.lower() and ":" in line:
                result["engine"] = line.split(":")[-1].strip()
            if "technique" in line.lower():
                result["technique"] = line.strip()

        return result
