"""
Checkov Tool Implementation
Infrastructure as code security scanning
"""

from typing import Any, Dict, List

from ..base import BaseTool


class CheckovTool(BaseTool):
    """
    Checkov - Infrastructure as code security scanning.

    Example usage:
        tool = CheckovTool()
        result = tool.execute('.', {
            'framework': 'terraform',
            'output_format': 'json'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Checkov", "checkov")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        directory = params.get("directory", target or ".")
        cmd.extend(["-d", directory])

        framework = params.get("framework", "")
        if framework:
            cmd.extend(["--framework", framework])

        check = params.get("check", "")
        if check:
            cmd.extend(["--check", check])

        skip_check = params.get("skip_check", "")
        if skip_check:
            cmd.extend(["--skip-check", skip_check])

        output_format = params.get("output_format", "json")
        cmd.extend(["-o", output_format])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
