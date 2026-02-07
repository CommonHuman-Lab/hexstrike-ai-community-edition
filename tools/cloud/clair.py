"""
Clair Tool Implementation
Container vulnerability scanner
"""

from typing import Any, Dict, List

from ..base import BaseTool


class ClairTool(BaseTool):
    """
    Clair - Container vulnerability scanner.

    Example usage:
        tool = ClairTool()
        result = tool.execute('nginx:latest', {
            'format': 'json'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Clair", "clairctl")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, "report"]

        config = params.get("config", "")
        if config:
            cmd.extend(["--config", config])

        output_format = params.get("format", "json")
        cmd.extend(["--format", output_format])

        cmd.append(target)

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
