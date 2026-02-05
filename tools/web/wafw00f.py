"""
Wafw00f Tool Implementation
Web Application Firewall detection
"""

from typing import Any, Dict, List

from ..base import BaseTool


class Wafw00fTool(BaseTool):
    """
    Wafw00f - Web Application Firewall detection.

    Example usage:
        tool = Wafw00fTool()
        result = tool.execute('https://example.com', {
            'all': True
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Wafw00f", "wafw00f")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, target]

        all_wafs = params.get("all", False)
        if all_wafs:
            cmd.append("-a")

        verbose = params.get("verbose", False)
        if verbose:
            cmd.append("-v")

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
