"""
Volatility Tool Implementation
Legacy memory forensics framework
"""

from typing import Any, Dict, List

from ..base import BaseTool


class VolatilityTool(BaseTool):
    """
    Volatility - Legacy memory forensics framework (v2).

    Example usage:
        tool = VolatilityTool()
        result = tool.execute('/path/to/memory.dmp', {
            'profile': 'Win7SP1x64',
            'plugin': 'pslist'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Volatility", "vol.py")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, "-f", target]

        profile = params.get("profile", "")
        if profile:
            cmd.extend(["--profile", profile])

        plugin = params.get("plugin", "imageinfo")
        cmd.append(plugin)

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
