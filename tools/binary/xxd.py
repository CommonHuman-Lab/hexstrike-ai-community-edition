"""
Xxd Tool Implementation
Hex dump utility
"""

from typing import Any, Dict, List

from ..base import BaseTool


class XxdTool(BaseTool):
    """
    Xxd - Hex dump utility.

    Example usage:
        tool = XxdTool()
        result = tool.execute('/path/to/file', {
            'length': 256
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Xxd", "xxd")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        length = params.get("length", "")
        if length:
            cmd.extend(["-l", str(length)])

        offset = params.get("offset", "")
        if offset:
            cmd.extend(["-s", str(offset)])

        cmd.append(target)

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
