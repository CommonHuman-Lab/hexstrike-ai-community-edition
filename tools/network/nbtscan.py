"""
NBTScan Tool Implementation
NetBIOS name scanning
"""

from typing import Any, Dict, List

from ..base import BaseTool


class NbtscanTool(BaseTool):
    """
    NBTScan - NetBIOS name scanning.

    Example usage:
        tool = NbtscanTool()
        result = tool.execute('192.168.1.0/24', {}, execute_command)
    """

    def __init__(self):
        super().__init__("NBTScan", "nbtscan")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, "-v"]

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        cmd.append(target)
        return cmd
