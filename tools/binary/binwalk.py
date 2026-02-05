"""
Binwalk Tool Implementation
Firmware analysis and extraction
"""

from typing import Any, Dict, List

from ..base import BaseTool


class BinwalkTool(BaseTool):
    """
    Binwalk - Firmware analysis and extraction.

    Example usage:
        tool = BinwalkTool()
        result = tool.execute('/path/to/firmware', {
            'extract': True,
            'entropy': True
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Binwalk", "binwalk")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        extract = params.get("extract", False)
        if extract:
            cmd.append("-e")

        signature = params.get("signature", True)
        if signature:
            cmd.append("-B")

        entropy = params.get("entropy", False)
        if entropy:
            cmd.append("-E")

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        cmd.append(target)
        return cmd
