"""
Ropper Tool Implementation
ROP gadget finder
"""

from typing import Any, Dict, List

from ..base import BaseTool


class RopperTool(BaseTool):
    """
    Ropper - ROP gadget finder.

    Example usage:
        tool = RopperTool()
        result = tool.execute('/path/to/binary', {
            'search': 'pop rdi'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Ropper", "ropper")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, "--file", target]

        search = params.get("search", "")
        if search:
            cmd.extend(["--search", search])

        arch = params.get("arch", "")
        if arch:
            cmd.extend(["--arch", arch])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
