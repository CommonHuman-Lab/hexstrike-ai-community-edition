"""
ROPgadget Tool Implementation
ROP gadget finder
"""

from typing import Any, Dict, List

from ..base import BaseTool


class RopgadgetTool(BaseTool):
    """
    ROPgadget - ROP gadget finder.

    Example usage:
        tool = RopgadgetTool()
        result = tool.execute('/path/to/binary', {
            'ropchain': True
        }, execute_command)
    """

    def __init__(self):
        super().__init__("ROPgadget", "ROPgadget")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, "--binary", target]

        ropchain = params.get("ropchain", False)
        if ropchain:
            cmd.append("--ropchain")

        depth = params.get("depth", "")
        if depth:
            cmd.extend(["--depth", str(depth)])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
