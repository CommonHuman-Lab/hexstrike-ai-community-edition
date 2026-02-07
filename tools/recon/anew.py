"""
Anew Tool Implementation
Append lines from stdin to a file, only if they don't exist
"""

from typing import Any, Dict, List

from ..base import BaseTool


class AnewTool(BaseTool):
    """
    Anew - Append unique lines to file.

    Example usage:
        tool = AnewTool()
        result = tool.execute('output.txt', {
            'quiet': True
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Anew", "anew")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        quiet = params.get("quiet", False)
        if quiet:
            cmd.append("-q")

        cmd.append(target)

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
