"""
Strings Tool Implementation
Extract printable strings from binaries
"""

from typing import Any, Dict, List

from ..base import BaseTool


class StringsTool(BaseTool):
    """
    Strings - Extract printable strings from binaries.

    Example usage:
        tool = StringsTool()
        result = tool.execute('/path/to/binary', {
            'min_length': 10
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Strings", "strings")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        min_length = params.get("min_length", "")
        if min_length:
            cmd.extend(["-n", str(min_length)])

        encoding = params.get("encoding", "")
        if encoding:
            cmd.extend(["-e", encoding])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        cmd.append(target)
        return cmd
