"""
Radare2 Tool Implementation
Reverse engineering framework
"""

from typing import Any, Dict, List

from ..base import BaseTool


class Radare2Tool(BaseTool):
    """
    Radare2 - Reverse engineering framework.

    Example usage:
        tool = Radare2Tool()
        result = tool.execute('/path/to/binary', {
            'commands': 'aaa; afl'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Radare2", "r2")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, "-q"]

        commands = params.get("commands", "aaa; afl")
        cmd.extend(["-c", commands])

        cmd.append(target)
        return cmd
