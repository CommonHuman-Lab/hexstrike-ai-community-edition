"""
RPCClient Tool Implementation
RPC enumeration tool
"""

from typing import Any, Dict, List

from ..base import BaseTool


class RpcclientTool(BaseTool):
    """
    RPCClient - RPC enumeration tool.

    Example usage:
        tool = RpcclientTool()
        result = tool.execute('192.168.1.100', {
            'command': 'enumdomusers'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("RPCClient", "rpcclient")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        username = params.get("username", "")
        if username:
            cmd.extend(["-U", username])
        else:
            cmd.extend(["-U", ""])

        command = params.get("command", "enumdomusers")
        cmd.extend(["-c", command])

        cmd.append(target)

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
