"""
NetExec Tool Implementation
Network service exploitation (formerly CrackMapExec)
"""

from typing import Any, Dict, List

from ..base import BaseTool


class NetexecTool(BaseTool):
    """
    NetExec - Network service exploitation.

    Example usage:
        tool = NetexecTool()
        result = tool.execute('192.168.1.100', {
            'protocol': 'smb',
            'username': 'admin',
            'password': 'password'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("NetExec", "netexec")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        protocol = params.get("protocol", "smb")
        cmd = [self.binary_name, protocol, target]

        username = params.get("username", "")
        if username:
            cmd.extend(["-u", username])

        password = params.get("password", "")
        if password:
            cmd.extend(["-p", password])

        hash_val = params.get("hash", "")
        if hash_val:
            cmd.extend(["-H", hash_val])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
