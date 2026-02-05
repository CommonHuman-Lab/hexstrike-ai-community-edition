"""
Enum4linux Tool Implementation
SMB enumeration tool
"""

from typing import Any, Dict, List

from ..base import BaseTool


class Enum4linuxTool(BaseTool):
    """
    Enum4linux - SMB enumeration tool.

    Example usage:
        tool = Enum4linuxTool()
        result = tool.execute('192.168.1.100', {
            'all': True
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Enum4linux", "enum4linux")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        all_enum = params.get("all", True)
        if all_enum:
            cmd.append("-a")

        username = params.get("username", "")
        if username:
            cmd.extend(["-u", username])

        password = params.get("password", "")
        if password:
            cmd.extend(["-p", password])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        cmd.append(target)
        return cmd
