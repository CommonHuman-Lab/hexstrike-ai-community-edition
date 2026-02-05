"""
CloudMapper Tool Implementation
AWS network visualization and security
"""

from typing import Any, Dict, List

from ..base import BaseTool


class CloudmapperTool(BaseTool):
    """
    CloudMapper - AWS network visualization and security.

    Example usage:
        tool = CloudmapperTool()
        result = tool.execute('', {
            'action': 'collect',
            'account': 'my-aws-account'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("CloudMapper", "cloudmapper")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = ["python3", "cloudmapper.py"]

        action = params.get("action", "collect")
        cmd.append(action)

        account = params.get("account", "")
        if account:
            cmd.extend(["--account", account])

        config = params.get("config", "config.json")
        cmd.extend(["--config", config])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
