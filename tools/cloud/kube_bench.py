"""
Kube-bench Tool Implementation
CIS Kubernetes benchmark checks
"""

from typing import Any, Dict, List

from ..base import BaseTool


class KubeBenchTool(BaseTool):
    """
    Kube-bench - CIS Kubernetes benchmark checks.

    Example usage:
        tool = KubeBenchTool()
        result = tool.execute('', {
            'targets': 'master',
            'output_format': 'json'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Kube Bench", "kube-bench")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        targets = params.get("targets", "")
        if targets:
            cmd.extend(["--targets", targets])

        version = params.get("version", "")
        if version:
            cmd.extend(["--version", version])

        config_dir = params.get("config_dir", "")
        if config_dir:
            cmd.extend(["--config-dir", config_dir])

        output_format = params.get("output_format", "json")
        if output_format == "json":
            cmd.append("--json")

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
