"""
Foremost Tool Implementation
Data carving tool
"""

from typing import Any, Dict, List

from ..base import BaseTool


class ForemostTool(BaseTool):
    """
    Foremost - Data carving tool.

    Example usage:
        tool = ForemostTool()
        result = tool.execute('/path/to/image.dd', {
            'output_dir': '/tmp/carved',
            'types': 'jpg,png,pdf'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Foremost", "foremost")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        output_dir = params.get("output_dir", "/tmp/foremost_output")
        cmd.extend(["-o", output_dir])

        types = params.get("types", "")
        if types:
            cmd.extend(["-t", types])

        verbose = params.get("verbose", False)
        if verbose:
            cmd.append("-v")

        cmd.extend(["-i", target])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
