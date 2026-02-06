"""
Trivy Tool Implementation
Container and filesystem vulnerability scanner
"""

from typing import Any, Dict, List

from ..base import BaseTool


class TrivyTool(BaseTool):
    """
    Trivy - Container and filesystem vulnerability scanner.

    Example usage:
        tool = TrivyTool()
        result = tool.execute('nginx:latest', {
            'scan_type': 'image',
            'severity': 'HIGH,CRITICAL'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Trivy", "trivy")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        scan_type = params.get("scan_type", "image")
        cmd.append(scan_type)

        output_format = params.get("output_format", "json")
        cmd.extend(["--format", output_format])

        severity = params.get("severity", "")
        if severity:
            cmd.extend(["--severity", severity])

        output_file = params.get("output_file", "")
        if output_file:
            cmd.extend(["--output", output_file])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        cmd.append(target)
        return cmd
