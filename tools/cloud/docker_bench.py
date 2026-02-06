"""
Docker Bench for Security Tool Implementation
Docker security assessment
"""

from typing import Any, Dict, List

from ..base import BaseTool


class DockerBenchTool(BaseTool):
    """
    Docker Bench for Security - Docker security assessment.

    Example usage:
        tool = DockerBenchTool()
        result = tool.execute('', {
            'checks': '1,2,3',
            'output_file': '/tmp/docker-bench.json'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Docker Bench", "docker-bench-security")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        checks = params.get("checks", "")
        if checks:
            cmd.extend(["-c", checks])

        exclude = params.get("exclude", "")
        if exclude:
            cmd.extend(["-e", exclude])

        output_file = params.get("output_file", "")
        if output_file:
            cmd.extend(["-l", output_file])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
