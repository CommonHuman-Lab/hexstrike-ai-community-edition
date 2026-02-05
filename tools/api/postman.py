"""
Postman/Newman Tool Implementation
CLI runner for Postman API collections - automated API testing
"""

from typing import Any, Dict, List

from ..base import BaseTool


class PostmanTool(BaseTool):
    """
    Postman (Newman) - CLI runner for Postman API collections.
    Executes Postman collections from the command line for automated API security testing.

    Example usage:
        tool = PostmanTool()
        result = tool.execute('https://api.example.com', {
            'collection': '/path/to/collection.json'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Postman (Newman)", "newman")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, "run"]

        collection = params.get("collection", "")
        if collection:
            cmd.append(collection)

        environment = params.get("environment", "")
        if environment:
            cmd.extend(["-e", environment])

        globals_file = params.get("globals", "")
        if globals_file:
            cmd.extend(["-g", globals_file])

        iterations = params.get("iterations", 1)
        if iterations > 1:
            cmd.extend(["-n", str(iterations)])

        delay = params.get("delay", 0)
        if delay:
            cmd.extend(["--delay-request", str(delay)])

        timeout = params.get("timeout", 30000)
        cmd.extend(["--timeout-request", str(timeout)])

        reporters = params.get("reporters", "cli,json")
        cmd.extend(["-r", reporters])

        env_vars = params.get("env_var", "")
        if env_vars:
            for var in env_vars.split(","):
                cmd.extend(["--env-var", var.strip()])

        if target:
            cmd.extend(["--env-var", f"base_url={target}"])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
