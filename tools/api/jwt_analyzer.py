"""
JWT Analyzer Tool Implementation
JSON Web Token security analysis
"""

from typing import Any, Dict, List

from ..base import BaseTool


class JwtAnalyzerTool(BaseTool):
    """
    JWT Analyzer - JSON Web Token security analysis.

    Example usage:
        tool = JwtAnalyzerTool()
        result = tool.execute('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', {
            'action': 'crack'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("JWT Analyzer", "jwt_tool")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, target]

        action = params.get("action", "")
        if action == "crack":
            cmd.append("-C")
            wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
            cmd.extend(["-d", wordlist])
        elif action == "tamper":
            cmd.append("-T")
        elif action == "exploit":
            cmd.append("-X")
            exploit_type = params.get("exploit_type", "")
            if exploit_type:
                cmd.append(exploit_type)

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
