"""
Angr Tool Implementation
Binary analysis with symbolic execution
"""

from typing import Any, Dict, List

from ..base import BaseTool


class AngrTool(BaseTool):
    """
    Angr - Binary analysis with symbolic execution.

    Example usage:
        tool = AngrTool()
        result = tool.execute('/path/to/binary', {
            'analysis_type': 'cfg'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Angr", "python3")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, "-c"]

        analysis_type = params.get("analysis_type", "basic")

        if analysis_type == "basic":
            script = f"import angr; p = angr.Project('{target}'); print(p)"
        elif analysis_type == "cfg":
            script = f"import angr; p = angr.Project('{target}'); cfg = p.analyses.CFGFast(); print(f'Functions: {{len(cfg.functions)}}')"
        else:
            script = params.get("script", f"import angr; p = angr.Project('{target}'); print(p)")

        cmd.append(script)
        return cmd
