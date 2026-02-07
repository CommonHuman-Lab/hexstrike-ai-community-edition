"""
Qsreplace Tool Implementation
URL query string parameter replacement
"""

from typing import Any, Dict, List

from ..base import BaseTool


class QsreplaceTool(BaseTool):
    """
    Qsreplace - URL query string parameter replacement.

    Example usage:
        tool = QsreplaceTool()
        result = tool.execute('FUZZ', {}, execute_command)
    """

    def __init__(self):
        super().__init__("Qsreplace", "qsreplace")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        if target:
            cmd.append(target)

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
