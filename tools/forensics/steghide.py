"""
Steghide Tool Implementation
Steganography tool
"""

from typing import Any, Dict, List

from ..base import BaseTool


class SteghideTool(BaseTool):
    """
    Steghide - Steganography tool for hiding/extracting data.

    Example usage:
        tool = SteghideTool()
        result = tool.execute('/path/to/image.jpg', {
            'action': 'extract',
            'passphrase': 'secret'
        }, execute_command)
    """

    def __init__(self):
        super().__init__("Steghide", "steghide")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]

        action = params.get("action", "info")
        cmd.append(action)

        cmd.extend(["-sf", target])

        passphrase = params.get("passphrase", "")
        if passphrase:
            cmd.extend(["-p", passphrase])

        extract_file = params.get("extract_file", "")
        if extract_file:
            cmd.extend(["-xf", extract_file])

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd.extend(additional_args.split())

        return cmd
