"""
Zsteg tool implementation for PNG/BMP steganography detection
"""

from typing import Any, Dict, List

from tools.base import BaseTool


class ZstegTool(BaseTool):
    """Zsteg - PNG/BMP steganography detection tool"""

    def __init__(self):
        super().__init__("Zsteg", "zsteg")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build zsteg command with options

        Args:
            target: Target image file
            params: Dictionary containing:
                - all: Try all possible methods
                - bits: Number of bits to extract
                - order: Bit order (MSB/LSB)
                - channels: Color channels to check
                - limit: Limit output bytes
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["zsteg", target]

        # All methods
        if params.get("all", True):
            cmd_parts.append("-a")

        # Bits
        bits = params.get("bits", "")
        if bits:
            cmd_parts.extend(["-b", bits])

        # Order
        order = params.get("order", "")
        if order:
            cmd_parts.extend(["-o", order])

        # Channels
        channels = params.get("channels", "")
        if channels:
            cmd_parts.extend(["-c", channels])

        # Limit
        limit = params.get("limit", 256)
        cmd_parts.extend(["-l", str(limit)])

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse zsteg output"""
        result = {"raw_output": stdout, "stderr": stderr, "returncode": returncode, "findings": [], "text_found": []}

        lines = stdout.split("\n")
        for line in lines:
            line = line.strip()
            if line and ":" in line:
                result["findings"].append(line)
                if "text" in line.lower() or any(c.isalpha() for c in line.split(":")[-1]):
                    result["text_found"].append(line)

        result["finding_count"] = len(result["findings"])

        return result
