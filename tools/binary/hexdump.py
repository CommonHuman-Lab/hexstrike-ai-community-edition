"""
Hexdump tool implementation for binary viewing
"""

from typing import Any, Dict, List

from tools.base import BaseTool


class HexdumpTool(BaseTool):
    """Hexdump - Hex viewer with customizable output"""

    def __init__(self):
        super().__init__("Hexdump", "hexdump")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build hexdump command with options

        Args:
            target: Target file
            params: Dictionary containing:
                - canonical: Canonical hex+ASCII display
                - length: Number of bytes to display
                - skip: Skip offset bytes
                - format: Output format string
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["hexdump"]

        # Canonical display (most common)
        if params.get("canonical", True):
            cmd_parts.append("-C")

        # Length
        length = params.get("length", "")
        if length:
            cmd_parts.extend(["-n", str(length)])

        # Skip
        skip = params.get("skip", "")
        if skip:
            cmd_parts.extend(["-s", str(skip)])

        # Format
        fmt = params.get("format", "")
        if fmt:
            cmd_parts.extend(["-e", fmt])

        cmd_parts.append(target)

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse hexdump output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "hex_lines": [],
            "ascii_strings": [],
        }

        lines = stdout.split("\n")
        for line in lines:
            if line.strip():
                result["hex_lines"].append(line)
                # Extract ASCII portion if present
                if "|" in line:
                    ascii_part = line.split("|")[-2] if line.count("|") >= 2 else ""
                    if ascii_part:
                        result["ascii_strings"].append(ascii_part)

        result["total_lines"] = len(result["hex_lines"])

        return result
