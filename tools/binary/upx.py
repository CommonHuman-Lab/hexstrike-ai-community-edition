"""
UPX tool implementation for executable packing/unpacking
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class UPXTool(BaseTool):
    """UPX - Executable packer/unpacker for binary analysis"""

    def __init__(self):
        super().__init__("UPX", "upx")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build upx command with options

        Args:
            target: Target binary file
            params: Dictionary containing:
                - decompress: Decompress the file
                - compress: Compress the file
                - test: Test compressed file
                - list: List compression info
                - best: Best compression
                - output: Output file
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["upx"]

        # Mode
        if params.get("decompress", False):
            cmd_parts.append("-d")
        elif params.get("test", False):
            cmd_parts.append("-t")
        elif params.get("list", False):
            cmd_parts.append("-l")
        elif params.get("compress", True):
            if params.get("best", False):
                cmd_parts.append("--best")

        # Output file
        output = params.get("output", "")
        if output:
            cmd_parts.extend(["-o", output])

        cmd_parts.append(target)

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse upx output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "packed": False,
            "ratio": "",
            "format": ""
        }

        lines = stdout.split('\n')
        for line in lines:
            if "packed" in line.lower():
                result["packed"] = True
            if "ratio" in line.lower() or "%" in line:
                result["ratio"] = line.strip()
            if "format" in line.lower():
                result["format"] = line.strip()

        return result
