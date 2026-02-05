"""
Stegsolve tool implementation for steganography analysis
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class StegSolveTool(BaseTool):
    """StegSolve - Steganography analysis with visual inspection"""

    def __init__(self):
        super().__init__("StegSolve", "stegsolve")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build stegsolve command with options

        StegSolve is a Java GUI tool, so we provide command-line equivalent analysis

        Args:
            target: Target image file
            params: Dictionary containing:
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        # StegSolve is typically a GUI tool, but we can run it headlessly
        cmd_parts = ["java", "-jar", "/opt/stegsolve/stegsolve.jar", target]

        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse stegsolve output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "analysis_complete": returncode == 0
        }

        return result


class OutguessTool(BaseTool):
    """Outguess - Universal steganographic tool for JPEG images"""

    def __init__(self):
        super().__init__("Outguess", "outguess")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build outguess command with options

        Args:
            target: Target image file
            params: Dictionary containing:
                - extract: Extract hidden data
                - key: Key for extraction
                - output: Output file
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["outguess"]

        # Mode
        if params.get("extract", True):
            cmd_parts.append("-r")
        
        # Key
        key = params.get("key", "")
        if key:
            cmd_parts.extend(["-k", key])

        cmd_parts.append(target)

        # Output file
        output = params.get("output", "/tmp/outguess_output.txt")
        cmd_parts.append(output)

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse outguess output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "extracted": returncode == 0,
            "bytes_extracted": 0
        }

        # Try to find extracted bytes count
        import re
        match = re.search(r'(\d+)\s*bytes', stdout + stderr)
        if match:
            result["bytes_extracted"] = int(match.group(1))

        return result
