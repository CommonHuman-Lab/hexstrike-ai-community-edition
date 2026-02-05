"""
Scalpel tool implementation for file carving
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class ScalpelTool(BaseTool):
    """Scalpel - File carving tool with configurable headers and footers"""

    def __init__(self):
        super().__init__("Scalpel", "scalpel")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build scalpel command with options

        Args:
            target: Target file or disk image
            params: Dictionary containing:
                - output_dir: Output directory for carved files
                - config: Custom configuration file
                - preview: Preview mode
                - verbose: Verbose output
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["scalpel"]

        # Output directory
        output_dir = params.get("output_dir", "/tmp/scalpel_output")
        cmd_parts.extend(["-o", output_dir])

        # Config file
        config = params.get("config", "")
        if config:
            cmd_parts.extend(["-c", config])

        # Preview mode
        if params.get("preview", False):
            cmd_parts.append("-p")

        # Verbose
        if params.get("verbose", True):
            cmd_parts.append("-v")

        cmd_parts.append(target)

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse scalpel output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "files_carved": [],
            "total_carved": 0
        }

        lines = stdout.split('\n')
        for line in lines:
            if "carved" in line.lower():
                result["files_carved"].append(line.strip())
            # Try to extract carved file count
            import re
            match = re.search(r'(\d+)\s*file', line)
            if match:
                result["total_carved"] = int(match.group(1))

        return result
