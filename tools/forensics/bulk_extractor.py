"""
Bulk Extractor tool implementation for digital forensics
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class BulkExtractorTool(BaseTool):
    """Bulk Extractor - Digital forensics tool for extracting features"""

    def __init__(self):
        super().__init__("BulkExtractor", "bulk_extractor")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build bulk_extractor command with options

        Args:
            target: Target file or disk image
            params: Dictionary containing:
                - output_dir: Output directory
                - scanner: Specific scanners to enable
                - threads: Number of threads
                - quiet: Quiet mode
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["bulk_extractor"]

        # Output directory
        output_dir = params.get("output_dir", "/tmp/bulk_output")
        cmd_parts.extend(["-o", output_dir])

        # Scanners
        scanner = params.get("scanner", "")
        if scanner:
            for s in scanner.split(","):
                cmd_parts.extend(["-E", s.strip()])

        # Threads
        threads = params.get("threads", 4)
        cmd_parts.extend(["-j", str(threads)])

        # Quiet mode
        if params.get("quiet", False):
            cmd_parts.append("-q")

        cmd_parts.append(target)

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse bulk_extractor output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "features_found": [],
            "files_created": []
        }

        lines = stdout.split('\n')
        for line in lines:
            if ".txt" in line or "found" in line.lower():
                result["features_found"].append(line.strip())

        return result
