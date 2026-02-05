"""
Sherlock tool implementation for username investigation across social networks
"""

from typing import Any, Dict, List

from tools.base import BaseTool


class SherlockTool(BaseTool):
    """Sherlock - Username investigation across 400+ social networks"""

    def __init__(self):
        super().__init__("Sherlock", "sherlock")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build sherlock command with options

        Args:
            target: Username to investigate
            params: Dictionary containing:
                - timeout: Request timeout in seconds
                - print_all: Print all results including not found
                - print_found: Print only found results
                - no_color: Disable colored output
                - browse: Open found URLs in browser
                - local: Force local data.json file
                - csv: Create CSV report
                - xlsx: Create XLSX report
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["sherlock", target]

        # Timeout
        timeout = params.get("timeout", 60)
        cmd_parts.extend(["--timeout", str(timeout)])

        # Print options
        if params.get("print_all", False):
            cmd_parts.append("--print-all")
        elif params.get("print_found", True):
            cmd_parts.append("--print-found")

        # Output options
        if params.get("no_color", False):
            cmd_parts.append("--no-color")

        if params.get("csv", False):
            cmd_parts.append("--csv")

        if params.get("xlsx", False):
            cmd_parts.append("--xlsx")

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse sherlock output to extract found profiles"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "found_profiles": [],
            "not_found": [],
        }

        lines = stdout.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Found profiles typically have URLs
            if "http" in line.lower() and "[+]" in line:
                result["found_profiles"].append(line.replace("[+]", "").strip())
            elif "[-]" in line:
                result["not_found"].append(line.replace("[-]", "").strip())

        result["found_count"] = len(result["found_profiles"])
        result["checked_count"] = len(result["found_profiles"]) + len(result["not_found"])

        return result
