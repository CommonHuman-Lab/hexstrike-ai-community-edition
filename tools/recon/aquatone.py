"""
Aquatone tool implementation for visual inspection of websites
"""

from typing import Any, Dict, List

from tools.base import BaseTool


class AquatoneTool(BaseTool):
    """Aquatone - Visual inspection of websites across multiple hosts"""

    def __init__(self):
        super().__init__("Aquatone", "aquatone")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build aquatone command with options

        Args:
            target: Target file with URLs or piped input
            params: Dictionary containing:
                - out_dir: Output directory
                - threads: Number of concurrent threads
                - timeout: Request timeout
                - ports: Ports to scan
                - scan_timeout: Timeout for port scanning
                - screenshot_timeout: Timeout for screenshots
                - chrome_path: Path to Chrome binary
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["aquatone"]

        # Output directory
        out_dir = params.get("out_dir", "/tmp/aquatone")
        cmd_parts.extend(["-out", out_dir])

        # Threads
        threads = params.get("threads", 8)
        cmd_parts.extend(["-threads", str(threads)])

        # Timeout
        timeout = params.get("timeout", 30000)
        cmd_parts.extend(["-timeout", str(timeout)])

        # Ports
        ports = params.get("ports", "80,443,8080,8443")
        if ports:
            cmd_parts.extend(["-ports", ports])

        # Screenshot timeout
        screenshot_timeout = params.get("screenshot_timeout", 30000)
        cmd_parts.extend(["-screenshot-timeout", str(screenshot_timeout)])

        # Chrome path
        chrome_path = params.get("chrome_path", "")
        if chrome_path:
            cmd_parts.extend(["-chrome-path", chrome_path])

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse aquatone output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "screenshots": [],
            "pages_processed": 0,
        }

        lines = stdout.split("\n")
        for line in lines:
            if "screenshot" in line.lower():
                result["screenshots"].append(line.strip())
            if "pages" in line.lower() and "processed" in line.lower():
                # Try to extract page count
                import re

                match = re.search(r"(\d+)\s*pages", line)
                if match:
                    result["pages_processed"] = int(match.group(1))

        result["screenshot_count"] = len(result["screenshots"])

        return result
