"""
SSLyze tool implementation for SSL/TLS configuration analysis
"""

from typing import Any, Dict, List

from tools.base import BaseTool


class SSLyzeTool(BaseTool):
    """SSLyze - Fast and comprehensive SSL/TLS configuration analyzer"""

    def __init__(self):
        super().__init__("SSLyze", "sslyze")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build sslyze command with options

        Args:
            target: Target hostname:port
            params: Dictionary containing:
                - certinfo: Get certificate info
                - cipher_suites: Test cipher suites
                - fallback: Test fallback SCSV
                - heartbleed: Test heartbleed
                - robot: Test ROBOT
                - compression: Test compression
                - json_output: JSON output file
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["sslyze", target]

        # Certificate info
        if params.get("certinfo", True):
            cmd_parts.append("--certinfo")

        # Cipher suites
        if params.get("cipher_suites", True):
            cmd_parts.append("--sslv2")
            cmd_parts.append("--sslv3")
            cmd_parts.append("--tlsv1")
            cmd_parts.append("--tlsv1_1")
            cmd_parts.append("--tlsv1_2")
            cmd_parts.append("--tlsv1_3")

        # Fallback SCSV
        if params.get("fallback", True):
            cmd_parts.append("--fallback")

        # Heartbleed
        if params.get("heartbleed", True):
            cmd_parts.append("--heartbleed")

        # ROBOT
        if params.get("robot", True):
            cmd_parts.append("--robot")

        # Compression
        if params.get("compression", True):
            cmd_parts.append("--compression")

        # JSON output
        json_output = params.get("json_output", "")
        if json_output:
            cmd_parts.extend(["--json_out", json_output])

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse sslyze output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "vulnerabilities": [],
            "supported_protocols": [],
            "certificate_info": {},
        }

        lines = stdout.split("\n")
        for line in lines:
            line = line.strip()
            if "VULNERABLE" in line.upper():
                result["vulnerabilities"].append(line)
            if "TLS" in line or "SSL" in line:
                if "OK" in line or "supported" in line.lower():
                    result["supported_protocols"].append(line)

        result["vulnerability_count"] = len(result["vulnerabilities"])

        return result
