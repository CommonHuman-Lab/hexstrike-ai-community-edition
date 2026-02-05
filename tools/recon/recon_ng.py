"""
Recon-ng tool implementation for web reconnaissance framework
"""
from typing import Dict, Any, List
from tools.base import BaseTool


class ReconNgTool(BaseTool):
    """Recon-ng - Web reconnaissance framework with modular architecture"""

    def __init__(self):
        super().__init__("Recon-ng", "recon-ng")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build recon-ng command with options

        Args:
            target: Target domain
            params: Dictionary containing:
                - workspace: Workspace name
                - module: Module to run
                - options: Module options as dict
                - script: Script file to execute
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["recon-ng"]

        # Workspace
        workspace = params.get("workspace", "default")
        cmd_parts.extend(["-w", workspace])

        # Module execution
        module = params.get("module", "")
        if module:
            cmd_parts.extend(["-m", module])

        # Options
        options = params.get("options", {})
        if options:
            for key, value in options.items():
                cmd_parts.extend(["-o", f"{key}={value}"])

        # Target as SOURCE option
        if target:
            cmd_parts.extend(["-o", f"SOURCE={target}"])

        # Script file
        script = params.get("script", "")
        if script:
            cmd_parts.extend(["-r", script])

        # Non-interactive mode
        cmd_parts.append("--no-check")

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse recon-ng output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "findings": [],
            "hosts": [],
            "contacts": []
        }

        lines = stdout.split('\n')
        for line in lines:
            line = line.strip()
            if "[*]" in line or "[+]" in line:
                result["findings"].append(line)

        result["finding_count"] = len(result["findings"])

        return result
