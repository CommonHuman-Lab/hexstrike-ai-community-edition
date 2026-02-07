"""
GDB-GEF tool implementation for exploit development
"""

from typing import Any, Dict, List

from tools.base import BaseTool


class GDBGEFTool(BaseTool):
    """GDB-GEF - GDB Enhanced Features for exploit development"""

    def __init__(self):
        super().__init__("GDB-GEF", "gdb")

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """
        Build gdb with GEF command with options

        Args:
            target: Target binary or PID
            params: Dictionary containing:
                - commands: GDB commands to execute
                - args: Arguments for the target binary
                - core: Core dump file
                - symbols: Symbol file
                - batch: Batch mode
                - gef_script: GEF script to run
                - additional_args: Additional arguments

        Returns:
            List of command arguments
        """
        cmd_parts = ["gdb", "-q"]

        # Load GEF
        cmd_parts.extend(["-ex", "source ~/.gdbinit-gef.py"])

        # Core dump
        core = params.get("core", "")
        if core:
            cmd_parts.extend(["-c", core])

        # Symbols
        symbols = params.get("symbols", "")
        if symbols:
            cmd_parts.extend(["-s", symbols])

        # Batch mode
        if params.get("batch", True):
            cmd_parts.append("--batch")

        # Commands
        commands = params.get("commands", "")
        if commands:
            for cmd in commands.split(";"):
                cmd_parts.extend(["-ex", cmd.strip()])

        cmd_parts.append(target)

        # Arguments for target
        args = params.get("args", "")
        if args:
            cmd_parts.extend(["--args", args])

        # Additional arguments
        additional_args = params.get("additional_args", "")
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return cmd_parts

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Dict[str, Any]:
        """Parse GDB-GEF output"""
        result = {
            "raw_output": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "registers": {},
            "stack": [],
            "code": [],
        }

        lines = stdout.split("\n")
        section = None
        for line in lines:
            if "registers" in line.lower():
                section = "registers"
            elif "stack" in line.lower():
                section = "stack"
            elif "code" in line.lower():
                section = "code"
            elif section == "stack":
                result["stack"].append(line.strip())
            elif section == "code":
                result["code"].append(line.strip())

        return result
