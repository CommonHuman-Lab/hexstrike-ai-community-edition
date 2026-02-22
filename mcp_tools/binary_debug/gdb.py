# mcp_tools/binary_debug/gdb.py

from typing import Dict, Any

def register_gdb_tools(mcp, hexstrike_client, logger):
    
    @mcp.tool()
    def gdb_analyze(binary: str, commands: str = "", script_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GDB for binary analysis and debugging with enhanced logging.

        Args:
            binary: Path to the binary file
            commands: GDB commands to execute
            script_file: Path to GDB script file
            additional_args: Additional GDB arguments

        Returns:
            Binary analysis results
        """
        data = {
            "binary": binary,
            "commands": commands,
            "script_file": script_file,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting GDB analysis: {binary}")
        result = hexstrike_client.safe_post("api/tools/gdb", data)
        if result.get("success"):
            logger.info(f"✅ GDB analysis completed for {binary}")
        else:
            logger.error(f"❌ GDB analysis failed for {binary}")
        return result
