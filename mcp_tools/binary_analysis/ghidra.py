# mcp_tools/binary_analysis/ghidra.py

from typing import Dict, Any

def register_ghidra_tools(mcp, hexstrike_client, logger):

    @mcp.tool()
    def ghidra_analysis(binary: str, project_name: str = "hexstrike_analysis",
                       script_file: str = "", analysis_timeout: int = 300,
                       output_format: str = "xml", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Ghidra for advanced binary analysis and reverse engineering.

        Args:
            binary: Path to the binary file
            project_name: Ghidra project name
            script_file: Custom Ghidra script to run
            analysis_timeout: Analysis timeout in seconds
            output_format: Output format (xml, json)
            additional_args: Additional Ghidra arguments

        Returns:
            Advanced binary analysis results from Ghidra
        """
        data = {
            "binary": binary,
            "project_name": project_name,
            "script_file": script_file,
            "analysis_timeout": analysis_timeout,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting Ghidra analysis: {binary}")
        result = hexstrike_client.safe_post("api/tools/ghidra", data)
        if result.get("success"):
            logger.info(f"✅ Ghidra analysis completed for {binary}")
        else:
            logger.error(f"❌ Ghidra analysis failed for {binary}")
        return result