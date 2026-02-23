# mcp_tools/metadata_extract/exiftool.py

from typing import Dict, Any

def register_exiftool_tool(mcp, hexstrike_client, logger):
    
    @mcp.tool()
    def exiftool_extract(file_path: str, output_format: str = "", tags: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ExifTool for metadata extraction with enhanced logging.

        Args:
            file_path: Path to file for metadata extraction
            output_format: Output format (json, xml, csv)
            tags: Specific tags to extract
            additional_args: Additional ExifTool arguments

        Returns:
            Metadata extraction results
        """
        data = {
            "file_path": file_path,
            "output_format": output_format,
            "tags": tags,
            "additional_args": additional_args
        }
        logger.info(f"📷 Starting ExifTool analysis: {file_path}")
        result = hexstrike_client.safe_post("api/tools/exiftool", data)
        if result.get("success"):
            logger.info(f"✅ ExifTool analysis completed")
        else:
            logger.error(f"❌ ExifTool analysis failed")
        return result
