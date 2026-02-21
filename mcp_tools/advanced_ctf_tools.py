# mcp_tools/advanced_ctf_tools.py

from typing import Dict, Any

def register_advanced_ctf_tools(mcp, hexstrike_client, logger):
    @mcp.tool()
    def volatility3_analyze(memory_file: str, plugin: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Volatility3 for advanced memory forensics with enhanced logging.

        Args:
            memory_file: Path to memory dump file
            plugin: Volatility3 plugin to execute
            output_file: Output file path
            additional_args: Additional Volatility3 arguments

        Returns:
            Advanced memory forensics results
        """
        data = {
            "memory_file": memory_file,
            "plugin": plugin,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🧠 Starting Volatility3 analysis: {plugin}")
        result = hexstrike_client.safe_post("api/tools/volatility3", data)
        if result.get("success"):
            logger.info(f"✅ Volatility3 analysis completed")
        else:
            logger.error(f"❌ Volatility3 analysis failed")
        return result

    @mcp.tool()
    def foremost_carving(input_file: str, output_dir: str = "/tmp/foremost_output", file_types: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Foremost for file carving with enhanced logging.

        Args:
            input_file: Input file or device to carve
            output_dir: Output directory for carved files
            file_types: File types to carve (jpg,gif,png,etc.)
            additional_args: Additional Foremost arguments

        Returns:
            File carving results
        """
        data = {
            "input_file": input_file,
            "output_dir": output_dir,
            "file_types": file_types,
            "additional_args": additional_args
        }
        logger.info(f"📁 Starting Foremost file carving: {input_file}")
        result = hexstrike_client.safe_post("api/tools/foremost", data)
        if result.get("success"):
            logger.info(f"✅ Foremost carving completed")
        else:
            logger.error(f"❌ Foremost carving failed")
        return result

    @mcp.tool()
    def steghide_analysis(action: str, cover_file: str, embed_file: str = "", passphrase: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Steghide for steganography analysis with enhanced logging.

        Args:
            action: Action to perform (extract, embed, info)
            cover_file: Cover file for steganography
            embed_file: File to embed (for embed action)
            passphrase: Passphrase for steganography
            output_file: Output file path
            additional_args: Additional Steghide arguments

        Returns:
            Steganography analysis results
        """
        data = {
            "action": action,
            "cover_file": cover_file,
            "embed_file": embed_file,
            "passphrase": passphrase,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🖼️ Starting Steghide {action}: {cover_file}")
        result = hexstrike_client.safe_post("api/tools/steghide", data)
        if result.get("success"):
            logger.info(f"✅ Steghide {action} completed")
        else:
            logger.error(f"❌ Steghide {action} failed")
        return result

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

    @mcp.tool()
    def hashpump_attack(signature: str, data: str, key_length: str, append_data: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute HashPump for hash length extension attacks with enhanced logging.

        Args:
            signature: Original hash signature
            data: Original data
            key_length: Length of secret key
            append_data: Data to append
            additional_args: Additional HashPump arguments

        Returns:
            Hash length extension attack results
        """
        payload = {
            "signature": signature,
            "data": data,
            "key_length": key_length,
            "append_data": append_data,
            "additional_args": additional_args
        }
        logger.info(f"🔐 Starting HashPump attack")
        result = hexstrike_client.safe_post("api/tools/hashpump", payload)
        if result.get("success"):
            logger.info(f"✅ HashPump attack completed")
        else:
            logger.error(f"❌ HashPump attack failed")
        return result
