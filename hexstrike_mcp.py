#!/usr/bin/env python3
"""
HexStrike AI MCP Client - Enhanced AI Agent Communication Interface

Enhanced with AI-Powered Intelligence & Automation
🚀 Bug Bounty | CTF | Red Team | Security Research

Architecture: MCP Client for AI agent communication with HexStrike server
Framework: FastMCP integration for tool orchestration
"""

import sys
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import time
from datetime import datetime

import core.config_core as config_core
from mcp.server.fastmcp import FastMCP
from mcp_core.hexstrikecolors import HexStrikeColors

# Backward compatibility alias
Colors = HexStrikeColors

class ColoredFormatter(logging.Formatter):
    """Enhanced formatter with colors and emojis for MCP client - matches server styling"""

    COLORS = {
        'DEBUG': HexStrikeColors.DEBUG,
        'INFO': HexStrikeColors.SUCCESS,
        'WARNING': HexStrikeColors.WARNING,
        'ERROR': HexStrikeColors.ERROR,
        'CRITICAL': HexStrikeColors.CRITICAL
    }

    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, HexStrikeColors.BRIGHT_WHITE)

        # Add color and emoji to the message
        record.msg = f"{color}{emoji} {record.msg}{HexStrikeColors.RESET}"
        return super().format(record)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[🔥 HexStrike MCP] %(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

# Apply colored formatter
for handler in logging.getLogger().handlers:
    handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike MCP] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_HEXSTRIKE_SERVER = "http://127.0.0.1:8888"  # Default HexStrike server URL
DEFAULT_REQUEST_TIMEOUT = config_core.get("COMMAND_TIMEOUT", 300)  # 5 minutes default timeout
MAX_RETRIES = 3  # Maximum number of retries for connection attempts

class HexStrikeClient:
    """Enhanced client for communicating with the HexStrike AI API Server"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the HexStrike AI Client

        Args:
            server_url: URL of the HexStrike AI API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

        # Try to connect to server with retries
        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"🔗 Attempting to connect to HexStrike AI API at {server_url} (attempt {i+1}/{MAX_RETRIES})")
                # First try a direct connection test before using the health endpoint
                try:
                    test_response = self.session.get(f"{self.server_url}/health", timeout=5)
                    test_response.raise_for_status()
                    health_check = test_response.json()
                    connected = True
                    logger.info(f"🎯 Successfully connected to HexStrike AI API Server at {server_url}")
                    logger.info(f"🏥 Server health status: {health_check.get('status', 'unknown')}")
                    logger.info(f"📊 Server version: {health_check.get('version', 'unknown')}")
                    break
                except requests.exceptions.ConnectionError:
                    logger.warning(f"🔌 Connection refused to {server_url}. Make sure the HexStrike AI server is running.")
                    time.sleep(2)  # Wait before retrying
                except Exception as e:
                    logger.warning(f"⚠️  Connection test failed: {str(e)}")
                    time.sleep(2)  # Wait before retrying
            except Exception as e:
                logger.warning(f"❌ Connection attempt {i+1} failed: {str(e)}")
                time.sleep(2)  # Wait before retrying

        if not connected:
            error_msg = f"Failed to establish connection to HexStrike AI API Server at {server_url} after {MAX_RETRIES} attempts"
            logger.error(error_msg)
            # We'll continue anyway to allow the MCP server to start, but tools will likely fail

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.

        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters

        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"📡 GET {url} with params: {params}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.

        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send

        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"📡 POST {url} with data: {json_data}")
            response = self.session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute a generic command on the HexStrike server

        Args:
            command: Command to execute
            use_cache: Whether to use caching for this command

        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command, "use_cache": use_cache})

    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the HexStrike AI API Server

        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(hexstrike_client: HexStrikeClient, compact: bool = False) -> FastMCP:
    """
    Set up the MCP server with all enhanced tool functions

    Args:
        hexstrike_client: Initialized HexStrikeClient
        compact: If True, register only classify_task and run_tool gateway tools

    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("hexstrike-ai-mcp")

    # ============================================================================
    # GATEWAY TOOLS (always registered)
    # ============================================================================

    # Register gateway tools for task classification and tool execution
    from mcp_tools.gateway import register_gateway_tools
    register_gateway_tools(mcp, hexstrike_client)

    if compact:
        logger.info("Compact mode: only gateway tools registered (classify_task, run_tool)")
        return mcp
    
     # Register wordlist tools
    from mcp_tools.wordlist import register_wordlist_tools
    register_wordlist_tools(mcp, hexstrike_client)

    # Register bot tools
    from mcp_tools.bot import register_bot_tools
    register_bot_tools(mcp, hexstrike_client)

    # Register database tools
    from mcp_tools.database import register_database_tools
    register_database_tools(mcp, hexstrike_client, logger)

    # Register core network scanning tools
    from mcp_tools.core_network_scanning import register_core_network_scanning_tools
    register_core_network_scanning_tools(mcp, hexstrike_client, logger, HexStrikeColors)

    # Register cloud and container security tools
    from mcp_tools.cloud_and_container_security import register_cloud_and_container_security_tools
    register_cloud_and_container_security_tools(mcp, hexstrike_client, logger)

    # Register file operations and payload generation tools
    from mcp_tools.file_ops_and_payload_gen import register_file_ops_and_payload_gen_tools
    register_file_ops_and_payload_gen_tools(mcp, hexstrike_client, logger)

    # Register Python environment management tools
    from mcp_tools.python_env import register_python_env_tools
    register_python_env_tools(mcp, hexstrike_client, logger)

    # Register additional security tools that were in the original implementation but not yet categorized
    from mcp_tools.additional_security_tools import register_additional_security_tools
    register_additional_security_tools(mcp, hexstrike_client, logger)

    # Register enhanced network scanning and enumeration tools
    from mcp_tools.enhanced_network_scanning import register_enhanced_network_scanning_tools
    register_enhanced_network_scanning_tools(mcp, hexstrike_client, logger)

    # Register binary analysis and reverse engineering tools
    from mcp_tools.binary_analysis_and_reverse_engineering import register_binary_analysis_and_reverse_engineering_tools
    register_binary_analysis_and_reverse_engineering_tools(mcp, hexstrike_client, logger)

    # Register enhanced binary analysis and exploitation tools
    from mcp_tools.enhanced_binary_analysis_and_exploitation import register_enhanced_binary_analysis_and_exploitation_tools
    register_enhanced_binary_analysis_and_exploitation_tools(mcp, hexstrike_client, logger) 
   
    # Register enhanced web application security tools
    from mcp_tools.enhanced_web_app_security import register_enhanced_web_app_security_tools
    register_enhanced_web_app_security_tools(mcp, hexstrike_client, logger, HexStrikeColors)

    # Register AI-powered payload generation and testing tools
    from mcp_tools.ai_payload_generation import register_ai_payload_generation_tools
    register_ai_payload_generation_tools(mcp, hexstrike_client, logger)

    # Register API testing tools for comprehensive API security assessment
    from mcp_tools.api_testing import register_api_testing_tools
    register_api_testing_tools(mcp, hexstrike_client, logger)

    # Register advanced CTF tools for competitive security challenges
    from mcp_tools.advanced_ctf_tools import register_advanced_ctf_tools
    register_advanced_ctf_tools(mcp, hexstrike_client, logger)

    # Regular bug bounty recon tools for web endpoint discovery and parameter enumeration
    from mcp_tools.bug_bounty_recon import register_bug_bounty_recon_tools
    register_bug_bounty_recon_tools(mcp, hexstrike_client, logger)

    # Register system monitoring tools for server health, cache stats, and telemetry
    from mcp_tools.system_monitoring import register_system_monitoring_tools
    register_system_monitoring_tools(mcp, hexstrike_client, logger)

    # Register process management tools for advanced task handling and monitoring
    from mcp_tools.process_management import register_process_management_tools
    register_process_management_tools(mcp, hexstrike_client, logger)

    # Register vulnerability intelligence tools for CVE analysis, exploit availability, and risk assessment
    from mcp_tools.vulnerability_intelligence import register_vulnerability_intelligence_tools
    register_vulnerability_intelligence_tools(mcp, hexstrike_client, logger)

    # Register enhanced visual output tools for better result presentation
    from mcp_tools.visual_output_tools import register_visual_output_tools
    register_visual_output_tools(mcp, hexstrike_client, logger)
    
    # Register intelligent decision engine tools for AI-powered analysis and recommendations
    from mcp_tools.intelligent_decision_engine import register_intelligent_decision_engine_tools
    register_intelligent_decision_engine_tools(mcp, hexstrike_client, logger, HexStrikeColors)

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the HexStrike AI MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_HEXSTRIKE_SERVER,
                      help=f"HexStrike AI API server URL (default: {DEFAULT_HEXSTRIKE_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--compact", action="store_true", help="Compact mode: register only classify_task and run_tool for small LLM clients")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()

    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled")

    # MCP compatibility: No banner output to avoid JSON parsing issues
    logger.info(f"🚀 Starting HexStrike AI MCP Client")
    logger.info(f"🔗 Connecting to: {args.server}")

    try:
        # Initialize the HexStrike AI client
        hexstrike_client = HexStrikeClient(args.server, args.timeout)

        # Check server health and log the result
        health = hexstrike_client.check_health()
        if "error" in health:
            logger.warning(f"⚠️  Unable to connect to HexStrike AI API server at {args.server}: {health['error']}")
            logger.warning("🚀 MCP server will start, but tool execution may fail")
        else:
            logger.info(f"🎯 Successfully connected to HexStrike AI API server at {args.server}")
            logger.info(f"🏥 Server health status: {health['status']}")
            logger.info(f"📊 Version: {config_core.get('VERSION', 'unknown')}")
            if not health.get("all_essential_tools_available", False):
                logger.warning("⚠️  Not all essential tools are available on the HexStrike server")
                missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
                if missing_tools:
                    logger.warning(f"❌ Missing tools: {', '.join(missing_tools[:5])}{'...' if len(missing_tools) > 5 else ''}")

        # Set up and run the MCP server
        mcp = setup_mcp_server(hexstrike_client, compact=args.compact)
        logger.info("🚀 Starting HexStrike AI MCP server")
        logger.info("🤖 Ready to serve AI agents with enhanced cybersecurity capabilities")
        # stdio fallback for MCP clients that don't support the run() method
        try:
            mcp.run()
        except AttributeError:
            import asyncio
            if hasattr(mcp, "run_stdio"):
                asyncio.run(mcp.run_stdio_async())
            else:
                raise
    except Exception as e:
        logger.error(f"💥 Error starting MCP server: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
