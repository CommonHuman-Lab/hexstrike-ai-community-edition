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
    register_enhanced_web_app_security_tools(mcp, hexstrike_client, logger)

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
    
    # ============================================================================
    # BUG BOUNTY HUNTING SPECIALIZED WORKFLOWS
    # ============================================================================

    @mcp.tool()
    def bugbounty_reconnaissance_workflow(domain: str, scope: str = "", out_of_scope: str = "",
                                        program_type: str = "web") -> Dict[str, Any]:
        """
        Create comprehensive reconnaissance workflow for bug bounty hunting.

        Args:
            domain: Target domain for bug bounty
            scope: Comma-separated list of in-scope domains/IPs
            out_of_scope: Comma-separated list of out-of-scope domains/IPs
            program_type: Type of program (web, api, mobile, iot)

        Returns:
            Comprehensive reconnaissance workflow with phases and tools
        """
        data = {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "out_of_scope": out_of_scope.split(",") if out_of_scope else [],
            "program_type": program_type
        }

        logger.info(f"🎯 Creating reconnaissance workflow for {domain}")
        result = hexstrike_client.safe_post("api/bugbounty/reconnaissance-workflow", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            logger.info(f"✅ Reconnaissance workflow created - {workflow.get('tools_count', 0)} tools, ~{workflow.get('estimated_time', 0)}s")
        else:
            logger.error(f"❌ Failed to create reconnaissance workflow for {domain}")

        return result

    @mcp.tool()
    def bugbounty_vulnerability_hunting(domain: str, priority_vulns: str = "rce,sqli,xss,idor,ssrf",
                                       bounty_range: str = "unknown") -> Dict[str, Any]:
        """
        Create vulnerability hunting workflow prioritized by impact and bounty potential.

        Args:
            domain: Target domain for bug bounty
            priority_vulns: Comma-separated list of priority vulnerability types
            bounty_range: Expected bounty range (low, medium, high, critical)

        Returns:
            Vulnerability hunting workflow prioritized by impact
        """
        data = {
            "domain": domain,
            "priority_vulns": priority_vulns.split(",") if priority_vulns else [],
            "bounty_range": bounty_range
        }

        logger.info(f"🎯 Creating vulnerability hunting workflow for {domain}")
        result = hexstrike_client.safe_post("api/bugbounty/vulnerability-hunting-workflow", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            logger.info(f"✅ Vulnerability hunting workflow created - Priority score: {workflow.get('priority_score', 0)}")
        else:
            logger.error(f"❌ Failed to create vulnerability hunting workflow for {domain}")

        return result

    @mcp.tool()
    def bugbounty_business_logic_testing(domain: str, program_type: str = "web") -> Dict[str, Any]:
        """
        Create business logic testing workflow for advanced bug bounty hunting.

        Args:
            domain: Target domain for bug bounty
            program_type: Type of program (web, api, mobile)

        Returns:
            Business logic testing workflow with manual and automated tests
        """
        data = {
            "domain": domain,
            "program_type": program_type
        }

        logger.info(f"🎯 Creating business logic testing workflow for {domain}")
        result = hexstrike_client.safe_post("api/bugbounty/business-logic-workflow", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            test_count = sum(len(category["tests"]) for category in workflow.get("business_logic_tests", []))
            logger.info(f"✅ Business logic testing workflow created - {test_count} tests")
        else:
            logger.error(f"❌ Failed to create business logic testing workflow for {domain}")

        return result

    @mcp.tool()
    def bugbounty_osint_gathering(domain: str) -> Dict[str, Any]:
        """
        Create OSINT (Open Source Intelligence) gathering workflow for bug bounty reconnaissance.

        Args:
            domain: Target domain for OSINT gathering

        Returns:
            OSINT gathering workflow with multiple intelligence phases
        """
        data = {"domain": domain}

        logger.info(f"🎯 Creating OSINT gathering workflow for {domain}")
        result = hexstrike_client.safe_post("api/bugbounty/osint-workflow", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            phases = len(workflow.get("osint_phases", []))
            logger.info(f"✅ OSINT workflow created - {phases} intelligence phases")
        else:
            logger.error(f"❌ Failed to create OSINT workflow for {domain}")

        return result

    @mcp.tool()
    def bugbounty_file_upload_testing(target_url: str) -> Dict[str, Any]:
        """
        Create file upload vulnerability testing workflow with bypass techniques.

        Args:
            target_url: Target URL with file upload functionality

        Returns:
            File upload testing workflow with malicious files and bypass techniques
        """
        data = {"target_url": target_url}

        logger.info(f"🎯 Creating file upload testing workflow for {target_url}")
        result = hexstrike_client.safe_post("api/bugbounty/file-upload-testing", data)

        if result.get("success"):
            workflow = result.get("workflow", {})
            phases = len(workflow.get("test_phases", []))
            logger.info(f"✅ File upload testing workflow created - {phases} test phases")
        else:
            logger.error(f"❌ Failed to create file upload testing workflow for {target_url}")

        return result

    @mcp.tool()
    def bugbounty_comprehensive_assessment(domain: str, scope: str = "",
                                         priority_vulns: str = "rce,sqli,xss,idor,ssrf",
                                         include_osint: bool = True,
                                         include_business_logic: bool = True) -> Dict[str, Any]:
        """
        Create comprehensive bug bounty assessment combining all specialized workflows.

        Args:
            domain: Target domain for bug bounty
            scope: Comma-separated list of in-scope domains/IPs
            priority_vulns: Comma-separated list of priority vulnerability types
            include_osint: Include OSINT gathering workflow
            include_business_logic: Include business logic testing workflow

        Returns:
            Comprehensive bug bounty assessment with all workflows and summary
        """
        data = {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "priority_vulns": priority_vulns.split(",") if priority_vulns else [],
            "include_osint": include_osint,
            "include_business_logic": include_business_logic
        }

        logger.info(f"🎯 Creating comprehensive bug bounty assessment for {domain}")
        result = hexstrike_client.safe_post("api/bugbounty/comprehensive-assessment", data)

        if result.get("success"):
            assessment = result.get("assessment", {})
            summary = assessment.get("summary", {})
            logger.info(f"✅ Comprehensive assessment created - {summary.get('workflow_count', 0)} workflows, ~{summary.get('total_estimated_time', 0)}s")
        else:
            logger.error(f"❌ Failed to create comprehensive assessment for {domain}")

        return result

    @mcp.tool()
    def bugbounty_authentication_bypass_testing(target_url: str, auth_type: str = "form") -> Dict[str, Any]:
        """
        Create authentication bypass testing workflow for bug bounty hunting.

        Args:
            target_url: Target URL with authentication
            auth_type: Type of authentication (form, jwt, oauth, saml)

        Returns:
            Authentication bypass testing strategies and techniques
        """
        bypass_techniques = {
            "form": [
                {"technique": "SQL Injection", "payloads": ["admin'--", "' OR '1'='1'--"]},
                {"technique": "Default Credentials", "payloads": ["admin:admin", "admin:password"]},
                {"technique": "Password Reset", "description": "Test password reset token reuse and manipulation"},
                {"technique": "Session Fixation", "description": "Test session ID prediction and fixation"}
            ],
            "jwt": [
                {"technique": "Algorithm Confusion", "description": "Change RS256 to HS256"},
                {"technique": "None Algorithm", "description": "Set algorithm to 'none'"},
                {"technique": "Key Confusion", "description": "Use public key as HMAC secret"},
                {"technique": "Token Manipulation", "description": "Modify claims and resign token"}
            ],
            "oauth": [
                {"technique": "Redirect URI Manipulation", "description": "Test open redirect in redirect_uri"},
                {"technique": "State Parameter", "description": "Test CSRF via missing/weak state parameter"},
                {"technique": "Code Reuse", "description": "Test authorization code reuse"},
                {"technique": "Client Secret", "description": "Test for exposed client secrets"}
            ],
            "saml": [
                {"technique": "XML Signature Wrapping", "description": "Manipulate SAML assertions"},
                {"technique": "XML External Entity", "description": "Test XXE in SAML requests"},
                {"technique": "Replay Attacks", "description": "Test assertion replay"},
                {"technique": "Signature Bypass", "description": "Test signature validation bypass"}
            ]
        }

        workflow = {
            "target": target_url,
            "auth_type": auth_type,
            "bypass_techniques": bypass_techniques.get(auth_type, []),
            "testing_phases": [
                {"phase": "reconnaissance", "description": "Identify authentication mechanisms"},
                {"phase": "baseline_testing", "description": "Test normal authentication flow"},
                {"phase": "bypass_testing", "description": "Apply bypass techniques"},
                {"phase": "privilege_escalation", "description": "Test for privilege escalation"}
            ],
            "estimated_time": 240,
            "manual_testing_required": True
        }

        logger.info(f"🎯 Created authentication bypass testing workflow for {target_url}")

        return {
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        }

    # ============================================================================
    # ENHANCED HTTP TESTING FRAMEWORK & BROWSER AGENT (BURP SUITE ALTERNATIVE)
    # ============================================================================

    @mcp.tool()
    def http_framework_test(url: str, method: str = "GET", data: dict = {},
                           headers: dict = {}, cookies: dict = {}, action: str = "request") -> Dict[str, Any]:
        """
        Enhanced HTTP testing framework (Burp Suite alternative) for comprehensive web security testing.

        Args:
            url: Target URL to test
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            data: Request data/parameters
            headers: Custom headers
            cookies: Custom cookies
            action: Action to perform (request, spider, proxy_history, set_rules, set_scope, repeater, intruder)

        Returns:
            HTTP testing results with vulnerability analysis
        """
        data_payload = {
            "url": url,
            "method": method,
            "data": data,
            "headers": headers,
            "cookies": cookies,
            "action": action
        }

        logger.info(f"{HexStrikeColors.FIRE_RED}🔥 Starting HTTP Framework {action}: {url}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/tools/http-framework", data_payload)

        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ HTTP Framework {action} completed for {url}{HexStrikeColors.RESET}")

            # Enhanced logging for vulnerabilities found
            if result.get("result", {}).get("vulnerabilities"):
                vuln_count = len(result["result"]["vulnerabilities"])
                logger.info(f"{HexStrikeColors.HIGHLIGHT_RED} Found {vuln_count} potential vulnerabilities {HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ HTTP Framework {action} failed for {url}{HexStrikeColors.RESET}")

        return result

    @mcp.tool()
    def browser_agent_inspect(url: str, headless: bool = True, wait_time: int = 5,
                             action: str = "navigate", proxy_port: Optional[int] = None, active_tests: bool = False) -> Dict[str, Any]:
        """
        AI-powered browser agent for comprehensive web application inspection and security analysis.

        Args:
            url: Target URL to inspect
            headless: Run browser in headless mode
            wait_time: Time to wait after page load
            action: Action to perform (navigate, screenshot, close, status)
            proxy_port: Optional proxy port for request interception
            active_tests: Run lightweight active reflected XSS tests (safe GET-only)

        Returns:
            Browser inspection results with security analysis
        """
        data_payload = {
            "url": url,
            "headless": headless,
            "wait_time": wait_time,
            "action": action,
            "proxy_port": proxy_port,
            "active_tests": active_tests
        }

        logger.info(f"{HexStrikeColors.CRIMSON}🌐 Starting Browser Agent {action}: {url}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/tools/browser-agent", data_payload)

        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Browser Agent {action} completed for {url}{HexStrikeColors.RESET}")

            # Enhanced logging for security analysis
            if action == "navigate" and result.get("result", {}).get("security_analysis"):
                security_analysis = result["result"]["security_analysis"]
                issues_count = security_analysis.get("total_issues", 0)
                security_score = security_analysis.get("security_score", 0)

                if issues_count > 0:
                    logger.warning(f"{HexStrikeColors.HIGHLIGHT_YELLOW} Security Issues: {issues_count} | Score: {security_score}/100 {HexStrikeColors.RESET}")
                else:
                    logger.info(f"{HexStrikeColors.HIGHLIGHT_GREEN} No security issues found | Score: {security_score}/100 {HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Browser Agent {action} failed for {url}{HexStrikeColors.RESET}")

        return result

    # ---------------- Additional HTTP Framework Tools (sync with server) ----------------
    @mcp.tool()
    def http_set_rules(rules: list) -> Dict[str, Any]:
        """Set match/replace rules used to rewrite parts of URL/query/headers/body before sending.
        Rule format: {'where':'url|query|headers|body','pattern':'regex','replacement':'string'}"""
        payload = {"action": "set_rules", "rules": rules}
        return hexstrike_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_set_scope(host: str, include_subdomains: bool = True) -> Dict[str, Any]:
        """Define in-scope host (and optionally subdomains) so out-of-scope requests are skipped."""
        payload = {"action": "set_scope", "host": host, "include_subdomains": include_subdomains}
        return hexstrike_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_repeater(request_spec: dict) -> Dict[str, Any]:
        """Send a crafted request (Burp Repeater equivalent). request_spec keys: url, method, headers, cookies, data."""
        payload = {"action": "repeater", "request": request_spec}
        return hexstrike_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_intruder(url: str, method: str = "GET", location: str = "query", params: Optional[list] = None,
                      payloads: Optional[list] = None, base_data: Optional[dict] = None, max_requests: int = 100) -> Dict[str, Any]:
        """Simple Intruder (sniper) fuzzing. Iterates payloads over each param individually.
        location: query|body|headers|cookie."""
        payload = {
            "action": "intruder",
            "url": url,
            "method": method,
            "location": location,
            "params": params or [],
            "payloads": payloads or [],
            "base_data": base_data or {},
            "max_requests": max_requests
        }
        return hexstrike_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def burpsuite_alternative_scan(target: str, scan_type: str = "comprehensive",
                                  headless: bool = True, max_depth: int = 3,
                                  max_pages: int = 50) -> Dict[str, Any]:
        """
        Comprehensive Burp Suite alternative combining HTTP framework and browser agent for complete web security testing.

        Args:
            target: Target URL or domain to scan
            scan_type: Type of scan (comprehensive, spider, passive, active)
            headless: Run browser in headless mode
            max_depth: Maximum crawling depth
            max_pages: Maximum pages to analyze

        Returns:
            Comprehensive security assessment results
        """
        data_payload = {
            "target": target,
            "scan_type": scan_type,
            "headless": headless,
            "max_depth": max_depth,
            "max_pages": max_pages
        }

        logger.info(f"{HexStrikeColors.BLOOD_RED}🔥 Starting Burp Suite Alternative {scan_type} scan: {target}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/tools/burpsuite-alternative", data_payload)

        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Burp Suite Alternative scan completed for {target}{HexStrikeColors.RESET}")

            # Enhanced logging for comprehensive results
            if result.get("result", {}).get("summary"):
                summary = result["result"]["summary"]
                total_vulns = summary.get("total_vulnerabilities", 0)
                pages_analyzed = summary.get("pages_analyzed", 0)
                security_score = summary.get("security_score", 0)

                logger.info(f"{HexStrikeColors.HIGHLIGHT_BLUE} SCAN SUMMARY {HexStrikeColors.RESET}")
                logger.info(f"  📊 Pages Analyzed: {pages_analyzed}")
                logger.info(f"  🚨 Vulnerabilities: {total_vulns}")
                logger.info(f"  🛡️  Security Score: {security_score}/100")

                # Log vulnerability breakdown
                vuln_breakdown = summary.get("vulnerability_breakdown", {})
                for severity, count in vuln_breakdown.items():
                    if count > 0:
                        color = {
                                    'critical': HexStrikeColors.CRITICAL,
        'high': HexStrikeColors.FIRE_RED,
        'medium': HexStrikeColors.CYBER_ORANGE,
        'low': HexStrikeColors.YELLOW,
        'info': HexStrikeColors.INFO
    }.get(severity.lower(), HexStrikeColors.WHITE)

                        logger.info(f"  {color}{severity.upper()}: {count}{HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Burp Suite Alternative scan failed for {target}{HexStrikeColors.RESET}")

        return result

    @mcp.tool()
    def error_handling_statistics() -> Dict[str, Any]:
        """
        Get intelligent error handling system statistics and recent error patterns.

        Returns:
            Error handling statistics and patterns
        """
        logger.info(f"{HexStrikeColors.ELECTRIC_PURPLE}📊 Retrieving error handling statistics{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_get("api/error-handling/statistics")

        if result.get("success"):
            stats = result.get("statistics", {})
            total_errors = stats.get("total_errors", 0)
            recent_errors = stats.get("recent_errors_count", 0)

            logger.info(f"{HexStrikeColors.SUCCESS}✅ Error statistics retrieved{HexStrikeColors.RESET}")
            logger.info(f"  📈 Total Errors: {total_errors}")
            logger.info(f"  🕒 Recent Errors: {recent_errors}")

            # Log error breakdown by type
            error_counts = stats.get("error_counts_by_type", {})
            if error_counts:
                logger.info(f"{HexStrikeColors.HIGHLIGHT_BLUE} ERROR BREAKDOWN {HexStrikeColors.RESET}")
                for error_type, count in error_counts.items():
                                          logger.info(f"  {HexStrikeColors.FIRE_RED}{error_type}: {count}{HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Failed to retrieve error statistics{HexStrikeColors.RESET}")

        return result

    @mcp.tool()
    def test_error_recovery(tool_name: str, error_type: str = "timeout",
                           target: str = "example.com") -> Dict[str, Any]:
        """
        Test the intelligent error recovery system with simulated failures.

        Args:
            tool_name: Name of tool to simulate error for
            error_type: Type of error to simulate (timeout, permission_denied, network_unreachable, etc.)
            target: Target for the simulated test

        Returns:
            Recovery strategy and system response
        """
        data_payload = {
            "tool_name": tool_name,
            "error_type": error_type,
            "target": target
        }

        logger.info(f"{HexStrikeColors.RUBY}🧪 Testing error recovery for {tool_name} with {error_type}{HexStrikeColors.RESET}")
        result = hexstrike_client.safe_post("api/error-handling/test-recovery", data_payload)

        if result.get("success"):
            recovery_strategy = result.get("recovery_strategy", {})
            action = recovery_strategy.get("action", "unknown")
            success_prob = recovery_strategy.get("success_probability", 0)

            logger.info(f"{HexStrikeColors.SUCCESS}✅ Error recovery test completed{HexStrikeColors.RESET}")
            logger.info(f"  🔧 Recovery Action: {action}")
            logger.info(f"  📊 Success Probability: {success_prob:.2%}")

            # Log alternative tools if available
            alternatives = result.get("alternative_tools", [])
            if alternatives:
                logger.info(f"  🔄 Alternative Tools: {', '.join(alternatives)}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Error recovery test failed{HexStrikeColors.RESET}")

        return result

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
