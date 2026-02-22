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

import core.config_core as config_core
from mcp.server.fastmcp import FastMCP
from mcp_core.hexstrikecolors import HexStrikeColors

from mcp_tools.gateway import register_gateway_tools
from mcp_tools.ops.wordlist import register_wordlist_tools
from mcp_tools.ops.file_ops_and_payload_gen import register_file_ops_and_payload_gen_tools
from mcp_tools.ops.python_env import register_python_env_tools
from mcp_tools.binary_analysis.enhanced_binary_analysis_and_exploitation import register_enhanced_binary_analysis_and_exploitation_tools

from mcp_tools.ai_agents.ai_payload_generation import register_ai_payload_generation_tools
from mcp_tools.web_app_security.api_testing import register_api_testing_tools
from mcp_tools.ctf_forensics.advanced_ctf_tools import register_advanced_ctf_tools
from mcp_tools.bug_bounty_osint.bug_bounty_recon import register_bug_bounty_recon_tools
from mcp_tools.ops.system_monitoring import register_system_monitoring_tools
from mcp_tools.ops.process_management import register_process_management_tools
from mcp_tools.ops.vulnerability_intelligence import register_vulnerability_intelligence_tools
from mcp_tools.ops.visual_output_tools import register_visual_output_tools
from mcp_tools.ai_agents.intelligent_decision_engine import register_intelligent_decision_engine_tools

from mcp_tools.web_fuzz.dirb import register_dirb_tool
from mcp_tools.web_fuzz.ffuf import register_ffuf_tool
from mcp_tools.web_fuzz.dirsearch import register_dirsearch_tools
from mcp_tools.web_fuzz.gobuster import register_gobuster

from mcp_tools.web_crawl.katana import register_katana_tool

from mcp_tools.web_scan.nikto import register_nikto_tool
from mcp_tools.web_scan.sqlmap import register_sqlmap_tool
from mcp_tools.web_scan.wpscan import register_wpscan_tool
from mcp_tools.web_scan.jaeles import register_jaeles_tool
from mcp_tools.web_scan.dalfox import register_dalfox_tool
from mcp_tools.web_scan.burpsuite import register_burpsuite_tool
from mcp_tools.web_scan.zap import register_zap_tool

from mcp_tools.exploit_framework.metasploit import register_metasploit_tool
from mcp_tools.exploit_framework.msfvenom import register_msfvenom

from mcp_tools.password_cracking.hydra import register_hydra_tool
from mcp_tools.password_cracking.john import register_john_tool
from mcp_tools.password_cracking.hashcat import register_hashcat_tool

from mcp_tools.smb_enum.enum4linux import register_enum4linux_tool
from mcp_tools.smb_enum.netexec import register_netexec_tool
from mcp_tools.smb_enum.smbmap import register_smbmap_tool
from mcp_tools.smb_enum.nbtscan import register_nbtscan_tool
from mcp_tools.smb_enum.rpcclient import register_rpcclient_tool

from mcp_tools.recon.amass import register_amass_tool
from mcp_tools.recon.subfinder import register_subfinder_tool
from mcp_tools.recon.autorecon import register_autorecon_tool

from mcp_tools.url_recon.gau import register_gau_tool
from mcp_tools.url_recon.waybackurls import register_waybackurls_tool

from mcp_tools.param_discovery.arjun import register_arjun_tool
from mcp_tools.param_discovery.paramspider import register_paramspider_tool
from mcp_tools.param_discovery.x8 import register_x8_tool

from mcp_tools.web_probe.httpx import register_httpx_tool

from mcp_tools.data_processing.anew import register_anew_tool

from mcp_tools.param_fuzz.qsreplace import register_qsreplace_tool

from mcp_tools.url_filter.uro import register_uro_tool

from mcp_tools.web_framework.http_framework import register_http_framework_tool
from mcp_tools.web_framework.browser_agent import register_browser_agent_tool

from mcp_tools.waf_detect.wafw00f import register_wafw00f_tool

from mcp_tools.dns_enum.fierce import register_fierce_tool
from mcp_tools.dns_enum.dnsenum import register_dnsenum_tool

from mcp_tools.error_handling.error_handling_statistics import register_error_handling_statistics_tool
from mcp_tools.error_handling.test_error_recovery import register_test_error_recovery_tool

from mcp_tools.cloud_audit.prowler import register_prowler_tool
from mcp_tools.cloud_audit.scout_suite import register_scout_suite_tool

from mcp_tools.cloud_visual.cloudmapper import register_cloudmapper_tool

from mcp_tools.cloud_exploit.pacu import register_pacu_tool

from mcp_tools.k8s_scan.kube_hunter import register_kube_hunter_tool
from mcp_tools.k8s_scan.kube_bench import register_kube_bench_tool

from mcp_tools.container_scan.trivy import register_trivy_tool
from mcp_tools.container_scan.docker_bench import register_docker_bench_tool
from mcp_tools.container_scan.clair_vulnerability import register_clair_vulnerability_tool

from mcp_tools.runtime_monitor.falco import register_falco_runtime_monitoring_tool

from mcp_tools.iac_scan.checkov import register_checkov_tool
from mcp_tools.iac_scan.terrascan import register_terrascan_tool

from mcp_tools.recon_bot.bbot import register_bbot_tools

from mcp_tools.db_query.mysql import register_mysql_tools
from mcp_tools.db_query.sqlite import register_sqlite_tools
from mcp_tools.db_query.postgresql import register_postgresql_tools

from mcp_tools.net_scan.nmap import register_nmap
from mcp_tools.net_scan.arp_scan import register_arp_scan_tool
from mcp_tools.net_scan.masscan import register_masscan_tool
from mcp_tools.net_scan.rustscan import register_rustscan_tool

from mcp_tools.net_lookup.whois import register_whois

from mcp_tools.vuln_scan.nuclei import register_nuclei

from mcp_tools.memory_forensics.volatility import register_volatility_tool

from mcp_tools.credential_harvest.responder import register_responder_tool

from mcp_tools.binary_debug.gdb import register_gdb_tools
from mcp_tools.binary_debug.radare2 import register_radare2_tools

from mcp_tools.binary_analysis.binwalk import register_binwalk_tool
from mcp_tools.binary_analysis.checksec import register_checksec_tool
from mcp_tools.binary_analysis.xxd import register_xxd_tool
from mcp_tools.binary_analysis.strings import register_strings_tool
from mcp_tools.binary_analysis.objdump import register_objdump_tool

from mcp_tools.gadget_search.ropgadget import register_ropgadget_tool

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

TOOL_CATEGORIES = {

    # All Profiles
    ## `compact` (essential gateway tools only)
    ## `full` (all tools registered)
   

    #Compact mode 
    #Only essential tools for task classification and tool execution, without all the individual tool functions. Allows smaller LLM clients to use the MCP server without running into token limits due to too many registered tools.
    "compact": [
        lambda mcp, client, logger: register_gateway_tools(mcp, client),
    ],

    #Tools for binary debugging
    "binary_debug": [
        lambda mcp, client, logger: register_gdb_tools(mcp, client, logger),
        lambda mcp, client, logger: register_radare2_tools(mcp, client, logger),
    ],

    #Tools for ROP gadget searching and analysis (e.g., ROPgadget).
    "gadget_search": [
        lambda mcp, client, logger: register_ropgadget_tool(mcp, client, logger),
    ],

    #Tools for binary analysis (e.g., Binwalk, Checksec, xxd, Strings, Objdump).
    "binary_analysis": [
        lambda mcp, client, logger: register_binwalk_tool(mcp, client, logger),
        lambda mcp, client, logger: register_checksec_tool(mcp, client, logger),
        lambda mcp, client, logger: register_xxd_tool(mcp, client, logger),
        lambda mcp, client, logger: register_strings_tool(mcp, client, logger),
        lambda mcp, client, logger: register_objdump_tool(mcp, client, logger),
    ],

    #Tools for credential harvesting and network poisoning (e.g., Responder).
    "credential_harvest": [
        lambda mcp, client, logger: register_responder_tool(mcp, client, logger),
    ],

    #Tools for memory forensics analysis (e.g., Volatility).
    "memory_forensics": [
        lambda mcp, client, logger: register_volatility_tool(mcp, client, logger),
    ],

    #Tools for brute-forcing and cracking password hashes (e.g., Hydra, John, Hashcat).
    "password_cracking": [
        lambda mcp, client, logger: register_hydra_tool(mcp, client, logger),
        lambda mcp, client, logger: register_john_tool(mcp, client, logger),
        lambda mcp, client, logger: register_hashcat_tool(mcp, client, logger),
    ],

    #Tools for SMB and network share enumeration (e.g., Enum4linux, NetExec, SMBMap, NBTSCan, RPCClient).
    "smb_enum": [
        lambda mcp, client, logger: register_enum4linux_tool(mcp, client, logger),
        lambda mcp, client, logger: register_netexec_tool(mcp, client, logger),
        lambda mcp, client, logger: register_smbmap_tool(mcp, client, logger),
        lambda mcp, client, logger: register_nbtscan_tool(mcp, client, logger),
        lambda mcp, client, logger: register_rpcclient_tool(mcp, client, logger),
    ],

    #Tools for reconnaissance and subdomain discovery (e.g., Amass, Subfinder, AutoRecon).
    "recon": [
        lambda mcp, client, logger: register_amass_tool(mcp, client, logger),
        lambda mcp, client, logger: register_subfinder_tool(mcp, client, logger),
        lambda mcp, client, logger: register_autorecon_tool(mcp, client, logger),
    ],

    #Tools for network scanning and enumeration (e.g., Nmap, ARP-Scan, Masscan, Rustscan).
    "net_scan": [
        lambda mcp, client, logger: register_nmap(mcp, client, logger, HexStrikeColors),
        lambda mcp, client, logger: register_arp_scan_tool(mcp, client, logger),
        lambda mcp, client, logger: register_masscan_tool(mcp, client, logger),
        lambda mcp, client, logger: register_rustscan_tool(mcp, client, logger),
    ],

    #Tools for network information gathering and lookups (e.g., WHOIS).
    "net_lookup": [
        lambda mcp, client, logger: register_whois(mcp, client, logger),
    ],

    #Tools for reconnaissance and enumeration (e.g., BBot).
    "recon_bot": [
        lambda mcp, client, logger: register_bbot_tools(mcp, client),
    ],

    #Tools for web content discovery and fuzzing (e.g., Dirb, FFuf, Dirsearch, Gobuster).
    "web_fuzz": [
        lambda mcp, client, logger: register_dirb_tool(mcp, client, logger),
        lambda mcp, client, logger: register_ffuf_tool(mcp, client, logger),
        lambda mcp, client, logger: register_dirsearch_tools(mcp, client, logger),
        lambda mcp, client, logger: register_gobuster(mcp, client, logger, HexStrikeColors),
    ],

    #Tools for web crawling and spidering (e.g., Katana).
    "web_crawl": [
        lambda mcp, client, logger: register_katana_tool(mcp, client, logger),
    ],

    #Tools for web vulnerability scanning and assessment (e.g., Nikto, WPScan, SQLMap, Jaeles, Dalfox, ZAP, Burp Suite).
    "web_scan": [
        lambda mcp, client, logger: register_nikto_tool(mcp, client, logger),
        lambda mcp, client, logger: register_sqlmap_tool(mcp, client, logger),
        lambda mcp, client, logger: register_wpscan_tool(mcp, client, logger),
        lambda mcp, client, logger: register_jaeles_tool(mcp, client, logger),
        lambda mcp, client, logger: register_dalfox_tool(mcp, client, logger),
        lambda mcp, client, logger: register_burpsuite_tool(mcp, client, logger, HexStrikeColors),
        lambda mcp, client, logger: register_zap_tool(mcp, client, logger),
    ],

    #Tools for web probing and technology detection (e.g., httpx).
    "web_probe": [
        lambda mcp, client, logger: register_httpx_tool(mcp, client, logger),
    ],

    #Tools for vulnerability scanning and assessment (e.g., Nuclei).
    "vuln_scan": [
        lambda mcp, client, logger: register_nuclei(mcp, client, logger, HexStrikeColors),
    ],

    #Tools for automated exploitation and attack frameworks (e.g., Metasploit, MSFVenom).
    "exploit_framework": [
        lambda mcp, client, logger: register_metasploit_tool(mcp, client, logger),
        lambda mcp, client, logger: register_msfvenom(mcp, client, logger),
    ],

    #Tools for URL discovery and reconnaissance (e.g., Gau, Waybackurls).
    "url_recon": [
        lambda mcp, client, logger: register_gau_tool(mcp, client, logger),
        lambda mcp, client, logger: register_waybackurls_tool(mcp, client, logger),
    ],

    #Tools for parameter discovery and fuzzing (e.g., Arju0n, ParamSpider, x8).
    "param_discovery": [
        lambda mcp, client, logger: register_arjun_tool(mcp, client, logger),
        lambda mcp, client, logger: register_paramspider_tool(mcp, client, logger),
        lambda mcp, client, logger: register_x8_tool(mcp, client, logger),
    ],

    #Tools for query string parameter replacement (e.g., qsreplace).
    "param_fuzz": [
        lambda mcp, client, logger: register_qsreplace_tool(mcp, client, logger),
    ],

    #Tools for data processing and unique line filtering (e.g., anew).
    "data_processing": [
        lambda mcp, client, logger: register_anew_tool(mcp, client, logger),
    ],

    #Tools for URL filtering and duplicate removal (e.g., uro).
    "url_filter": [
        lambda mcp, client, logger: register_uro_tool(mcp, client, logger),
    ],

    #Tools for web application security testing frameworks (e.g., HTTP Framework, Browser Agent).
    "web_framework": [
        lambda mcp, client, logger: register_http_framework_tool(mcp, client, logger, HexStrikeColors),
        lambda mcp, client, logger: register_browser_agent_tool(mcp, client, logger, HexStrikeColors),
    ],

    #Tools for WAF detection and fingerprinting (e.g., wafw00f).
    "waf_detect": [
        lambda mcp, client, logger: register_wafw00f_tool(mcp, client, logger),    
    ],

    #Tools for DNS enumeration and subdomain takeover detection (e.g., Fierce, DNSenum).
    "dns_enum": [
        lambda mcp, client, logger: register_fierce_tool(mcp, client, logger),
        lambda mcp, client, logger: register_dnsenum_tool(mcp, client, logger),
    ],
    
    #Tools for error handling and statistics collection to improve reliability and debugging.
    "error_handling": [
        lambda mcp, client, logger: register_error_handling_statistics_tool(mcp, client, logger, HexStrikeColors),
        lambda mcp, client, logger: register_test_error_recovery_tool(mcp, client, logger, HexStrikeColors),
    ],

    #Tools for cloud assessment and auditing (e.g., Prowler, Scout Suite).
    "cloud_audit": [
        lambda mcp, client, logger: register_prowler_tool(mcp, client, logger),
        lambda mcp, client, logger: register_scout_suite_tool(mcp, client, logger),
    ],

    #Tools for cloud infrastructure visualization and mapping (e.g., CloudMapper).
    "cloud_visual": [
        lambda mcp, client, logger: register_cloudmapper_tool(mcp, client, logger),
    ],

    #Tools for cloud exploitation and attack simulation (e.g., Pacu).
    "cloud_exploit": [
        lambda mcp, client, logger: register_pacu_tool(mcp, client, logger),
    ],

    #Tools for Kubernetes scanning and penetration testing (e.g., kube-hunter, kube-bench).
    "k8s_scan": [
        lambda mcp, client, logger: register_kube_hunter_tool(mcp, client, logger),
        lambda mcp, client, logger: register_kube_bench_tool(mcp, client, logger),
    ],

    #Tools for infrastructure as code security scanning (e.g., Checkov, Terrascan).
    "iac_scan": [
        lambda mcp, client, logger: register_checkov_tool(mcp, client, logger),
        lambda mcp, client, logger: register_terrascan_tool(mcp, client, logger),
    ],

    #Tools for container scanning and vulnerability assessment (e.g., Trivy, Docker Bench, Clair).
    "container_scan": [
        lambda mcp, client, logger: register_trivy_tool(mcp, client, logger),
        lambda mcp, client, logger: register_docker_bench_tool(mcp, client, logger),
        lambda mcp, client, logger: register_clair_vulnerability_tool(mcp, client, logger),
    ],

    #Tools for runtime monitoring and anomaly detection (e.g., Falco).
    "runtime_monitor": [
        lambda mcp, client, logger: register_falco_runtime_monitoring_tool(mcp, client, logger),
    ],

    #Tools for database querying and interaction (e.g., SQLite, MySQL, PostgreSQL).
    "db_query": [
        lambda mcp, client, logger: register_mysql_tools(mcp, client, logger),
        lambda mcp, client, logger: register_sqlite_tools(mcp, client, logger),
        lambda mcp, client, logger: register_postgresql_tools(mcp, client, logger),
    ],

    #Tools for Python environment interaction and code execution
    "python_env": [
        lambda mcp, client, logger: register_python_env_tools(mcp, client, logger),
    ],

    #Tools for file operations and AI-powered payload generation
    "file_payload": [
        lambda mcp, client, logger: register_file_ops_and_payload_gen_tools(mcp, client, logger),
    ],

    #Tools for wordlist management
    "wordlist": [
        lambda mcp, client, logger: register_wordlist_tools(mcp, client),
    ],

    #Tools for system monitoring
    "monitoring": [
        lambda mcp, client, logger: register_system_monitoring_tools(mcp, client, logger),
    ],

    #Tools for process management
    "process_management": [
        lambda mcp, client, logger: register_process_management_tools(mcp, client, logger),
    ],

    # ----------

    "binary": [
        lambda mcp, client, logger: register_enhanced_binary_analysis_and_exploitation_tools(mcp, client, logger),
    ],
    "web_app": [
        lambda mcp, client, logger: register_ai_payload_generation_tools(mcp, client, logger),
        lambda mcp, client, logger: register_api_testing_tools(mcp, client, logger),
        lambda mcp, client, logger: register_bug_bounty_recon_tools(mcp, client, logger),
    ],
    "ctf": [
        lambda mcp, client, logger: register_advanced_ctf_tools(mcp, client, logger),
    ],

    "vuln_intel": [
        lambda mcp, client, logger: register_vulnerability_intelligence_tools(mcp, client, logger),
    ],
    "visual": [
        lambda mcp, client, logger: register_visual_output_tools(mcp, client, logger),
    ],
    "ai_agents": [
        lambda mcp, client, logger: register_intelligent_decision_engine_tools(mcp, client, logger, HexStrikeColors),
    ],
}

# Define default and full profiles for easy loading of tool categories
DEFAULT_PROFILE = [
    "credential_harvest",
    "memory_forensics",
    "net_scan",
    "net_lookup",
    "dns_enum",
    "smb_enum",
    "recon",
    "web_probe",
    "web_crawl",
    "web_fuzz",
    "web_scan",
    "vuln_scan",
    "exploit_framework",
    "password_cracking",
    "param_discovery",
    "url_recon",
    "data_processing",
    "error_handling",
    "monitoring",
    "process_management"
]
FULL_PROFILE = list(TOOL_CATEGORIES.keys())

def setup_mcp_server(hexstrike_client: HexStrikeClient, compact: bool = False, profiles: Optional[list] = None) -> FastMCP:
    """
    Set up the MCP server with all enhanced tool functions

    Args:
        hexstrike_client: Initialized HexStrikeClient
        compact: If True, register only classify_task and run_tool gateway tools
        profile: Optional list of tool profiles to load (e.g., ["core_network", "web_app"])

    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("hexstrike-ai-mcp")


    if compact:
        # Register gateway tools for task classification and tool execution
        register_gateway_tools(mcp, hexstrike_client)

        logger.info("Compact mode: only gateway tools registered (classify_task, run_tool)")
        return mcp

    # Determine which profiles to load
    if profiles:
        if "default" in profiles:
            selected_profiles = DEFAULT_PROFILE
        elif "full" in profiles:
            selected_profiles = FULL_PROFILE
        else:
            selected_profiles = profiles
    else:
        selected_profiles = DEFAULT_PROFILE

    # Register tools for each selected profile
    for profile in selected_profiles:
        for reg_func in TOOL_CATEGORIES.get(profile, []):
            reg_func(mcp, hexstrike_client, logger)    

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
    parser.add_argument("--profile", nargs="+", type=str, default=[], help="Tool profile(s) to load (e.g., web_crawl, exploit_framework, recon or default/full)")
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
        mcp = setup_mcp_server(hexstrike_client, compact=args.compact, profiles=args.profile)
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
