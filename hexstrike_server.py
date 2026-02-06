#!/usr/bin/env python3
"""

HexStrike AI Community Edition - Advanced Penetration Testing Framework Server

"""

import argparse
import hmac

# Fix Windows console encoding for emoji/unicode support
import io
import logging
import os
import sys
import threading

from flask import Flask, abort, request

# ============================================================================
# LOGGING CONFIGURATION (MUST BE FIRST)
# ============================================================================


if sys.platform == "win32":
    # Wrap stdout/stderr with UTF-8 encoding to prevent cp1252 errors
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Configure logging with fallback for permission issues
try:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("hexstrike.log", encoding="utf-8")],
    )
except PermissionError:
    # Fallback to console-only logging if file creation fails
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# API Configuration
API_PORT = int(os.environ.get("HEXSTRIKE_PORT", 8888))
API_HOST = os.environ.get(
    "HEXSTRIKE_HOST", "127.0.0.1"
)  # Fix: default to localhost (Issue #122 by @bcoles, PR #137 by @jrespeto)
API_TOKEN = os.environ.get("HEXSTRIKE_API_TOKEN", None)  # Optional Bearer token auth (PR #137 by @jrespeto)


# Bearer token authentication middleware (PR #137 by @jrespeto)
@app.before_request
def optional_bearer_auth():
    """Optional Bearer token authentication for API requests.

    If HEXSTRIKE_API_TOKEN env var is set, all requests must include
    a matching 'Authorization: Bearer <token>' header.
    If not set, all requests are allowed (default for local usage).
    """
    if not API_TOKEN:
        return

    auth_header = request.headers.get("Authorization", "")
    prefix = "Bearer "

    if not auth_header.startswith(prefix):
        abort(401, description="Missing or invalid Authorization header. Expected: Bearer <token>")

    token = auth_header.removeprefix(prefix)
    if not hmac.compare_digest(token, API_TOKEN):
        abort(401, description="Unauthorized: invalid API token")


from agents.ai_payload_generator import ai_payload_generator
from agents.browser_agent import BrowserAgent
from agents.bugbounty import BugBountyTarget, BugBountyWorkflowManager
from agents.ctf import CTFToolManager, CTFWorkflowManager
from agents.ctf.automator import CTFChallengeAutomator
from agents.ctf.coordinator import CTFTeamCoordinator
from agents.cve import CVEIntelligenceManager
from agents.cve.correlator import VulnerabilityCorrelator
from agents.cve.exploit_ai import AIExploitGenerator
from agents.decision_engine import IntelligentDecisionEngine
from core.cache import HexStrikeCache
from core.degradation import GracefulDegradation
from core.enhanced_process import EnhancedProcessManager
from core.error_handler import IntelligentErrorHandler
from core.execution import execute_command, execute_command_with_recovery
from core.file_manager import FileOperationsManager
from core.http_testing_framework import HTTPTestingFramework
from core.logging_formatter import ColoredFormatter
from core.process_manager import ProcessManager
from core.python_env_manager import PythonEnvironmentManager
from core.telemetry import TelemetryCollector
from core.tool_factory import create_tool_executor
from core.visual import ModernVisualEngine
from tools.api import *
from tools.binary import *
from tools.cloud import *
from tools.exploit import *
from tools.forensics import *
from tools.network import *
from tools.recon import *
from tools.security import *
from tools.web import *

# Global decision engine instance
decision_engine = IntelligentDecisionEngine()

# Global error handler and degradation manager instances
error_handler = IntelligentErrorHandler()
degradation_manager = GracefulDegradation()

from core.optimizer import (
    FailureRecoverySystem,
    ParameterOptimizer,
    PerformanceMonitor,
    RateLimitDetector,
    TechnologyDetector,
)

# Global instances
tech_detector = TechnologyDetector()
rate_limiter = RateLimitDetector()
failure_recovery = FailureRecoverySystem()
performance_monitor = PerformanceMonitor()
parameter_optimizer = ParameterOptimizer()
enhanced_process_manager = EnhancedProcessManager()

# Global CTF framework instances
ctf_manager = CTFWorkflowManager()
ctf_tools = CTFToolManager()
ctf_automator = CTFChallengeAutomator()
ctf_coordinator = CTFTeamCoordinator()

# Global Bug Bounty framework instance
bugbounty_manager = BugBountyWorkflowManager()

# Global Web Testing Framework instances
http_testing_framework = HTTPTestingFramework()
browser_agent = BrowserAgent()

# Process management for command termination
active_processes = {}  # pid -> process info
process_lock = threading.Lock()

# Global environment manager
env_manager = PythonEnvironmentManager()


# Enhanced logging setup
def setup_logging():
    """Setup enhanced logging with colors and formatting"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        ColoredFormatter("[🔥 HexStrike AI] %(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(console_handler)

    return logger


# Configuration (using existing API_PORT from top of file)
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
CACHE_SIZE = 1000
CACHE_TTL = 3600  # 1 hour

# Global instances using imported classes
cache = HexStrikeCache()
telemetry = TelemetryCollector()

# Global intelligence managers
cve_intelligence = CVEIntelligenceManager()
exploit_generator = AIExploitGenerator()
vulnerability_correlator = VulnerabilityCorrelator()

# File Operations Manager
# Global file operations manager
file_manager = FileOperationsManager()

import api.routes.ai as ai_routes
import api.routes.bugbounty as bugbounty_routes
import api.routes.core as core_routes
import api.routes.ctf as ctf_routes
import api.routes.error_handling as error_handling_routes
import api.routes.files as files_routes
import api.routes.intelligence as intelligence_routes
import api.routes.process_workflows as process_workflows_routes
import api.routes.processes as processes_routes
import api.routes.python_env as python_env_routes
import api.routes.tools_api as tools_api_routes
import api.routes.tools_binary as tools_binary_routes
import api.routes.tools_cloud as tools_cloud_routes
import api.routes.tools_exploit as tools_exploit_routes
import api.routes.tools_forensics as tools_forensics_routes
import api.routes.tools_network as tools_network_routes
import api.routes.tools_parameters as tools_parameters_routes
import api.routes.tools_recon as tools_recon_routes
import api.routes.tools_web as tools_web_routes
import api.routes.tools_web_advanced as tools_web_advanced_routes
import api.routes.tools_web_frameworks as tools_web_frameworks_routes
import api.routes.vuln_intel as vuln_intel_routes
from api.routes.ai import ai_bp
from api.routes.bugbounty import bugbounty_bp
from api.routes.core import core_bp
from api.routes.ctf import ctf_bp
from api.routes.error_handling import error_handling_bp

# ============================================================================
# REGISTER API BLUEPRINTS
# ============================================================================
from api.routes.files import files_bp
from api.routes.intelligence import intelligence_bp
from api.routes.process_workflows import process_workflows_bp
from api.routes.processes import processes_bp
from api.routes.python_env import python_env_bp
from api.routes.tools_api import tools_api_bp
from api.routes.tools_binary import tools_binary_bp
from api.routes.tools_cloud import tools_cloud_bp
from api.routes.tools_exploit import tools_exploit_bp
from api.routes.tools_forensics import tools_forensics_bp
from api.routes.tools_network import tools_network_bp
from api.routes.tools_parameters import tools_parameters_bp
from api.routes.tools_recon import tools_recon_bp
from api.routes.tools_web import tools_web_bp
from api.routes.tools_web_advanced import tools_web_advanced_bp
from api.routes.tools_web_frameworks import tools_web_frameworks_bp
from api.routes.visual import visual_bp
from api.routes.vuln_intel import vuln_intel_bp

files_routes.init_app(file_manager)
error_handling_routes.init_app(error_handler, degradation_manager, execute_command_with_recovery)
processes_routes.init_app(ProcessManager)
bugbounty_routes.init_app(bugbounty_manager, None, BugBountyTarget)  # fileupload_framework=None (not implemented)
ctf_routes.init_app(ctf_manager, ctf_tools, ctf_automator, ctf_coordinator)
vuln_intel_routes.init_app(cve_intelligence, exploit_generator, vulnerability_correlator)
core_routes.init_app(execute_command, cache, telemetry, file_manager)
python_env_routes.init_app(env_manager, file_manager, execute_command)
process_workflows_routes.init_app(enhanced_process_manager)
tools_cloud_routes.init_app(execute_command)
tools_web_routes.init_app(execute_command)
tools_web_advanced_routes.init_app(execute_command)
tools_network_routes.init_app(execute_command, execute_command_with_recovery)
tools_exploit_routes.init_app(execute_command)
tools_binary_routes.init_app(execute_command)
tools_api_routes.init_app(execute_command)
tools_parameters_routes.init_app(execute_command)
tools_forensics_routes.init_app(execute_command)
tools_web_frameworks_routes.init_app(http_testing_framework, browser_agent)
tools_recon_routes.init_app(execute_command, execute_command_with_recovery)
ai_routes.init_app(ai_payload_generator, execute_command)
app.register_blueprint(files_bp)
app.register_blueprint(visual_bp)
app.register_blueprint(error_handling_bp)
app.register_blueprint(processes_bp)
app.register_blueprint(bugbounty_bp)
app.register_blueprint(ctf_bp)
app.register_blueprint(vuln_intel_bp)
app.register_blueprint(core_bp)
app.register_blueprint(ai_bp)
app.register_blueprint(python_env_bp)
app.register_blueprint(process_workflows_bp)
app.register_blueprint(tools_cloud_bp)
app.register_blueprint(tools_web_advanced_bp)
app.register_blueprint(tools_web_bp)
app.register_blueprint(tools_network_bp)
app.register_blueprint(tools_exploit_bp)
app.register_blueprint(tools_binary_bp)
app.register_blueprint(tools_api_bp)
app.register_blueprint(tools_parameters_bp)
app.register_blueprint(tools_forensics_bp)
app.register_blueprint(tools_web_frameworks_bp)
app.register_blueprint(tools_recon_bp)

# Create tool_executors dictionary for intelligence engine
# Each executor wraps a tool class and provides a simple (target, params) -> result interface

tool_executors = {
    # Network (16)
    "nmap": create_tool_executor(NmapTool),
    "httpx": create_tool_executor(HttpxTool),
    "masscan": create_tool_executor(MasscanTool),
    "dnsenum": create_tool_executor(DNSEnumTool),
    "fierce": create_tool_executor(FierceTool),
    "dnsx": create_tool_executor(DNSxTool),
    "rustscan": create_tool_executor(RustscanTool),
    "autorecon": create_tool_executor(AutoreconTool),
    "nbtscan": create_tool_executor(NbtscanTool),
    "arp_scan": create_tool_executor(ArpScanTool),
    "responder": create_tool_executor(ResponderTool),
    "netexec": create_tool_executor(NetexecTool),
    "enum4linux": create_tool_executor(Enum4linuxTool),
    "smbmap": create_tool_executor(SmbmapTool),
    "rpcclient": create_tool_executor(RpcclientTool),
    "enum4linux_ng": create_tool_executor(Enum4linuxNgTool),
    "nmap_advanced": create_tool_executor(NmapTool),  # nmap-advanced uses same tool, different params from optimizer
    # Web (22)
    "nuclei": create_tool_executor(NucleiTool),
    "gobuster": create_tool_executor(GobusterTool),
    "sqlmap": create_tool_executor(SQLMapTool),
    "nikto": create_tool_executor(NiktoTool),
    "feroxbuster": create_tool_executor(FeroxbusterTool),
    "ffuf": create_tool_executor(FfufTool),
    "katana": create_tool_executor(KatanaTool),
    "wpscan": create_tool_executor(WpscanTool),
    "arjun": create_tool_executor(ArjunTool),
    "dalfox": create_tool_executor(DalfoxTool),
    "whatweb": create_tool_executor(WhatwebTool),
    "dirsearch": create_tool_executor(DirsearchTool),
    "paramspider": create_tool_executor(ParamSpiderTool),
    "x8": create_tool_executor(X8Tool),
    "dirb": create_tool_executor(DirbTool),
    "dotdotpwn": create_tool_executor(DotdotpwnTool),
    "wfuzz": create_tool_executor(WfuzzTool),
    "xsser": create_tool_executor(XsserTool),
    "wafw00f": create_tool_executor(Wafw00fTool),
    "commix": create_tool_executor(CommixTool),
    "nosqlmap": create_tool_executor(NoSQLMapTool),
    "tplmap": create_tool_executor(TplmapTool),
    # Recon (15)
    "amass": create_tool_executor(AmassTool),
    "subfinder": create_tool_executor(SubfinderTool),
    "waybackurls": create_tool_executor(WaybackURLsTool),
    "gau": create_tool_executor(GAUTool),
    "hakrawler": create_tool_executor(HakrawlerTool),
    "anew": create_tool_executor(AnewTool),
    "qsreplace": create_tool_executor(QsreplaceTool),
    "uro": create_tool_executor(UroTool),
    "theharvester": create_tool_executor(TheHarvesterTool),
    "sherlock": create_tool_executor(SherlockTool),
    "spiderfoot": create_tool_executor(SpiderFootTool),
    "trufflehog": create_tool_executor(TruffleHogTool),
    "aquatone": create_tool_executor(AquatoneTool),
    "subjack": create_tool_executor(SubjackTool),
    "recon_ng": create_tool_executor(ReconNgTool),
    # Security (6)
    "testssl": create_tool_executor(TestSSLTool),
    "sslscan": create_tool_executor(SSLScanTool),
    "jaeles": create_tool_executor(JaelesTool),
    "zap": create_tool_executor(ZAPTool),
    "burpsuite": create_tool_executor(BurpSuiteTool),
    "sslyze": create_tool_executor(SSLyzeTool),
    # Exploit (11)
    "metasploit": create_tool_executor(MetasploitTool),
    "hydra": create_tool_executor(HydraTool),
    "john": create_tool_executor(JohnTool),
    "hashcat": create_tool_executor(HashcatTool),
    "hashpump": create_tool_executor(HashpumpTool),
    "msfvenom": create_tool_executor(MsfvenomTool),
    "medusa": create_tool_executor(MedusaTool),
    "patator": create_tool_executor(PatatorTool),
    "evil_winrm": create_tool_executor(EvilWinRMTool),
    "hash_identifier": create_tool_executor(HashIdentifierTool),
    "hashid": create_tool_executor(HashIDTool),
    # Forensics (10)
    "volatility": create_tool_executor(VolatilityTool),
    "volatility3": create_tool_executor(Volatility3Tool),
    "steghide": create_tool_executor(SteghideTool),
    "exiftool": create_tool_executor(ExiftoolTool),
    "foremost": create_tool_executor(ForemostTool),
    "zsteg": create_tool_executor(ZstegTool),
    "stegsolve": create_tool_executor(StegSolveTool),
    "scalpel": create_tool_executor(ScalpelTool),
    "bulk_extractor": create_tool_executor(BulkExtractorTool),
    "outguess": create_tool_executor(OutguessTool),
    # Binary (19)
    "ghidra": create_tool_executor(GhidraTool),
    "checksec": create_tool_executor(ChecksecTool),
    "binwalk": create_tool_executor(BinwalkTool),
    "gdb": create_tool_executor(GdbTool),
    "gdb_peda": create_tool_executor(GdbPedaTool),
    "gdb_gef": create_tool_executor(GDBGEFTool),
    "radare2": create_tool_executor(Radare2Tool),
    "ropgadget": create_tool_executor(RopgadgetTool),
    "ropper": create_tool_executor(RopperTool),
    "one_gadget": create_tool_executor(OneGadgetTool),
    "strings": create_tool_executor(StringsTool),
    "objdump": create_tool_executor(ObjdumpTool),
    "xxd": create_tool_executor(XxdTool),
    "pwntools": create_tool_executor(PwntoolsTool),
    "angr": create_tool_executor(AngrTool),
    "libc_database": create_tool_executor(LibcDatabaseTool),
    "pwninit": create_tool_executor(PwninitTool),
    "upx": create_tool_executor(UPXTool),
    "hexdump": create_tool_executor(HexdumpTool),
    # Cloud (12)
    "prowler": create_tool_executor(ProwlerTool),
    "scout_suite": create_tool_executor(ScoutSuiteTool),
    "trivy": create_tool_executor(TrivyTool),
    "kube_hunter": create_tool_executor(KubeHunterTool),
    "kube_bench": create_tool_executor(KubeBenchTool),
    "docker_bench": create_tool_executor(DockerBenchTool),
    "falco": create_tool_executor(FalcoTool),
    "checkov": create_tool_executor(CheckovTool),
    "terrascan": create_tool_executor(TerrascanTool),
    "clair": create_tool_executor(ClairTool),
    "pacu": create_tool_executor(PacuTool),
    "cloudmapper": create_tool_executor(CloudmapperTool),
    # API (1)
    "postman": create_tool_executor(PostmanTool),
}

# Initialize and register intelligence blueprint
intelligence_routes.init_app(decision_engine, tool_executors)
app.register_blueprint(intelligence_bp)

# ============================================================================
# SERVER STARTUP
# ============================================================================

# Create the banner after all classes are defined
BANNER = ModernVisualEngine.create_banner()

if __name__ == "__main__":
    # Display the beautiful new banner
    print(BANNER)

    parser = argparse.ArgumentParser(description="Run the HexStrike AI API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    args = parser.parse_args()

    if args.debug:
        DEBUG_MODE = True
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    # Enhanced startup messages with beautiful formatting
    startup_info = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Starting HexStrike AI Tools API Server{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}🌐 Port:{ModernVisualEngine.COLORS['RESET']} {API_PORT}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}🔧 Debug Mode:{ModernVisualEngine.COLORS['RESET']} {DEBUG_MODE}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}💾 Cache Size:{ModernVisualEngine.COLORS['RESET']} {CACHE_SIZE} | TTL: {CACHE_TTL}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['TERMINAL_GRAY']}⏱️  Command Timeout:{ModernVisualEngine.COLORS['RESET']} {COMMAND_TIMEOUT}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}✨ Enhanced Visual Engine:{ModernVisualEngine.COLORS['RESET']} Active
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""

    for line in startup_info.strip().split("\n"):
        if line.strip():
            logger.info(line)

    app.run(host=API_HOST, port=API_PORT, debug=DEBUG_MODE)  # Uses API_HOST (Issue #122, PR #137)
