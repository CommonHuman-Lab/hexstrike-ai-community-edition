from mcp_core.hexstrikecolors import HexStrikeColors
from mcp_tools.gateway import register_gateway_tools
from mcp_tools.ops.wordlist import register_wordlist_tools
from mcp_tools.ops.file_ops_and_payload_gen import register_file_ops_and_payload_gen_tools
from mcp_tools.ops.python_env import register_python_env_tools
from mcp_tools.ai_payload.ai_payload_generation import register_ai_payload_generation_tools
from mcp_tools.bugbounty_workflow.bug_bounty_recon import register_bug_bounty_recon_tools
from mcp_tools.ops.system_monitoring import register_system_monitoring_tools
from mcp_tools.ops.process_management import register_process_management_tools
from mcp_tools.ops.vulnerability_intelligence import register_vulnerability_intelligence_tools
from mcp_tools.ops.visual_output_tools import register_visual_output_tools
from mcp_tools.ai_assist.intelligent_decision_engine import register_intelligent_decision_engine_tools
from mcp_tools.web_fuzz import (
    register_dirb_tool,
    register_ffuf_tool,
    register_dirsearch_tools,
    register_gobuster,
    register_feroxbuster_tool,
    register_dotdotpwn_tool,
    register_wfuzz_tool,
)
from mcp_tools.web_crawl.katana import register_katana_tool
from mcp_tools.web_crawl.hakrawler import register_hakrawler_tools
from mcp_tools.web_scan import (
    register_nikto_tool,
    register_sqlmap_tool,
    register_wpscan_tool,
    register_jaeles_tool,
    register_dalfox_tool,
    register_burpsuite_tool,
    register_zap_tool,
    register_xsser_tool,
)
from mcp_tools.exploit_framework.metasploit import register_metasploit_tool
from mcp_tools.exploit_framework.msfvenom import register_msfvenom
from mcp_tools.exploit_framework.pwntools import register_pwntools
from mcp_tools.exploit_framework.pwninit import register_pwninit_tool
from mcp_tools.exploit_framework.searchsploit import register_searchsploit_tool

from mcp_tools.password_cracking import (
    register_hydra_tool,
    register_john_tool,
    register_hashcat_tool,
    register_medusa_tool,
    register_patator_tool,
    register_hashid_tool,
    register_ophcrack_tool
)

from mcp_tools.smb_enum import (
    register_enum4linux_tool,
    register_netexec_tool,
    register_smbmap_tool,
    register_nbtscan_tool,
    register_rpcclient_tool
)

from mcp_tools.recon.amass import register_amass_tool
from mcp_tools.recon.subfinder import register_subfinder_tool
from mcp_tools.recon.autorecon import register_autorecon_tool
from mcp_tools.recon.theharvester import register_theharvester_tool
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
from mcp_tools.memory_forensics.volatility3 import register_volatility3
from mcp_tools.credential_harvest.responder import register_responder_tool
from mcp_tools.binary_debug.gdb import register_gdb_tools
from mcp_tools.binary_debug.radare2 import register_radare2_tools
from mcp_tools.binary_analysis import (
    register_binwalk_tool,
    register_checksec_tool,
    register_xxd_tool,
    register_strings_tool,
    register_objdump_tool,
    register_ghidra_tools,
    register_libc_tools,
    register_angr_tools,
)
from mcp_tools.gadget_search.ropgadget import register_ropgadget_tool
from mcp_tools.gadget_search.one_gadget import register_one_gadget_tool
from mcp_tools.gadget_search.ropper import register_ropper_tool
from mcp_tools.api_fuzz.api_fuzzer import register_api_fuzzer_tool
from mcp_tools.api_scan.graphql_scanner import register_graphql_scanner_tool
from mcp_tools.api_scan.jwt_analyzer import register_jwt_analyzer_tool
from mcp_tools.api_scan.api_schema_analyzer import register_api_schema_analyzer
from mcp_tools.api_audit.comprehensive_api_audit import register_comprehensive_api_audit_tool
from mcp_tools.file_carving.foremost import register_foremost_tool
from mcp_tools.stego_analysis.steghide import register_steghide_tool
from mcp_tools.metadata_extract.exiftool import register_exiftool_tool
from mcp_tools.crypto_attack.hashpump import register_hashpump_tool

def resolve_profile_dependencies(profiles):
    resolved = set()
    to_process = list(profiles)
    while to_process:
        profile = to_process.pop()
        if profile not in resolved:
            resolved.add(profile)
            deps = PROFILE_DEPENDENCIES.get(profile, [])
            to_process.extend([dep for dep in deps if dep not in resolved])
    return list(resolved)

TOOL_PROFILES = {

    # All Profiles
    ## `compact` (essential gateway tools only)
    ## `full` (all tools registered)

    #Compact mode 
    #Only essential tools for task classification and tool execution, without all the individual tool functions. Allows smaller LLM clients to use the MCP server without running into token limits due to too many registered tools.
    "compact": [
        lambda mcp, client, logger: register_gateway_tools(mcp, client),
    ],

    "api_audit": [
        lambda mcp, client, logger: register_comprehensive_api_audit_tool(mcp, client, logger), #Uses api_fuzz and api_scan tools internally, so they are needed for this profile as well.
    ],

    #Tools for steganography analysis (e.g., Steghide).
    "stego_analysis": [
        lambda mcp, client, logger: register_steghide_tool(mcp, client, logger),
    ],

    #Tools for metadata extraction (e.g., ExifTool).
    "metadata_extract": [
        lambda mcp, client, logger: register_exiftool_tool(mcp, client, logger),
    ],

    #Tools for cryptographic attacks (e.g., HashPump).
    "crypto_attack": [
        lambda mcp, client, logger: register_hashpump_tool(mcp, client, logger),
    ],

    #Tools for file carving and data recovery (e.g., Foremost).
    "file_carving": [
        lambda mcp, client, logger: register_foremost_tool(mcp, client, logger),
    ],

    #Tools for API fuzzing and endpoint discovery (e.g., API Fuzzer with intelligent parameter discovery).
    "api_fuzz": [
        lambda mcp, client, logger: register_api_fuzzer_tool(mcp, client, logger),
    ],

    #Tools for API scanning (e.g., GraphQL Scanner with enhanced security testing).
    "api_scan": [
        lambda mcp, client, logger: register_graphql_scanner_tool(mcp, client, logger),
        lambda mcp, client, logger: register_jwt_analyzer_tool(mcp, client, logger),
        lambda mcp, client, logger: register_api_schema_analyzer(mcp, client, logger),
    ],

    #Tools for binary debugging
    "binary_debug": [
        lambda mcp, client, logger: register_gdb_tools(mcp, client, logger),
        lambda mcp, client, logger: register_radare2_tools(mcp, client, logger),
    ],

    #Tools for ROP gadget searching and analysis (e.g., ROPgadget, OneGadget, Ropper).
    "gadget_search": [
        lambda mcp, client, logger: register_ropgadget_tool(mcp, client, logger),
        lambda mcp, client, logger: register_one_gadget_tool(mcp, client, logger),
        lambda mcp, client, logger: register_ropper_tool(mcp, client, logger),
    ],

    #Tools for binary analysis (e.g., Binwalk, Checksec, xxd, Strings, Objdump, Libc, Angr).
    "binary_analysis": [
        lambda mcp, client, logger: register_binwalk_tool(mcp, client, logger),
        lambda mcp, client, logger: register_checksec_tool(mcp, client, logger),
        lambda mcp, client, logger: register_xxd_tool(mcp, client, logger),
        lambda mcp, client, logger: register_strings_tool(mcp, client, logger),
        lambda mcp, client, logger: register_objdump_tool(mcp, client, logger),
        lambda mcp, client, logger: register_ghidra_tools(mcp, client, logger),
        lambda mcp, client, logger: register_libc_tools(mcp, client, logger),
        lambda mcp, client, logger: register_angr_tools(mcp, client, logger),
    ],

    #Tools for credential harvesting and network poisoning (e.g., Responder).
    "credential_harvest": [
        lambda mcp, client, logger: register_responder_tool(mcp, client, logger),
    ],

    #Tools for memory forensics analysis (e.g., Volatility, Volatility3).
    "memory_forensics": [
        lambda mcp, client, logger: register_volatility_tool(mcp, client, logger),
        lambda mcp, client, logger: register_volatility3(mcp, client, logger),
    ],

    #Tools for brute-forcing and cracking password hashes (e.g., Hydra, John, Hashcat, Medusa, Patator, HashId, Ophcrack).
    "password_cracking": [
        lambda mcp, client, logger: register_hydra_tool(mcp, client, logger),
        lambda mcp, client, logger: register_john_tool(mcp, client, logger),
        lambda mcp, client, logger: register_hashcat_tool(mcp, client, logger),
        lambda mcp, client, logger: register_medusa_tool(mcp, client, logger),
        lambda mcp, client, logger: register_patator_tool(mcp, client, logger),
        lambda mcp, client, logger: register_hashid_tool(mcp, client, logger),
        lambda mcp, client, logger: register_ophcrack_tool(mcp, client, logger),
    ],

    #Tools for SMB and network share enumeration (e.g., Enum4linux, NetExec, SMBMap, NBTSCan, RPCClient).
    "smb_enum": [
        lambda mcp, client, logger: register_enum4linux_tool(mcp, client, logger),
        lambda mcp, client, logger: register_netexec_tool(mcp, client, logger),
        lambda mcp, client, logger: register_smbmap_tool(mcp, client, logger),
        lambda mcp, client, logger: register_nbtscan_tool(mcp, client, logger),
        lambda mcp, client, logger: register_rpcclient_tool(mcp, client, logger),
    ],

    #Tools for reconnaissance and subdomain discovery (e.g., Amass, Subfinder, AutoRecon, TheHarvester).
    "recon": [
        lambda mcp, client, logger: register_amass_tool(mcp, client, logger),
        lambda mcp, client, logger: register_subfinder_tool(mcp, client, logger),
        lambda mcp, client, logger: register_autorecon_tool(mcp, client, logger),
        lambda mcp, client, logger: register_theharvester_tool(mcp, client, logger),
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

    #Tools for web content discovery and fuzzing (e.g., Dirb, FFuf, Dirsearch, Gobuster, Feroxbuster, DotDotPwn, Wfuzz).
    "web_fuzz": [
        lambda mcp, client, logger: register_dirb_tool(mcp, client, logger),
        lambda mcp, client, logger: register_ffuf_tool(mcp, client, logger),
        lambda mcp, client, logger: register_dirsearch_tools(mcp, client, logger),
        lambda mcp, client, logger: register_gobuster(mcp, client, logger, HexStrikeColors),
        lambda mcp, client, logger: register_feroxbuster_tool(mcp, client, logger),
        lambda mcp, client, logger: register_dotdotpwn_tool(mcp, client, logger),
        lambda mcp, client, logger: register_wfuzz_tool(mcp, client, logger),
    ],

    #Tools for web crawling and spidering (e.g., Katana, Hakrawler).
    "web_crawl": [
        lambda mcp, client, logger: register_katana_tool(mcp, client, logger),
        lambda mcp, client, logger: register_hakrawler_tools(mcp, client, logger),
    ],

    #Tools for web vulnerability scanning and assessment (e.g., Nikto, WPScan, SQLMap, Jaeles, Dalfox, ZAP, Burp Suite, XSSer).
    "web_scan": [
        lambda mcp, client, logger: register_nikto_tool(mcp, client, logger),
        lambda mcp, client, logger: register_sqlmap_tool(mcp, client, logger),
        lambda mcp, client, logger: register_wpscan_tool(mcp, client, logger),
        lambda mcp, client, logger: register_jaeles_tool(mcp, client, logger),
        lambda mcp, client, logger: register_dalfox_tool(mcp, client, logger),
        lambda mcp, client, logger: register_burpsuite_tool(mcp, client, logger, HexStrikeColors),
        lambda mcp, client, logger: register_zap_tool(mcp, client, logger),
        lambda mcp, client, logger: register_xsser_tool(mcp, client, logger),
    ],

    #Tools for web probing and technology detection (e.g., httpx).
    "web_probe": [
        lambda mcp, client, logger: register_httpx_tool(mcp, client, logger),
    ],

    #Tools for vulnerability scanning and assessment (e.g., Nuclei).
    "vuln_scan": [
        lambda mcp, client, logger: register_nuclei(mcp, client, logger, HexStrikeColors),
    ],

    #Tools for automated exploitation and attack frameworks (e.g., Metasploit, MSFVenom, Pwninit, Pwntools, exploit-db).
    "exploit_framework": [
        lambda mcp, client, logger: register_metasploit_tool(mcp, client, logger),
        lambda mcp, client, logger: register_msfvenom(mcp, client, logger),
        lambda mcp, client, logger: register_pwntools(mcp, client, logger),
        lambda mcp, client, logger: register_pwninit_tool(mcp, client, logger),
        lambda mcp, client, logger: register_searchsploit_tool(mcp, client, logger), #aka. exploit-db
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

    #Tools for bug bounty workflows and recon automation
    "bug_bounty": [
        lambda mcp, client, logger: register_bug_bounty_recon_tools(mcp, client, logger),
    ],

    #Tools for AI-powered payload generation and testing
    "ai_payload": [
        lambda mcp, client, logger: register_ai_payload_generation_tools(mcp, client, logger),
    ],

    #Tools for intelligent decision making and tool selection based on task context and goals
    "ai_assist": [
        lambda mcp, client, logger: register_intelligent_decision_engine_tools(mcp, client, logger, HexStrikeColors),
    ],

    #Tools for vulnerability intelligence gathering and analysis
    "vuln_intel": [
        lambda mcp, client, logger: register_vulnerability_intelligence_tools(mcp, client, logger),
    ],

    #Tools for visual output and reporting
    "visual": [
        lambda mcp, client, logger: register_visual_output_tools(mcp, client, logger),
    ],

    #Tools for system monitoring
    "monitoring": [
        lambda mcp, client, logger: register_system_monitoring_tools(mcp, client, logger),
    ],

    #Tools for process management
    "process_management": [
        lambda mcp, client, logger: register_process_management_tools(mcp, client, logger),
    ],
}

# Profile dependencies
PROFILE_DEPENDENCIES = {
    "api_audit": ["api_fuzz", "api_scan"],
}

# Default profile for easy loading of tool categories
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

    # System tools"
    "monitoring",
    "process_management",
    "visual"
]

# Full profile includes all available tool categories
FULL_PROFILE = list(TOOL_PROFILES.keys())