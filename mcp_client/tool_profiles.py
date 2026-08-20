from mcp_client.cli_colors import CliColors
from mcp_client.gateway import register_gateway_tools
from mcp_client.registrar import register_toolspec_category

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

    "active_directory": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "active_directory"),
    ],

    "api_audit": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "api_audit"), #Uses api_fuzz and api_scan tools internally, so they are needed for this profile as well.
    ],

    #OSINT tools for information gathering and reconnaissance e.g. Sherlock)
    "osint": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "osint"),
    ],

    #Tools for steganography analysis (e.g., Steghide).
    "stego_analysis": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "stego_analysis"),
    ],

    #Tools for metadata extraction (e.g., ExifTool).
    "metadata_extract": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "metadata_extract"),
    ],

    #Tools for cryptographic attacks (e.g., HashPump).
    "crypto_attack": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "crypto_attack"),
    ],

    #Tools for file carving and data recovery (e.g., Foremost).
    "file_carving": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "file_carving"),
    ],

    #Tools for API fuzzing and endpoint discovery (e.g., API Fuzzer with intelligent parameter discovery).
    "api_fuzz": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "api_fuzz"),
    ],

    #Tools for API scanning (e.g., GraphQL Scanner with enhanced security testing).
    "api_scan": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "api_scan"),
    ],

    #Tools for binary debugging
    "binary_debug": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "binary_debug"),
    ],

    #Tools for ROP gadget searching and analysis (e.g., ROPgadget, OneGadget, Ropper).
    "gadget_search": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "gadget_search"),
    ],

    #Tools for binary analysis (e.g., Binwalk, Checksec, xxd, Strings, Objdump, Libc, Angr, Autopsy, one_gadget, Ropper).
    "binary_analysis": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "binary_analysis"),
    ],

    #Tools for credential harvesting and network poisoning (e.g., Responder, VaultRip).
    "credential_harvest": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "credential_harvest"),
    ],

    #Tools for memory forensics analysis (e.g., Volatility, Volatility3).
    "memory_forensics": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "memory_forensics"),
    ],

    #Tools for brute-forcing and cracking password hashes (e.g., Hydra, John, Hashcat, Medusa, Patator, HashId, Ophcrack, Aircrack-ng).
    "password_cracking": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "password_cracking"),
    ],

       # WiFi penetration testing and wireless security assessment
    "wifi_pentest": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "wifi_pentest"),
    ],

    #Tools for SMB and network share enumeration (e.g., Enum4linux, NetExec, SMBMap, NBTSCan, RPCClient).
    "smb_enum": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "smb_enum"),
    ],

    #Tools for reconnaissance and subdomain discovery (e.g., Amass, Subfinder, AutoRecon, TheHarvester).
    "recon": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "recon"),
    ],

    #Tools for network scanning and enumeration (e.g., Nmap, ARP-Scan, Masscan, Rustscan).
    "net_scan": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "net_scan"),
    ],

    #Tools for network information gathering and lookups (e.g., WHOIS).
    "net_lookup": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "net_lookup"),
    ],

    #Tools for reconnaissance and enumeration (e.g., BBot).
    "recon_bot": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "recon_bot"),
    ],

    #Tools for web content discovery and fuzzing (e.g., Dirb, FFuf, Dirsearch, Gobuster, Feroxbuster, DotDotPwn, Wfuzz).
    "web_fuzz": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "web_fuzz"),
    ],

    #Tools for web crawling and spidering (e.g., Katana, Hakrawler).
    "web_crawl": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "web_crawl"),
    ],

    #Tools for web vulnerability scanning and assessment (e.g., Nikto, WPScan, SQLMap, Jaeles, Dalfox, ZAP, Burp Suite, XSSer).
    "web_scan": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "web_scan"),
    ],

    #Tools for web probing and technology detection (e.g., httpx).
    "web_probe": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "web_probe"),
    ],

    #Tools for vulnerability scanning and assessment (e.g., Nuclei).
    "vuln_scan": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "vuln_scan"),
    ],

    #Tools for automated exploitation and attack frameworks (e.g., Metasploit, MSFVenom, Pwninit, Pwntools, exploit-db).
    "exploit_framework": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "exploit_framework"),
    ],

    #Tools for URL discovery and reconnaissance (e.g., Gau, Waybackurls, Waymore).
    "url_recon": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "url_recon"),
    ],

    #Tools for parameter discovery and fuzzing (e.g., Arju0n, ParamSpider, x8).
    "param_discovery": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "param_discovery"),
    ],

    #Tools for query string parameter replacement (e.g., qsreplace).
    "param_fuzz": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "param_fuzz"),
    ],

    #Tools for data processing and unique line filtering (e.g., anew).
    "data_processing": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "data_processing"),
    ],

    #Tools for URL filtering and duplicate removal (e.g., uro).
    "url_filter": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "url_filter"),
    ],

    #Tools for web application security testing frameworks (e.g., HTTP Framework, Browser Agent).
    "web_framework": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "web_framework"),
    ],

    #Tools for WAF detection and fingerprinting (e.g., wafw00f).
    "waf_detect": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "waf_detect"),
    ],

    #Tools for DNS enumeration and subdomain takeover detection (e.g., Fierce, DNSenum).
    "dns_enum": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "dns_enum"),
    ],
    
    #Tools for error handling and statistics collection to improve reliability and debugging.
    "error_handling": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "error_handling"),
    ],

    #Tools for cloud assessment and auditing (e.g., Prowler, Scout Suite).
    "cloud_audit": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "cloud_audit"),
    ],

    #Tools for cloud exploitation and attack simulation (e.g., CloudMapper, Pacu).
    "cloud_exploit": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "cloud_exploit"),
    ],

    #Tools for Kubernetes scanning and penetration testing (e.g., kube-hunter, kube-bench).
    "k8s_scan": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "k8s_scan"),
    ],

    #Tools for infrastructure as code security scanning (e.g., Checkov, Terrascan).
    "iac_scan": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "iac_scan"),
    ],

    #Tools for container scanning and vulnerability assessment (e.g., Trivy, Docker Bench, Clair).
    "container_scan": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "container_scan"),
    ],

    #Tools for runtime monitoring and anomaly detection (e.g., Falco).
    "runtime_monitor": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "runtime_monitor"),
    ],

    #Tools for database querying and interaction (e.g., SQLite, MySQL, PostgreSQL).
    "db_query": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "db_query"),
    ],

    #Tools for Python environment interaction and code execution
    "python_env": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "python_env"),
    ],

    #Tools for file operations and AI-powered payload generation
    "file_payload": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "file_payload"),
    ],

    #Tools for wordlist management
    "wordlist": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "wordlist"),
    ],

    #Tools for bug bounty workflows and recon automation
    "bug_bounty": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "bug_bounty"),
    ],

    #Tools for AI-powered payload generation and testing
    "ai_payload": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "ai_payload"),
    ],

    #Tools for intelligent decision making and tool selection based on task context and goals
    "ai_assist": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "ai_assist"),
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "decision_engine"),
    ],

    #Tools for vulnerability intelligence gathering and analysis
    "vuln_intel": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "vuln_intel"),
    ],

    #Tools for visual output and reporting
    "visual": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "visual"),
    ],

    #Tools for system monitoring
    "monitoring": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "monitoring"),
    ],

    #Tools for process management
    "process_management": [
        lambda mcp, client, logger: register_toolspec_category(mcp, client, logger, "process_management"),
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
    "wifi_pentest",
    "api_audit",

    # System tools"
    "monitoring",
    "process_management",
    "visual",
]

# Full profile includes all available tool categories
FULL_PROFILE = list(TOOL_PROFILES.keys())
