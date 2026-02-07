"""
HexStrike AI — Tool Profile Registry

Maps every MCP tool function name to a category, and defines preset profiles
that bundle categories for common use-cases (pentest, CTF, bug bounty, etc.).

Usage:
    from core.tool_profiles import TOOL_CATEGORIES, PROFILES, resolve_profile

    tools = resolve_profile("web")       # → set of tool function names
    tools = resolve_categories(["network", "exploit"])  # → union of categories
"""

from typing import Dict, FrozenSet, Set

# ============================================================================
# TOOL → CATEGORY MAPPING
# Every MCP tool function name mapped to exactly one primary category.
# ============================================================================

TOOL_REGISTRY: Dict[str, str] = {
    # --- Network Scanning (16) ---
    "nmap_scan": "network",
    "nmap_advanced_scan": "network",
    "masscan_high_speed": "network",
    "rustscan_fast_scan": "network",
    "httpx_probe": "network",
    "dnsenum_scan": "network",
    "fierce_scan": "network",
    "autorecon_comprehensive": "network",
    "autorecon_scan": "network",
    "nbtscan_netbios": "network",
    "arp_scan_discovery": "network",
    "responder_credential_harvest": "network",
    "netexec_scan": "network",
    "enum4linux_scan": "network",
    "enum4linux_ng_advanced": "network",
    "smbmap_scan": "network",
    "rpcclient_enumeration": "network",
    "sslyze_scan": "network",
    # --- Web Application Testing (24) ---
    "nuclei_scan": "web",
    "gobuster_scan": "web",
    "sqlmap_scan": "web",
    "nikto_scan": "web",
    "feroxbuster_scan": "web",
    "ffuf_scan": "web",
    "katana_crawl": "web",
    "wpscan_analyze": "web",
    "arjun_parameter_discovery": "web",
    "arjun_scan": "web",
    "dalfox_xss_scan": "web",
    "dirsearch_scan": "web",
    "paramspider_mining": "web",
    "paramspider_discovery": "web",
    "x8_parameter_discovery": "web",
    "dirb_scan": "web",
    "dotdotpwn_scan": "web",
    "wfuzz_scan": "web",
    "xsser_scan": "web",
    "wafw00f_scan": "web",
    "commix_scan": "web",
    "nosqlmap_scan": "web",
    "tplmap_scan": "web",
    "jaeles_vulnerability_scan": "web",
    # --- Reconnaissance & OSINT (18) ---
    "amass_scan": "recon",
    "subfinder_scan": "recon",
    "waybackurls_discovery": "recon",
    "gau_discovery": "recon",
    "hakrawler_crawl": "recon",
    "theharvester_scan": "recon",
    "sherlock_investigate": "recon",
    "spiderfoot_scan": "recon",
    "trufflehog_scan": "recon",
    "aquatone_scan": "recon",
    "subjack_scan": "recon",
    "recon_ng_scan": "recon",
    # --- API-Based Recon / OSINT (6) ---
    "shodan_host_lookup": "recon",
    "shodan_search_query": "recon",
    "shodan_exploit_search": "recon",
    "censys_host_lookup": "recon",
    "censys_search_hosts": "recon",
    "censys_certificate_search": "recon",
    # --- Breach Intelligence (4) ---
    "hibp_breach_check": "breach",
    "hibp_paste_check": "breach",
    "hibp_breach_detail": "breach",
    "hibp_domain_search": "breach",
    # --- Exploitation & Password (12) ---
    "metasploit_run": "exploit",
    "hydra_attack": "exploit",
    "john_crack": "exploit",
    "hashcat_crack": "exploit",
    "medusa_attack": "exploit",
    "msfvenom_generate": "exploit",
    "patator_attack": "exploit",
    "evil_winrm_connect": "exploit",
    "hash_identifier": "exploit",
    "hashid_identify": "exploit",
    "generate_payload": "exploit",
    "hashpump_attack": "exploit",
    # --- Cloud Security (12) ---
    "prowler_scan": "cloud",
    "scout_suite_assessment": "cloud",
    "trivy_scan": "cloud",
    "kube_hunter_scan": "cloud",
    "kube_bench_cis": "cloud",
    "docker_bench_security_scan": "cloud",
    "falco_runtime_monitoring": "cloud",
    "checkov_iac_scan": "cloud",
    "terrascan_iac_scan": "cloud",
    "clair_vulnerability_scan": "cloud",
    "pacu_exploitation": "cloud",
    "cloudmapper_analysis": "cloud",
    # --- Binary Analysis (16) ---
    "ghidra_analysis": "binary",
    "checksec_analyze": "binary",
    "binwalk_analyze": "binary",
    "gdb_analyze": "binary",
    "gdb_peda_debug": "binary",
    "radare2_analyze": "binary",
    "ropgadget_search": "binary",
    "ropper_gadget_search": "binary",
    "one_gadget_search": "binary",
    "strings_extract": "binary",
    "objdump_analyze": "binary",
    "xxd_hexdump": "binary",
    "pwntools_exploit": "binary",
    "angr_symbolic_execution": "binary",
    "libc_database_lookup": "binary",
    "pwninit_setup": "binary",
    # --- Forensics (9) ---
    "volatility_analyze": "forensics",
    "volatility3_analyze": "forensics",
    "steghide_analysis": "forensics",
    "exiftool_extract": "forensics",
    "foremost_carving": "forensics",
    "zsteg_analyze": "forensics",
    "outguess_extract": "forensics",
    "scalpel_carve": "forensics",
    "bulk_extractor_scan": "forensics",
    # --- AI Intelligence Engine (10) ---
    "analyze_target_intelligence": "intelligence",
    "select_optimal_tools_ai": "intelligence",
    "optimize_tool_parameters_ai": "intelligence",
    "create_attack_chain_ai": "intelligence",
    "intelligent_smart_scan": "intelligence",
    "detect_technologies_ai": "intelligence",
    "ai_reconnaissance_workflow": "intelligence",
    "ai_vulnerability_assessment": "intelligence",
    "iterative_smart_scan": "intelligence",
    # --- Scan Session Management (6) ---
    "create_scan_session": "session",
    "get_scan_session": "session",
    "list_scan_sessions": "session",
    "analyze_tool_results": "session",
    "correlate_session_findings": "session",
    # --- Scan Memory & Persistence (9) ---
    "complete_scan_session": "memory",
    "checkpoint_scan_session": "memory",
    "get_scan_recommendations": "memory",
    "list_past_scans": "memory",
    "get_past_scan": "memory",
    "search_scan_memory": "memory",
    "get_learned_patterns": "memory",
    "consolidate_scan_memory": "memory",
    "add_scan_learning": "memory",
    # --- Finding Verification (2) ---
    "verify_finding": "intelligence",
    "batch_verify_findings": "intelligence",
    # --- Knowledge Graph (3) ---
    "ingest_to_knowledge_graph": "intelligence",
    "find_attack_paths": "intelligence",
    "query_knowledge_graph": "intelligence",
    # --- Effectiveness Tracking (1) ---
    "get_tool_effectiveness": "intelligence",
    # --- Parallel Execution (1) ---
    "parallel_execute_tools": "intelligence",
    # --- AI Payload Generation (3) ---
    "ai_generate_payload": "ai_payload",
    "ai_test_payload": "ai_payload",
    "ai_generate_attack_suite": "ai_payload",
    # --- API Security Testing (6) ---
    "api_fuzzer": "api_security",
    "graphql_scanner": "api_security",
    "jwt_analyzer": "api_security",
    "api_schema_analyzer": "api_security",
    "postman_collection_run": "api_security",
    "comprehensive_api_audit": "api_security",
    # --- Bug Bounty Workflows (7) ---
    "bugbounty_reconnaissance_workflow": "bugbounty",
    "bugbounty_vulnerability_hunting": "bugbounty",
    "bugbounty_business_logic_testing": "bugbounty",
    "bugbounty_osint_gathering": "bugbounty",
    "bugbounty_file_upload_testing": "bugbounty",
    "bugbounty_comprehensive_assessment": "bugbounty",
    "bugbounty_authentication_bypass_testing": "bugbounty",
    # --- CVE Intelligence (7) ---
    "monitor_cve_feeds": "cve",
    "generate_exploit_from_cve": "cve",
    "discover_attack_chains": "cve",
    "research_zero_day_opportunities": "cve",
    "correlate_threat_intelligence": "cve",
    "advanced_payload_generation": "cve",
    "vulnerability_intelligence_dashboard": "cve",
    "threat_hunting_assistant": "cve",
    # --- HTTP Testing Framework (6) ---
    "http_framework_test": "http_testing",
    "http_set_rules": "http_testing",
    "http_set_scope": "http_testing",
    "http_repeater": "http_testing",
    "http_intruder": "http_testing",
    "burpsuite_alternative_scan": "http_testing",
    "burpsuite_scan": "http_testing",
    "zap_scan": "http_testing",
    # --- Browser Automation (1) ---
    "browser_agent_inspect": "browser",
    # --- File Operations (4) ---
    "create_file": "fileops",
    "modify_file": "fileops",
    "delete_file": "fileops",
    "list_files": "fileops",
    # --- Python Environment (2) ---
    "install_python_package": "utility",
    "execute_python_script": "utility",
    # --- Data Processing Utilities (3) ---
    "anew_data_processing": "utility",
    "qsreplace_parameter_replacement": "utility",
    "uro_url_filtering": "utility",
    # --- Server Administration (10) ---
    "server_health": "admin",
    "get_cache_stats": "admin",
    "clear_cache": "admin",
    "get_telemetry": "admin",
    "list_active_processes": "admin",
    "get_process_status": "admin",
    "terminate_process": "admin",
    "pause_process": "admin",
    "resume_process": "admin",
    "get_process_dashboard": "admin",
    "execute_command": "admin",
    "error_handling_statistics": "admin",
    "test_error_recovery": "admin",
    # --- Visual & Reporting (4) ---
    "get_live_dashboard": "reporting",
    "create_vulnerability_report": "reporting",
    "format_tool_output_visual": "reporting",
    "create_scan_summary": "reporting",
    "display_system_metrics": "reporting",
}

# ============================================================================
# CATEGORY DESCRIPTIONS
# ============================================================================

CATEGORY_INFO: Dict[str, str] = {
    "network": "Network scanning & enumeration (nmap, masscan, enum4linux, etc.)",
    "web": "Web application testing (nuclei, gobuster, sqlmap, nikto, etc.)",
    "recon": "Reconnaissance & OSINT (amass, subfinder, shodan, censys, etc.)",
    "breach": "Breach intelligence (Have I Been Pwned lookups)",
    "exploit": "Exploitation & password attacks (metasploit, hydra, john, etc.)",
    "cloud": "Cloud security (prowler, trivy, kube-hunter, etc.)",
    "binary": "Binary analysis & reverse engineering (ghidra, gdb, binwalk, etc.)",
    "forensics": "Digital forensics & steganography (volatility, steghide, etc.)",
    "intelligence": "AI intelligence engine (smart scan, attack chains, etc.)",
    "session": "Scan session management (create, get, correlate findings)",
    "memory": "Scan memory & persistence (episodic memory, patterns, learnings)",
    "ai_payload": "AI-powered payload generation",
    "api_security": "API security testing (fuzzing, GraphQL, JWT, etc.)",
    "bugbounty": "Bug bounty workflow automation",
    "cve": "CVE intelligence & threat hunting",
    "http_testing": "HTTP testing framework (repeater, intruder, proxy)",
    "browser": "Browser automation agent",
    "fileops": "File operations on HexStrike server",
    "utility": "Python environment & data processing utilities",
    "admin": "Server administration & telemetry",
    "reporting": "Visual dashboards & vulnerability reporting",
}

# ============================================================================
# BUILD REVERSE INDEX: category → set of tool names
# ============================================================================

TOOL_CATEGORIES: Dict[str, FrozenSet[str]] = {}
for _tool_name, _category in TOOL_REGISTRY.items():
    TOOL_CATEGORIES.setdefault(_category, set())
    TOOL_CATEGORIES[_category].add(_tool_name)
# Freeze for safety
TOOL_CATEGORIES = {k: frozenset(v) for k, v in TOOL_CATEGORIES.items()}

ALL_TOOLS: FrozenSet[str] = frozenset(TOOL_REGISTRY.keys())
ALL_CATEGORIES: FrozenSet[str] = frozenset(TOOL_CATEGORIES.keys())

# ============================================================================
# PRESET PROFILES
# Each profile is a set of category names. The resolver expands them to tools.
# ============================================================================

PROFILES: Dict[str, Dict] = {
    "minimal": {
        "description": "AI-driven smart scanning — lean and fast",
        "emoji": "🎯",
        "categories": frozenset({"intelligence", "session", "memory", "reporting"}),
    },
    "web": {
        "description": "Web application penetration testing",
        "emoji": "🌐",
        "categories": frozenset(
            {
                "web",
                "recon",
                "api_security",
                "http_testing",
                "intelligence",
                "session",
                "memory",
                "reporting",
                "utility",
                "fileops",
            }
        ),
    },
    "network": {
        "description": "Network assessment & enumeration",
        "emoji": "🔌",
        "categories": frozenset(
            {
                "network",
                "exploit",
                "intelligence",
                "session",
                "memory",
                "reporting",
                "admin",
                "fileops",
            }
        ),
    },
    "bugbounty": {
        "description": "Bug bounty hunting workflow",
        "emoji": "🐛",
        "categories": frozenset(
            {
                "web",
                "recon",
                "breach",
                "bugbounty",
                "api_security",
                "http_testing",
                "intelligence",
                "session",
                "memory",
                "reporting",
                "utility",
                "fileops",
            }
        ),
    },
    "ctf": {
        "description": "Capture the flag competitions",
        "emoji": "🏴",
        "categories": frozenset(
            {
                "binary",
                "forensics",
                "exploit",
                "web",
                "network",
                "intelligence",
                "session",
                "memory",
                "reporting",
                "utility",
                "fileops",
            }
        ),
    },
    "cloud": {
        "description": "Cloud security audit & compliance",
        "emoji": "☁️",
        "categories": frozenset(
            {
                "cloud",
                "network",
                "intelligence",
                "session",
                "memory",
                "reporting",
                "admin",
            }
        ),
    },
    "redteam": {
        "description": "Red team operations — full offensive toolkit",
        "emoji": "🔴",
        "categories": frozenset(
            {
                "network",
                "web",
                "recon",
                "exploit",
                "breach",
                "cve",
                "ai_payload",
                "http_testing",
                "browser",
                "intelligence",
                "session",
                "memory",
                "reporting",
                "utility",
                "fileops",
                "admin",
            }
        ),
    },
    "full": {
        "description": "All tools loaded — maximum capability",
        "emoji": "💀",
        "categories": ALL_CATEGORIES,
    },
}


def resolve_profile(profile_name: str) -> Set[str]:
    """Resolve a profile name to the set of tool function names it includes."""
    profile_name = profile_name.lower().strip()
    if profile_name not in PROFILES:
        valid = ", ".join(sorted(PROFILES.keys()))
        raise ValueError(f"Unknown profile '{profile_name}'. Valid profiles: {valid}")
    categories = PROFILES[profile_name]["categories"]
    return resolve_categories(categories)


def resolve_categories(categories) -> Set[str]:
    """Resolve a set of category names to the union of their tool function names."""
    tools: Set[str] = set()
    for cat in categories:
        cat = cat.lower().strip()
        if cat not in TOOL_CATEGORIES:
            valid = ", ".join(sorted(TOOL_CATEGORIES.keys()))
            raise ValueError(f"Unknown category '{cat}'. Valid categories: {valid}")
        tools |= TOOL_CATEGORIES[cat]
    return tools


def get_profile_tool_count(profile_name: str) -> int:
    """Get the number of tools in a profile without resolving the full set."""
    return len(resolve_profile(profile_name))


def get_category_tool_count(category: str) -> int:
    """Get the number of tools in a category."""
    category = category.lower().strip()
    if category not in TOOL_CATEGORIES:
        return 0
    return len(TOOL_CATEGORIES[category])
