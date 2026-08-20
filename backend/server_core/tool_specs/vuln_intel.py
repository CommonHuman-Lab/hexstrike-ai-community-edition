import shlex
import time
from datetime import datetime

from backend.server_core.generators.payload_generator import ai_payload_generator
from backend.server_core.singletons import cve_intelligence, exploit_generator, vulnerability_correlator
from backend.server_core.tool_spec import ParamSpec, ToolSpec, ToolValidationError


def _vulnx_command(p: dict) -> str:
    cve_id, search, auth = p["cve_id"], p["search"], p["auth_key"]
    if not (cve_id or search):
        raise ToolValidationError("At least one of cve_id or search must be provided")

    argv = ["vulnx"]
    if cve_id:
        argv.append("id")
        argv.append(cve_id)
    if search:
        argv.append("search")
        argv.append(search)
    if auth:
        argv.append("auth")
        argv.append("--api-key")
        argv.append(auth)
    return shlex.join(argv)


def _cve_monitor_handler(p: dict) -> dict:
    hours = p["hours"]
    severity_filter = p["severity_filter"]
    keywords = p["keywords"]

    cve_results = cve_intelligence.fetch_latest_cves(hours, severity_filter)

    if keywords and cve_results.get("success"):
        keyword_list = [k.strip().lower() for k in keywords.split(",")]
        filtered_cves = []

        for cve in cve_results.get("cves", []):
            description = cve.get("description", "").lower()
            if any(keyword in description for keyword in keyword_list):
                filtered_cves.append(cve)

        cve_results["cves"] = filtered_cves
        cve_results["filtered_by_keywords"] = keywords
        cve_results["total_after_filter"] = len(filtered_cves)

    exploitability_analysis = []
    for cve in cve_results.get("cves", [])[:5]:
        cve_id = cve.get("cve_id", "")
        if cve_id:
            analysis = cve_intelligence.analyze_cve_exploitability(cve_id)
            if analysis.get("success"):
                exploitability_analysis.append(analysis)

    return {
        "success": True,
        "cve_monitoring": cve_results,
        "exploitability_analysis": exploitability_analysis,
        "timestamp": datetime.now().isoformat(),
    }


def _exploit_generate_handler(p: dict) -> dict:
    cve_id = p["cve_id"]
    target_os = p["target_os"]
    target_arch = p["target_arch"]
    exploit_type = p["exploit_type"]
    evasion_level = p["evasion_level"]

    target_info = {
        "target_os": target_os,
        "target_arch": target_arch,
        "exploit_type": exploit_type,
        "evasion_level": evasion_level,
        "target_ip": "192.168.1.100",
        "target_port": 80,
        "description": f"Target for {cve_id}",
    }

    cve_analysis = cve_intelligence.analyze_cve_exploitability(cve_id)
    if not cve_analysis.get("success"):
        raise ToolValidationError(
            f"Failed to analyze CVE {cve_id}: {cve_analysis.get('error', 'Unknown error')}"
        )

    cve_data = {
        "cve_id": cve_id,
        "description": f"Vulnerability analysis for {cve_id}",
        "exploitability_level": cve_analysis.get("exploitability_level", "UNKNOWN"),
        "exploitability_score": cve_analysis.get("exploitability_score", 0),
    }

    exploit_result = exploit_generator.generate_exploit_from_cve(cve_data, target_info)
    existing_exploits = cve_intelligence.search_existing_exploits(cve_id)

    return {
        "success": True,
        "cve_analysis": cve_analysis,
        "exploit_generation": exploit_result,
        "existing_exploits": existing_exploits,
        "target_info": target_info,
        "timestamp": datetime.now().isoformat(),
    }


def _attack_chains_handler(p: dict) -> dict:
    target_software = p["target_software"]
    attack_depth = min(max(int(p["attack_depth"]), 1), 5)
    include_zero_days = p["include_zero_days"]

    chain_results = vulnerability_correlator.find_attack_chains(target_software, attack_depth)

    if chain_results.get("success") and chain_results.get("attack_chains"):
        enhanced_chains = []

        for chain in chain_results["attack_chains"][:2]:
            enhanced_chain = chain.copy()
            enhanced_stages = []

            for stage in chain["stages"]:
                enhanced_stage = stage.copy()

                vuln = stage.get("vulnerability", {})
                cve_id = vuln.get("cve_id", "")

                if cve_id:
                    try:
                        cve_data = {"cve_id": cve_id, "description": vuln.get("description", "")}
                        target_info = {"target_os": "linux", "target_arch": "x64", "evasion_level": "basic"}

                        exploit_result = exploit_generator.generate_exploit_from_cve(cve_data, target_info)
                        enhanced_stage["exploit_available"] = exploit_result.get("success", False)

                        if exploit_result.get("success"):
                            enhanced_stage["exploit_code"] = exploit_result.get("exploit_code", "")[:500] + "..."
                    except Exception:
                        enhanced_stage["exploit_available"] = False

                enhanced_stages.append(enhanced_stage)

            enhanced_chain["stages"] = enhanced_stages
            enhanced_chains.append(enhanced_chain)

        chain_results["enhanced_chains"] = enhanced_chains

    return {
        "success": True,
        "attack_chain_discovery": chain_results,
        "parameters": {
            "target_software": target_software,
            "attack_depth": attack_depth,
            "include_zero_days": include_zero_days,
        },
        "timestamp": datetime.now().isoformat(),
    }


def _zero_day_research_handler(p: dict) -> dict:
    target_software = p["target_software"]
    analysis_depth = p["analysis_depth"]
    if analysis_depth not in ["quick", "standard", "comprehensive"]:
        analysis_depth = "standard"
    source_code_url = p["source_code_url"]

    research_results = {
        "target_software": target_software,
        "analysis_depth": analysis_depth,
        "research_areas": [],
        "potential_vulnerabilities": [],
        "risk_assessment": {},
        "recommendations": [],
    }

    common_research_areas = [
        "Input validation vulnerabilities",
        "Memory corruption issues",
        "Authentication bypasses",
        "Authorization flaws",
        "Cryptographic weaknesses",
        "Race conditions",
        "Logic flaws",
    ]

    web_research_areas = [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Server-side request forgery (SSRF)",
        "Insecure deserialization",
        "Template injection",
    ]

    system_research_areas = [
        "Buffer overflows",
        "Privilege escalation",
        "Kernel vulnerabilities",
        "Service exploitation",
        "Configuration weaknesses",
    ]

    target_lower = target_software.lower()
    if any(web_tech in target_lower for web_tech in ["apache", "nginx", "tomcat", "php", "node", "django"]):
        research_results["research_areas"] = common_research_areas + web_research_areas
    elif any(sys_tech in target_lower for sys_tech in ["windows", "linux", "kernel", "driver"]):
        research_results["research_areas"] = common_research_areas + system_research_areas
    else:
        research_results["research_areas"] = common_research_areas

    vuln_count = {"quick": 2, "standard": 4, "comprehensive": 6}.get(analysis_depth, 4)

    for i in range(vuln_count):
        potential_vuln = {
            "id": f"RESEARCH-{target_software.upper()}-{i+1:03d}",
            "category": research_results["research_areas"][i % len(research_results["research_areas"])],
            "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
            "confidence": ["LOW", "MEDIUM", "HIGH"][i % 3],
            "description": f"Potential {research_results['research_areas'][i % len(research_results['research_areas'])].lower()} in {target_software}",
            "attack_vector": "To be determined through further analysis",
            "impact": "To be assessed",
            "proof_of_concept": "Research phase - PoC development needed",
        }
        research_results["potential_vulnerabilities"].append(potential_vuln)

    high_risk_count = sum(1 for v in research_results["potential_vulnerabilities"] if v["severity"] in ["HIGH", "CRITICAL"])
    total_vulns = len(research_results["potential_vulnerabilities"])

    research_results["risk_assessment"] = {
        "total_areas_analyzed": len(research_results["research_areas"]),
        "potential_vulnerabilities_found": total_vulns,
        "high_risk_findings": high_risk_count,
        "risk_score": min((high_risk_count * 25 + (total_vulns - high_risk_count) * 10), 100),
        "research_confidence": analysis_depth,
    }

    if high_risk_count > 0:
        research_results["recommendations"] = [
            "Prioritize security testing in identified high-risk areas",
            "Conduct focused penetration testing",
            "Implement additional security controls",
            "Consider bug bounty program for target software",
            "Perform code review in identified areas",
        ]
    else:
        research_results["recommendations"] = [
            "Continue standard security testing",
            "Monitor for new vulnerability research",
            "Implement defense-in-depth strategies",
            "Regular security assessments recommended",
        ]

    if source_code_url:
        research_results["source_code_analysis"] = {
            "repository_url": source_code_url,
            "analysis_status": "simulated",
            "findings": [
                "Static analysis patterns identified",
                "Potential code quality issues detected",
                "Security-relevant functions located",
            ],
            "recommendation": "Manual code review recommended for identified areas",
        }

    return {
        "success": True,
        "zero_day_research": research_results,
        "disclaimer": "This is simulated research for demonstration. Real zero-day research requires extensive manual analysis.",
        "timestamp": datetime.now().isoformat(),
    }


def _threat_feeds_handler(p: dict) -> dict:
    timeframe = p["timeframe"]
    sources = p["sources"]

    valid_timeframes = ["7d", "30d", "90d", "1y"]
    if timeframe not in valid_timeframes:
        timeframe = "30d"

    indicators = [i.strip() for i in p["indicators"].split(",") if i.strip()]
    if not indicators:
        raise ToolValidationError("Indicators parameter is required")

    correlation_results = {
        "indicators_analyzed": indicators,
        "timeframe": timeframe,
        "sources": sources,
        "correlations": [],
        "threat_score": 0,
        "recommendations": [],
    }

    cve_indicators = [i for i in indicators if i.startswith("CVE-")]
    ip_indicators = [i for i in indicators if i.replace(".", "").isdigit()]
    hash_indicators = [
        i for i in indicators
        if len(i) in [32, 40, 64] and all(c in "0123456789abcdef" for c in i.lower())
    ]

    for cve_id in cve_indicators:
        try:
            cve_analysis = cve_intelligence.analyze_cve_exploitability(cve_id)
            if cve_analysis.get("success"):
                correlation_results["correlations"].append({
                    "indicator": cve_id,
                    "type": "cve",
                    "analysis": cve_analysis,
                    "threat_level": cve_analysis.get("exploitability_level", "UNKNOWN"),
                })

                exploit_score = cve_analysis.get("exploitability_score", 0)
                correlation_results["threat_score"] += min(exploit_score, 100)

            exploits = cve_intelligence.search_existing_exploits(cve_id)
            if exploits.get("success") and exploits.get("total_exploits", 0) > 0:
                correlation_results["correlations"].append({
                    "indicator": cve_id,
                    "type": "exploit_availability",
                    "exploits_found": exploits.get("total_exploits", 0),
                    "threat_level": "HIGH",
                })
                correlation_results["threat_score"] += 25

        except Exception:
            pass

    for ip in ip_indicators:
        correlation_results["correlations"].append({
            "indicator": ip,
            "type": "ip_reputation",
            "analysis": {
                "reputation": "unknown",
                "geolocation": "unknown",
                "associated_threats": [],
            },
            "threat_level": "MEDIUM",
        })

    for hash_val in hash_indicators:
        correlation_results["correlations"].append({
            "indicator": hash_val,
            "type": "file_hash",
            "analysis": {
                "hash_type": f"hash{len(hash_val)}",
                "malware_family": "unknown",
                "detection_rate": "unknown",
            },
            "threat_level": "MEDIUM",
        })

    total_indicators = len(indicators)
    if total_indicators > 0:
        correlation_results["threat_score"] = min(correlation_results["threat_score"] / total_indicators, 100)

        if correlation_results["threat_score"] >= 75:
            correlation_results["recommendations"] = [
                "Immediate threat response required",
                "Block identified indicators",
                "Enhance monitoring for related IOCs",
                "Implement emergency patches for identified CVEs",
            ]
        elif correlation_results["threat_score"] >= 50:
            correlation_results["recommendations"] = [
                "Elevated threat level detected",
                "Increase monitoring for identified indicators",
                "Plan patching for identified vulnerabilities",
                "Review security controls",
            ]
        else:
            correlation_results["recommendations"] = [
                "Low to medium threat level",
                "Continue standard monitoring",
                "Plan routine patching",
                "Consider additional threat intelligence sources",
            ]

    return {
        "success": True,
        "threat_intelligence": correlation_results,
        "timestamp": datetime.now().isoformat(),
    }


def _advanced_payload_generation_handler(p: dict) -> dict:
    attack_type = p["attack_type"]
    target_context = p["target_context"]
    evasion_level = p["evasion_level"]
    custom_constraints = p["custom_constraints"]

    valid_attack_types = ["rce", "privilege_escalation", "persistence", "exfiltration", "xss", "sqli", "lfi", "ssrf"]
    valid_evasion_levels = ["basic", "standard", "advanced", "nation-state"]

    if attack_type not in valid_attack_types:
        attack_type = "rce"

    if evasion_level not in valid_evasion_levels:
        evasion_level = "standard"

    target_info = {
        "attack_type": attack_type,
        "complexity": "advanced",
        "technology": target_context,
        "evasion_level": evasion_level,
        "constraints": custom_constraints,
    }

    base_result = ai_payload_generator.generate_contextual_payload(target_info)

    advanced_payloads = []

    for payload_info in base_result.get("payloads", [])[:10]:
        enhanced_payload = {
            "payload": payload_info["payload"],
            "original_context": payload_info["context"],
            "risk_level": payload_info["risk_level"],
            "evasion_techniques": [],
            "deployment_methods": [],
        }

        if evasion_level in ["advanced", "nation-state"]:
            encoded_variants = [
                {
                    "technique": "Double URL Encoding",
                    "payload": payload_info["payload"].replace("%", "%25").replace(" ", "%2520"),
                },
                {
                    "technique": "Unicode Normalization",
                    "payload": payload_info["payload"].replace("script", "scrıpt"),
                },
                {
                    "technique": "Case Variation",
                    "payload": "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload_info["payload"])),
                },
            ]
            enhanced_payload["evasion_techniques"].extend(encoded_variants)

        if evasion_level == "nation-state":
            advanced_techniques = [
                {
                    "technique": "Polyglot Payload",
                    "payload": f"/*{payload_info['payload']}*/ OR {payload_info['payload']}",
                },
                {
                    "technique": "Time-delayed Execution",
                    "payload": f"setTimeout(function(){{{payload_info['payload']}}}, 1000)",
                },
                {
                    "technique": "Environmental Keying",
                    "payload": f"if(navigator.userAgent.includes('specific')){{ {payload_info['payload']} }}",
                },
            ]
            enhanced_payload["evasion_techniques"].extend(advanced_techniques)

        enhanced_payload["deployment_methods"] = [
            "Direct injection",
            "Parameter pollution",
            "Header injection",
            "Cookie manipulation",
            "Fragment-based delivery",
        ]

        advanced_payloads.append(enhanced_payload)

    deployment_guide = {
        "pre_deployment": [
            "Reconnaissance of target environment",
            "Identification of input validation mechanisms",
            "Analysis of security controls (WAF, IDS, etc.)",
            "Selection of appropriate evasion techniques",
        ],
        "deployment": [
            "Start with least detectable payloads",
            "Monitor for defensive responses",
            "Escalate evasion techniques as needed",
            "Document successful techniques for future use",
        ],
        "post_deployment": [
            "Monitor for payload execution",
            "Clean up traces if necessary",
            "Document findings",
            "Report vulnerabilities responsibly",
        ],
    }

    return {
        "success": True,
        "advanced_payload_generation": {
            "attack_type": attack_type,
            "evasion_level": evasion_level,
            "target_context": target_context,
            "payload_count": len(advanced_payloads),
            "advanced_payloads": advanced_payloads,
            "deployment_guide": deployment_guide,
            "custom_constraints_applied": custom_constraints if custom_constraints else "none",
        },
        "disclaimer": "These payloads are for authorized security testing only. Ensure proper authorization before use.",
        "timestamp": datetime.now().isoformat(),
    }


def _vulnerability_intelligence_dashboard_handler(p: dict) -> dict:
    latest_cves = _cve_monitor_handler({"hours": 24, "severity_filter": "CRITICAL", "keywords": ""})

    dashboard = {
        "timestamp": time.time(),
        "latest_critical_cves": latest_cves.get("cve_monitoring", {}).get("cves", [])[:5],
        "threat_landscape": {
            "high_risk_software": ["Apache HTTP Server", "Microsoft Exchange", "VMware vCenter", "Fortinet FortiOS"],
            "trending_attack_vectors": ["Supply chain attacks", "Cloud misconfigurations", "Zero-day exploits", "AI-powered attacks"],
            "active_threat_groups": ["APT29", "Lazarus Group", "FIN7", "REvil"],
        },
        "exploit_intelligence": {
            "new_public_exploits": "Simulated data - check exploit-db for real data",
            "weaponized_exploits": "Monitor threat intelligence feeds",
            "exploit_kits": "Track underground markets",
        },
        "recommendations": [
            "Prioritize patching for critical CVEs discovered in last 24h",
            "Monitor for zero-day activity in trending attack vectors",
            "Implement advanced threat detection for active threat groups",
            "Review security controls against nation-state level attacks",
        ],
    }

    return {"success": True, "dashboard": dashboard}


_THREAT_FOCUS_SCENARIOS = {
    "apt": [
        "Spear phishing with weaponized documents",
        "Living-off-the-land techniques",
        "Lateral movement via stolen credentials",
        "Data staging and exfiltration",
    ],
    "ransomware": [
        "Initial access via RDP/VPN",
        "Privilege escalation and persistence",
        "Shadow copy deletion",
        "Encryption and ransom note deployment",
    ],
    "insider_threat": [
        "Unusual data access patterns",
        "After-hours activity",
        "Large data downloads",
        "Access to sensitive systems",
    ],
}


def _threat_hunting_assistant_handler(p: dict) -> dict:
    target_environment = p["target_environment"]
    threat_indicators = p["threat_indicators"]
    hunt_focus = p["hunt_focus"]

    valid_hunt_focus = ["general", "apt", "ransomware", "insider_threat", "supply_chain"]
    if hunt_focus not in valid_hunt_focus:
        hunt_focus = "general"

    indicators = [i.strip() for i in threat_indicators.split(",") if i.strip()] if threat_indicators else []

    hunting_playbook = {
        "target_environment": target_environment,
        "hunt_focus": hunt_focus,
        "indicators_analyzed": indicators,
        "detection_queries": [],
        "investigation_steps": [],
        "threat_scenarios": [],
        "mitigation_strategies": [],
    }

    if "windows" in target_environment.lower():
        hunting_playbook["detection_queries"] = [
            "Get-WinEvent | Where-Object {$_.Id -eq 4688 -and $_.Message -like '*suspicious*'}",
            "Get-Process | Where-Object {$_.ProcessName -notin @('explorer.exe', 'svchost.exe')}",
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notlike '10.*'}",
        ]
    elif "cloud" in target_environment.lower():
        hunting_playbook["detection_queries"] = [
            "CloudTrail logs for unusual API calls",
            "Failed authentication attempts from unknown IPs",
            "Privilege escalation events",
            "Data exfiltration indicators",
        ]

    hunting_playbook["threat_scenarios"] = _THREAT_FOCUS_SCENARIOS.get(hunt_focus, [
        "Unauthorized access attempts",
        "Suspicious process execution",
        "Network anomalies",
        "Data access violations",
    ])

    hunting_playbook["investigation_steps"] = [
        "1. Validate initial indicators and expand IOC list",
        "2. Run detection queries and analyze results",
        "3. Correlate events across multiple data sources",
        "4. Identify affected systems and user accounts",
        "5. Assess scope and impact of potential compromise",
        "6. Implement containment measures if threat confirmed",
        "7. Document findings and update detection rules",
    ]

    if indicators:
        correlation_result = _threat_feeds_handler({
            "indicators": ",".join(indicators),
            "timeframe": "30d",
            "sources": "all",
        })
        if correlation_result.get("success"):
            hunting_playbook["threat_correlation"] = correlation_result.get("threat_intelligence", {})

    return {"success": True, "hunting_playbook": hunting_playbook}


SPECS = [
    ToolSpec(
        name="vulnx",
        mcp_tool_name="vulnx",
        endpoint="/api/vuln-intel/vulnx",
        category="vuln_intel",
        description="CVE vulnerability intelligence and analysis using vulnx.",
        params=[
            ParamSpec("cve_id", str, default="", help_text="CVE identifier (optional)"),
            ParamSpec("search", str, default="", help_text="Search string (optional)"),
            ParamSpec("auth_key", str, default="", help_text="API authentication key (optional)"),
        ],
        build_command=_vulnx_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="monitor_cve_feeds",
        mcp_tool_name="monitor_cve_feeds",
        endpoint="/api/vuln-intel/cve-monitor",
        category="vuln_intel",
        description="Monitor CVE databases for new vulnerabilities with AI analysis.",
        params=[
            ParamSpec("hours", int, default=24, help_text="Hours to look back for new CVEs (default: 24)"),
            ParamSpec(
                "severity_filter", str, default="HIGH,CRITICAL",
                help_text="Filter by CVSS severity - comma-separated values (LOW,MEDIUM,HIGH,CRITICAL,ALL)",
            ),
            ParamSpec("keywords", str, default="", help_text="Filter CVEs by keywords in description (comma-separated)"),
        ],
        handler=_cve_monitor_handler,
    ),
    ToolSpec(
        name="generate_exploit_from_cve",
        mcp_tool_name="generate_exploit_from_cve",
        endpoint="/api/vuln-intel/exploit-generate",
        category="vuln_intel",
        description="Generate working exploits from CVE information using AI-powered analysis.",
        params=[
            ParamSpec("cve_id", str, required=True, help_text="CVE identifier (e.g., CVE-2024-1234)"),
            ParamSpec("target_os", str, default="", help_text="Target operating system (windows, linux, macos, any)"),
            ParamSpec("target_arch", str, default="x64", help_text="Target architecture (x86, x64, arm, any)"),
            ParamSpec("exploit_type", str, default="poc", help_text="Type of exploit to generate (poc, weaponized, stealth)"),
            ParamSpec("evasion_level", str, default="none", help_text="Evasion sophistication (none, basic, advanced)"),
        ],
        handler=_exploit_generate_handler,
    ),
    ToolSpec(
        name="discover_attack_chains",
        mcp_tool_name="discover_attack_chains",
        endpoint="/api/vuln-intel/attack-chains",
        category="vuln_intel",
        description="Discover multi-stage attack chains for target software with vulnerability correlation.",
        params=[
            ParamSpec("target_software", str, required=True, help_text='Target software/system (e.g., "Apache HTTP Server", "Windows Server 2019")'),
            ParamSpec("attack_depth", int, default=3, help_text="Maximum number of stages in attack chain (1-5)"),
            ParamSpec("include_zero_days", bool, default=False, help_text="Include potential zero-day vulnerabilities in analysis"),
        ],
        handler=_attack_chains_handler,
    ),
    ToolSpec(
        name="research_zero_day_opportunities",
        mcp_tool_name="research_zero_day_opportunities",
        endpoint="/api/vuln-intel/zero-day-research",
        category="vuln_intel",
        description="Automated zero-day vulnerability research using AI analysis and pattern recognition.",
        params=[
            ParamSpec("target_software", str, required=True, help_text='Software to research for vulnerabilities (e.g., "nginx", "OpenSSL")'),
            ParamSpec("analysis_depth", str, default="standard", help_text="Depth of analysis (quick, standard, comprehensive)"),
            ParamSpec("source_code_url", str, default="", help_text="URL to source code repository for enhanced analysis"),
        ],
        handler=_zero_day_research_handler,
    ),
    ToolSpec(
        name="correlate_threat_intelligence",
        mcp_tool_name="correlate_threat_intelligence",
        endpoint="/api/vuln-intel/threat-feeds",
        category="vuln_intel",
        description="Correlate threat intelligence across multiple sources with advanced analysis.",
        params=[
            ParamSpec("indicators", str, required=True, help_text="Comma-separated IOCs (IPs, domains, hashes, CVEs, etc.)"),
            ParamSpec("timeframe", str, default="30d", help_text="Time window for correlation (7d, 30d, 90d, 1y)"),
            ParamSpec("sources", str, default="all", help_text="Intelligence sources to query (cve, exploit-db, github, twitter, all)"),
        ],
        handler=_threat_feeds_handler,
    ),
    ToolSpec(
        name="advanced_payload_generation",
        mcp_tool_name="advanced_payload_generation",
        endpoint="/api/ai/advanced-payload-generation",
        category="vuln_intel",
        description="Generate advanced payloads with AI-powered evasion techniques and contextual adaptation.",
        params=[
            ParamSpec("attack_type", str, required=True, help_text="Type of attack (rce, privilege_escalation, persistence, exfiltration, xss, sqli)"),
            ParamSpec("target_context", str, default="", help_text="Target environment details (OS, software versions, security controls)"),
            ParamSpec("evasion_level", str, default="standard", help_text="Evasion sophistication (basic, standard, advanced, nation-state)"),
            ParamSpec("custom_constraints", str, default="", help_text="Custom payload constraints (size limits, character restrictions, etc.)"),
        ],
        handler=_advanced_payload_generation_handler,
    ),
    ToolSpec(
        name="vulnerability_intelligence_dashboard",
        mcp_tool_name="vulnerability_intelligence_dashboard",
        endpoint="/api/vuln-intel/dashboard",
        category="vuln_intel",
        description="Get a comprehensive vulnerability intelligence dashboard with latest threats and trends.",
        params=[],
        handler=_vulnerability_intelligence_dashboard_handler,
    ),
    ToolSpec(
        name="threat_hunting_assistant",
        mcp_tool_name="threat_hunting_assistant",
        endpoint="/api/vuln-intel/threat-hunting-assistant",
        category="vuln_intel",
        description="AI-powered threat hunting assistant with vulnerability correlation and attack simulation.",
        params=[
            ParamSpec("target_environment", str, required=True, help_text='Environment to hunt in (e.g., "Windows Domain", "Cloud Infrastructure")'),
            ParamSpec("threat_indicators", str, default="", help_text="Known IOCs or suspicious indicators to investigate"),
            ParamSpec("hunt_focus", str, default="general", help_text="Focus area (general, apt, ransomware, insider_threat, supply_chain)"),
        ],
        handler=_threat_hunting_assistant_handler,
    ),
]
