import logging
import shlex
from datetime import datetime

from backend.server_api.web_framework.browser_agent import browser_agent
from backend.server_api.web_framework.http_framework import http_framework
from backend.server_core import ModernVisualEngine
from backend.server_core.tool_spec import ParamSpec, ToolSpec, ToolValidationError

logger = logging.getLogger(__name__)


def _bool(val) -> bool:
    """Coerce UI values to bool. Handles True/False, 'true'/'false', 1/0."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() == "true"
    return bool(val)


def _findings_as_success_postprocess(raw, params: dict) -> dict:
    if raw.get("return_code") == 1:
        raw["success"] = True
    return raw


def _burpsuite_alternative_handler(p: dict) -> dict:
    target = p["target"]
    scan_type = p["scan_type"]
    headless = p["headless"]
    max_depth = p["max_depth"]
    max_pages = p["max_pages"]

    logger.info(ModernVisualEngine.create_section_header("BURP SUITE ALTERNATIVE", "🔥", "BLOOD_RED"))
    logger.info(ModernVisualEngine.format_highlighted_text(f"Starting {scan_type} scan of {target}", "RED"))

    results = {
        "target": target,
        "scan_type": scan_type,
        "timestamp": datetime.now().isoformat(),
        "success": True,
    }

    if scan_type in ("comprehensive", "spider"):
        logger.info(ModernVisualEngine.format_tool_status("BrowserAgent", "RUNNING", "Reconnaissance Phase"))
        with browser_agent.lock:
            if not browser_agent.driver:
                browser_agent.setup_browser(headless)
            results["browser_analysis"] = browser_agent.navigate_and_inspect(target)

    if scan_type in ("comprehensive", "spider"):
        logger.info(ModernVisualEngine.format_tool_status("HTTP-Spider", "RUNNING", "Discovery Phase"))
        results["spider_analysis"] = http_framework.spider_website(target, max_depth, max_pages)

    if scan_type in ("comprehensive", "active"):
        logger.info(ModernVisualEngine.format_tool_status("VulnScanner", "RUNNING", "Analysis Phase"))
        discovered_urls = results.get("spider_analysis", {}).get("discovered_urls", [target])
        vuln_results = []
        for url in discovered_urls[:20]:
            test_result = http_framework.intercept_request(url)
            if test_result.get("success"):
                vuln_results.append(test_result)
        results["vulnerability_analysis"] = {
            "tested_urls": len(vuln_results),
            "total_vulnerabilities": len(http_framework.vulnerabilities),
            "recent_vulnerabilities": http_framework._get_recent_vulns(20),
        }

    total_vulns = len(http_framework.vulnerabilities)
    vuln_summary = {}
    for vuln in http_framework.vulnerabilities:
        severity = vuln.get("severity", "unknown")
        vuln_summary[severity] = vuln_summary.get(severity, 0) + 1

    results["summary"] = {
        "total_vulnerabilities": total_vulns,
        "vulnerability_breakdown": vuln_summary,
        "pages_analyzed": len(results.get("spider_analysis", {}).get("discovered_urls", [])),
        "security_score": max(0, 100 - (total_vulns * 5)),
    }

    logger.info(ModernVisualEngine.create_section_header("SCAN COMPLETE", "✅", "SUCCESS"))
    logger.info(ModernVisualEngine.format_highlighted_text(
        f"Found {total_vulns} vulnerabilities", "YELLOW" if total_vulns > 0 else "GREEN"
    ))
    for severity, count in vuln_summary.items():
        logger.info(f"  {ModernVisualEngine.format_vulnerability_severity(severity, count)}")

    return results


def _breachsql_command(p: dict) -> str:
    argv = ["breachsql", "-u", p["url"]]
    if p["data"]:
        argv.append("-d")
        argv.append(p["data"])
    for header in (p["headers"] or {}).items():
        argv.append("-H")
        argv.append(f"{header[0]}:{header[1]}")
    if p["cookies"]:
        argv.append("-c")
        argv.append(p["cookies"])
    if p["proxy"]:
        argv.append("--proxy")
        argv.append(p["proxy"])
    if p["threads"] and int(p["threads"]) != 5:
        argv.append("-t")
        argv.append(str(int(p["threads"])))
    if p["timeout"] and int(p["timeout"]) != 15:
        argv.append("--timeout")
        argv.append(str(int(p["timeout"])))
    if p["level"] and int(p["level"]) != 1:
        argv.append("--level")
        argv.append(str(int(p["level"])))
    if p["dbms"] and p["dbms"] != "auto":
        argv.append("--dbms")
        argv.append(p["dbms"])
    if p["technique"] and p["technique"] != "EBTUO":
        argv.append("--technique")
        argv.append(p["technique"])
    if p["time_threshold"] and int(p["time_threshold"]) != 4:
        argv.append("--time-threshold")
        argv.append(str(int(p["time_threshold"])))
    if p["risk"] and int(p["risk"]) != 1:
        argv.append("--risk")
        argv.append(str(int(p["risk"])))
    if p["path_params"]:
        argv.append("--path-params")
        argv.append(",".join(p["path_params"]))
    if p["cookie_params"]:
        argv.append("--cookie-params")
        argv.append(",".join(p["cookie_params"]))
    if p["header_params"]:
        argv.append("--header-params")
        argv.append(",".join(p["header_params"]))
    if _bool(p["exploit"]):
        argv.append("--exploit")
    if p["dump"]:
        argv.append("--dump")
        argv.append(p["dump"])
    if _bool(p["dump_all"]):
        argv.append("--dump-all")
    if _bool(p["crawl"]):
        argv.append("--crawl")
    if p["max_pages"] and int(p["max_pages"]) != 100:
        argv.append("--max-pages")
        argv.append(str(int(p["max_pages"])))
    if p["max_depth"] and int(p["max_depth"]) != 3:
        argv.append("--max-depth")
        argv.append(str(int(p["max_depth"])))
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _dalfox_command(p: dict) -> str:
    url, pipe_mode = p["url"], p["pipe_mode"]
    if not url and not pipe_mode:
        raise ToolValidationError("URL parameter is required")

    argv = ["dalfox", "pipe"] if pipe_mode else ["dalfox", "url", url]
    if p["blind"]:
        argv.append("--blind")
    if p["mining_dom"]:
        argv.append("--dom")
    if p["mining_dict"]:
        argv.append("--mining-dict")
    if p["custom_payload"]:
        argv.append("--custom-payload")
        argv.append(p["custom_payload"])
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _interactsh_command(p: dict) -> str:
    argv = ["interactsh-client", "-json", "-n", str(p["n"]), "-pi", str(p["poll_interval"])]
    if p["server"]:
        argv.append("-server")
        argv.append(p["server"])
    if p["token"]:
        argv.append("-token")
        argv.append(p["token"])
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _jaeles_command(p: dict) -> str:
    argv = ["jaeles", "scan", "-u", p["url"], "-c", str(p["threads"]), "--timeout", str(p["timeout"])]
    if p["signatures"]:
        argv.append("-s")
        argv.append(p["signatures"])
    if p["config"]:
        argv.append("--config")
        argv.append(p["config"])
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _joomscan_command(p: dict) -> str:
    argv = ["joomscan", "--url", p["url"]]
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _nikto_command(p: dict) -> str:
    argv = ["nikto", "-h", p["target"]]
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _phaseaccess_command(p: dict) -> str:
    argv = ["phaseaccess", "-u", p["target"], "--json", "-q"]

    method = p["method"]
    if method and method != "GET":
        argv.append("-X")
        argv.append(method)
    if p["body"]:
        argv.append("-d")
        argv.append(p["body"])

    for key, val in (p["session_a_headers"] or {}).items():
        argv.append("-H")
        argv.append(f"{key}:{val}")
    if p["session_a_cookies"]:
        argv.append("-c")
        argv.append(p["session_a_cookies"])
    label_a = p["session_a_label"]
    if label_a and label_a != "session_a":
        argv.append("--label-a")
        argv.append(label_a)

    for key, val in (p["session_b_headers"] or {}).items():
        argv.append("--header-b")
        argv.append(f"{key}:{val}")
    if p["session_b_cookies"]:
        argv.append("--cookie-b")
        argv.append(p["session_b_cookies"])
    if p["session_b_label"]:
        argv.append("--label-b")
        argv.append(p["session_b_label"])

    if p["login_url"]:
        argv.append("--login-url")
        argv.append(p["login_url"])
    if p["login_user"]:
        argv.append("--login-user")
        argv.append(p["login_user"])
    if p["login_pass"]:
        argv.append("--login-pass")
        argv.append(p["login_pass"])
    if p["login_user_field"]:
        argv.append("--login-user-field")
        argv.append(p["login_user_field"])
    if p["login_pass_field"]:
        argv.append("--login-pass-field")
        argv.append(p["login_pass_field"])

    if p["login_url_b"]:
        argv.append("--login-url-b")
        argv.append(p["login_url_b"])
    if p["login_user_b"]:
        argv.append("--login-user-b")
        argv.append(p["login_user_b"])
    if p["login_pass_b"]:
        argv.append("--login-pass-b")
        argv.append(p["login_pass_b"])

    if _bool(p["crawl"]):
        argv.append("--crawl")
    if p["crawl_depth"] and int(p["crawl_depth"]) != 3:
        argv.append("--crawl-depth")
        argv.append(str(int(p["crawl_depth"])))
    if p["crawl_pages"] and int(p["crawl_pages"]) != 100:
        argv.append("--crawl-pages")
        argv.append(str(int(p["crawl_pages"])))
    if _bool(p["browser_crawl"]):
        argv.append("--browser-crawl")
    if _bool(p["auto_login"]):
        argv.append("--auto-login")

    if p["openapi"]:
        argv.append("--openapi")
        argv.append(p["openapi"])
    if p["base_url"]:
        argv.append("--base-url")
        argv.append(p["base_url"])
    if p["targets"]:
        argv.append("--targets")
        argv.append(p["targets"])

    if p["chain_create"]:
        argv.append("--chain-create")
        argv.append(p["chain_create"])
    if p["chain_body"]:
        argv.append("--chain-body")
        argv.append(p["chain_body"])
    if p["chain_read"]:
        argv.append("--chain-read")
        argv.append(p["chain_read"])

    if p["proxy"]:
        argv.append("--proxy")
        argv.append(p["proxy"])
    if not _bool(p["verify_ssl"]):
        argv.append("--insecure")
    if p["delay"] and float(p["delay"]) > 0:
        argv.append("--delay")
        argv.append(str(float(p["delay"])))
    if p["threads"] and int(p["threads"]) != 5:
        argv.append("-t")
        argv.append(str(int(p["threads"])))
    if p["timeout"] and int(p["timeout"]) != 15:
        argv.append("--timeout")
        argv.append(str(int(p["timeout"])))
    if p["user_agent"]:
        argv.append("--user-agent")
        argv.append(p["user_agent"])

    if p["max_candidates"] and int(p["max_candidates"]) != 10:
        argv.append("--max-candidates")
        argv.append(str(int(p["max_candidates"])))
    if p["min_confidence"]:
        argv.append("--min-confidence")
        argv.append(p["min_confidence"])
    if not _bool(p["method_bypass"]):
        argv.append("--no-method-bypass")
    if not _bool(p["param_pollution"]):
        argv.append("--no-param-pollution")
    if not _bool(p["mass_assignment"]):
        argv.append("--no-mass-assignment")
    if not _bool(p["soft_delete"]):
        argv.append("--no-soft-delete")
    if not _bool(p["blind_idor"]):
        argv.append("--no-blind-idor")

    for extra_url in (p["extra_urls"] or []):
        argv.append("--extra-url")
        argv.append(extra_url)

    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _sqlmap_command(p: dict) -> str:
    argv = ["sqlmap", "-u", p["url"], "--batch"]
    if p["data"]:
        argv.append(f"--data={p['data']}")
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _stingxss_command(p: dict) -> str:
    argv = ["stingxss", "-u", p["url"]]
    if p["data"]:
        argv.append("-d")
        argv.append(p["data"])
    for key, val in (p["headers"] or {}).items():
        argv.append("-H")
        argv.append(f"{key}:{val}")
    if p["cookies"]:
        argv.append("-c")
        argv.append(p["cookies"])
    if p["proxy"]:
        argv.append("--proxy")
        argv.append(p["proxy"])
    if p["threads"] and int(p["threads"]) != 5:
        argv.append("-t")
        argv.append(str(int(p["threads"])))
    if p["timeout"] and int(p["timeout"]) != 15:
        argv.append("--timeout")
        argv.append(str(int(p["timeout"])))
    if p["level"] and int(p["level"]) != 1:
        argv.append("--level")
        argv.append(str(int(p["level"])))
    if _bool(p["crawl"]):
        argv.append("--crawl")
    if p["max_pages"] and int(p["max_pages"]) != 50:
        argv.append("--max-pages")
        argv.append(str(int(p["max_pages"])))
    if p["max_depth"] and int(p["max_depth"]) != 3:
        argv.append("--max-depth")
        argv.append(str(int(p["max_depth"])))
    if p["blind_callback"]:
        argv.append("--blind")
        argv.append(p["blind_callback"])
    if _bool(p["browser"]):
        argv.append("--browser")
        if not _bool(p["browser_headless"]):
            argv.append("--no-browser-headless")
    if _bool(p["test_stored"]):
        argv.append("--test-stored")
    if _bool(p["poc"]):
        argv.append("--poc")
    for header in (p["inject_headers"] or []):
        argv.append("--inject-headers")
        argv.append(header)
    # custom_payloads is a list — only supported via file; accepted but a no-op, matches Flask
    if not _bool(p["probe_filter"]):
        argv.append("--no-probe-filter")
    if _bool(p["graphql"]):
        argv.append("--graphql")
    if _bool(p["websocket"]):
        argv.append("--websocket")
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _whatweb_command(p: dict) -> str:
    return shlex.join(["whatweb", "-v", "-a", "3", p["url"]])


def _wpscan_command(p: dict) -> str:
    argv = ["wpscan", "--url", p["url"]]
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _xsser_command(p: dict) -> str:
    argv = ["xsser", "--url", p["url"]]
    if p["params"]:
        argv.append(f"--param={p['params']}")
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _zap_command(p: dict) -> str:
    target, scan_type = p["target"], p["scan_type"]
    if not target and scan_type != "daemon":
        raise ToolValidationError("Target parameter is required for scans")

    if p["daemon"]:
        argv = ["zaproxy", "-daemon", "-host", p["host"], "-port", str(p["port"])]
        if p["api_key"]:
            argv.append("-config")
            argv.append(f"api.key={p['api_key']}")
    else:
        argv = ["zaproxy", "-cmd", "-quickurl", target]
        if p["format"]:
            argv.append("-quickout")
            argv.append(p["format"])
        if p["output_file"]:
            argv.append("-quickprogress")
            argv.append("-dir")
            argv.append(p["output_file"])
        if p["api_key"]:
            argv.append("-config")
            argv.append(f"api.key={p['api_key']}")

    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


SPECS = [
    ToolSpec(
        name="burpsuite_alternative",
        mcp_tool_name="burpsuite_alternative_scan",
        endpoint="/api/tools/burpsuite-alternative",
        category="web_scan",
        description=(
            "Comprehensive Burp Suite alternative combining HTTP framework and browser agent "
            "for complete web security testing."
        ),
        params=[
            ParamSpec("target", str, required=True, help_text="Target URL or domain to scan"),
            ParamSpec("scan_type", str, default="comprehensive", help_text="Type of scan (comprehensive, spider, passive, active)"),
            ParamSpec("headless", bool, default=True, help_text="Run browser in headless mode"),
            ParamSpec("max_depth", int, default=3, help_text="Maximum crawling depth"),
            ParamSpec("max_pages", int, default=50, help_text="Maximum pages to analyze"),
        ],
        handler=_burpsuite_alternative_handler,
    ),
    ToolSpec(
        name="breachsql",
        mcp_tool_name="breachsql_scan",
        endpoint="/api/tools/breachsql",
        category="web_scan",
        description="Run BreachSQL SQL injection detection and exploitation.",
        params=[
            ParamSpec("url", str, required=True, help_text="Target URL (include the vulnerable parameter, e.g. /item?id=1)"),
            ParamSpec("data", str, default="", help_text="POST body (URL-encoded or JSON string)"),
            ParamSpec("headers", dict, default={}, help_text="Extra request headers as a dict"),
            ParamSpec("cookies", str, default="", help_text="Cookie header string"),
            ParamSpec("proxy", str, default="", help_text="HTTP proxy URL"),
            ParamSpec("threads", int, default=5, help_text="Concurrent threads (1-20)"),
            ParamSpec("timeout", int, default=15, help_text="Request timeout in seconds"),
            ParamSpec("level", int, default=1, help_text="Scan depth (1=params only, 2=+headers, 3=+cookies)"),
            ParamSpec("dbms", str, default="auto", help_text="Force backend (auto|mysql|mssql|postgres|sqlite|oracle)"),
            ParamSpec("technique", str, default="EBTUO", help_text="Detection techniques (letters: E=error B=boolean T=time U=union O=oob)"),
            ParamSpec("time_threshold", int, default=4, help_text="Seconds before a time-based injection is flagged"),
            ParamSpec("risk", int, default=1, help_text="Payload risk level (1-3)"),
            ParamSpec("path_params", list, default=[], help_text="Path segment names to inject (e.g. ['id'])"),
            ParamSpec("cookie_params", list, default=[], help_text="Cookie names to inject into"),
            ParamSpec("header_params", list, default=[], help_text="HTTP header names to inject into"),
            ParamSpec("exploit", bool, default=False, help_text="After detection, dump version/user/db/tables automatically"),
            ParamSpec("dump", str, default="", help_text="Table name to dump rows from"),
            ParamSpec("dump_all", bool, default=False, help_text="Dump every discovered table"),
            ParamSpec("crawl", bool, default=False, help_text="Crawl the site and test discovered endpoints"),
            ParamSpec("max_pages", int, default=100, help_text="Max pages to crawl"),
            ParamSpec("max_depth", int, default=3, help_text="Crawl depth limit"),
            ParamSpec("additional_args", str, default="", help_text="Additional BreachSQL arguments"),
        ],
        build_command=_breachsql_command,
        postprocess=_findings_as_success_postprocess,
        use_recovery=True,
    ),
    ToolSpec(
        name="dalfox",
        mcp_tool_name="dalfox_xss_scan",
        endpoint="/api/tools/dalfox",
        category="web_scan",
        description="Execute Dalfox for advanced XSS vulnerability scanning.",
        params=[
            ParamSpec("url", str, default="", help_text="The target URL"),
            ParamSpec("pipe_mode", bool, default=False, help_text="Use pipe mode for input"),
            ParamSpec("blind", bool, default=False, help_text="Enable blind XSS testing"),
            ParamSpec("mining_dom", bool, default=True, help_text="Enable DOM mining"),
            ParamSpec("mining_dict", bool, default=True, help_text="Enable dictionary mining"),
            ParamSpec("custom_payload", str, default="", help_text="Custom XSS payload"),
            ParamSpec("additional_args", str, default="", help_text="Additional Dalfox arguments"),
        ],
        build_command=_dalfox_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="interactsh",
        mcp_tool_name="interactsh_client",
        endpoint="/api/tools/web_scan/interactsh",
        category="web_scan",
        description="Run interactsh-client to generate OOB interaction URLs and capture out-of-band interactions.",
        params=[
            ParamSpec("server", str, default="", help_text="Custom interactsh server URL"),
            ParamSpec("token", str, default="", help_text="Authentication token for private server"),
            ParamSpec("n", int, default=1, help_text="Number of interaction payload URLs to generate"),
            ParamSpec("poll_interval", int, default=5, help_text="Polling interval in seconds between interaction checks"),
            ParamSpec("timeout", int, default=60, help_text="Total time in seconds to listen for interactions before exiting"),
            ParamSpec("additional_args", str, default="", help_text="Additional interactsh-client flags"),
        ],
        build_command=_interactsh_command,
        timeout_param="timeout",
        use_recovery=True,
    ),
    ToolSpec(
        name="jaeles",
        mcp_tool_name="jaeles_vulnerability_scan",
        endpoint="/api/tools/jaeles",
        category="web_scan",
        description="Execute Jaeles for advanced vulnerability scanning with custom signatures.",
        params=[
            ParamSpec("url", str, required=True, help_text="The target URL"),
            ParamSpec("signatures", str, default="", help_text="Custom signature path"),
            ParamSpec("config", str, default="", help_text="Configuration file"),
            ParamSpec("threads", int, default=20, help_text="Number of threads"),
            ParamSpec("timeout", int, default=20, help_text="Request timeout"),
            ParamSpec("additional_args", str, default="", help_text="Additional Jaeles arguments"),
        ],
        build_command=_jaeles_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="joomscan",
        mcp_tool_name="joomscan_analyze",
        endpoint="/api/tools/web_recon/joomscan",
        category="web_scan",
        description="Execute Joomscan for Joomla vulnerability scanning.",
        params=[
            ParamSpec("url", str, required=True, help_text="The Joomla site URL"),
            ParamSpec("additional_args", str, default="", help_text="Additional Joomscan arguments"),
        ],
        build_command=_joomscan_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="nikto",
        mcp_tool_name="nikto_scan",
        endpoint="/api/tools/nikto",
        category="web_scan",
        description="Execute Nikto web vulnerability scanner.",
        params=[
            ParamSpec("target", str, required=True, help_text="The target URL or IP"),
            ParamSpec("additional_args", str, default="", help_text="Additional Nikto arguments"),
        ],
        build_command=_nikto_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="phaseaccess",
        mcp_tool_name="phaseaccess_scan",
        endpoint="/api/tools/phaseaccess",
        category="web_scan",
        description="Run PhaseAccess IDOR/BOLA scanner.",
        params=[
            ParamSpec("target", str, required=True, help_text="Primary target URL (e.g. http://app.example.invalid/users/42)"),
            ParamSpec("session_a_headers", dict, default={}, help_text="Auth headers for session A"),
            ParamSpec("session_a_cookies", str, default="", help_text="Cookie string for session A"),
            ParamSpec("session_a_label", str, default="session_a", help_text="Human label for session A shown in findings"),
            ParamSpec("session_b_headers", dict, default={}, help_text="Auth headers for session B — enables dual-session mode"),
            ParamSpec("session_b_cookies", str, default="", help_text="Cookie string for session B"),
            ParamSpec("session_b_label", str, default="", help_text="Label for session B — leave empty for single-session"),
            ParamSpec("method", str, default="GET", help_text="HTTP method for the primary target"),
            ParamSpec("body", str, default="", help_text="Request body for POST/PUT endpoints"),
            ParamSpec("login_url", str, default="", help_text="Login form URL to authenticate session A"),
            ParamSpec("login_user", str, default="", help_text="Username for session A form login"),
            ParamSpec("login_pass", str, default="", help_text="Password for session A form login"),
            ParamSpec("login_user_field", str, default="", help_text="Form field name for the username"),
            ParamSpec("login_pass_field", str, default="", help_text="Form field name for the password"),
            ParamSpec("login_url_b", str, default="", help_text="Login form URL for session B"),
            ParamSpec("login_user_b", str, default="", help_text="Username for session B form login"),
            ParamSpec("login_pass_b", str, default="", help_text="Password for session B form login"),
            ParamSpec("crawl", bool, default=False, help_text="Crawl target before scanning to auto-discover endpoints"),
            ParamSpec("crawl_depth", int, default=3, help_text="Crawler max depth"),
            ParamSpec("crawl_pages", int, default=100, help_text="Crawler max pages"),
            ParamSpec("browser_crawl", bool, default=False, help_text="Use headless Chromium for JS-rendered SPA discovery"),
            ParamSpec("auto_login", bool, default=False, help_text="Auto-discover login endpoints during crawl and authenticate both sessions"),
            ParamSpec("openapi", str, default="", help_text="OpenAPI/Swagger spec path or URL"),
            ParamSpec("base_url", str, default="", help_text="Base URL override for OpenAPI spec"),
            ParamSpec("targets", str, default="", help_text="Import endpoints from a HAR file or Burp Suite XML export"),
            ParamSpec("chain_create", str, default="", help_text="Stored IDOR create endpoint, format METHOD:URL"),
            ParamSpec("chain_body", str, default="", help_text="Request body for --chain-create"),
            ParamSpec("chain_read", str, default="", help_text="Stored IDOR read URL template"),
            ParamSpec("proxy", str, default="", help_text="HTTP proxy URL"),
            ParamSpec("verify_ssl", bool, default=True, help_text="Verify TLS certificates"),
            ParamSpec("delay", float, default=0.0, help_text="Seconds between requests"),
            ParamSpec("threads", int, default=5, help_text="Concurrent request threads"),
            ParamSpec("timeout", int, default=15, help_text="Request timeout in seconds"),
            ParamSpec("user_agent", str, default="", help_text="Override User-Agent"),
            ParamSpec("max_candidates", int, default=10, help_text="Max tamper candidates per discovered ID parameter"),
            ParamSpec("min_confidence", str, default="", help_text="Minimum confidence to report (confirmed|high|medium|low|info)"),
            ParamSpec("method_bypass", bool, default=True, help_text="Test HTTP method bypass variants"),
            ParamSpec("param_pollution", bool, default=True, help_text="Test HTTP parameter pollution"),
            ParamSpec("mass_assignment", bool, default=True, help_text="Test mass assignment on JSON body endpoints"),
            ParamSpec("soft_delete", bool, default=True, help_text="Test soft-delete bypass via hint parameters"),
            ParamSpec("blind_idor", bool, default=True, help_text="Flag blind IDOR via status-only signals"),
            ParamSpec("extra_urls", list, default=[], help_text="Additional URLs to test alongside the primary target"),
            ParamSpec("additional_args", str, default="", help_text="Additional PhaseAccess arguments"),
        ],
        build_command=_phaseaccess_command,
        postprocess=_findings_as_success_postprocess,
        use_recovery=True,
    ),
    ToolSpec(
        name="sqlmap",
        mcp_tool_name="sqlmap_scan",
        endpoint="/api/tools/sqlmap",
        category="web_scan",
        description="Execute SQLMap for SQL injection testing.",
        params=[
            ParamSpec("url", str, required=True, help_text="The target URL"),
            ParamSpec("data", str, default="", help_text="POST data for testing"),
            ParamSpec("additional_args", str, default="", help_text="Additional SQLMap arguments"),
        ],
        build_command=_sqlmap_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="stingxss",
        mcp_tool_name="stingxss_scan",
        endpoint="/api/tools/stingxss",
        category="web_scan",
        description="Run StingXSS context-aware XSS scanner.",
        params=[
            ParamSpec("url", str, required=True, help_text="Target URL"),
            ParamSpec("data", str, default="", help_text="POST body for form/API endpoints"),
            ParamSpec("headers", dict, default={}, help_text="Extra request headers"),
            ParamSpec("cookies", str, default="", help_text="Cookie header string"),
            ParamSpec("proxy", str, default="", help_text="HTTP proxy URL"),
            ParamSpec("threads", int, default=5, help_text="Concurrent threads (1-20)"),
            ParamSpec("timeout", int, default=15, help_text="Request timeout in seconds"),
            ParamSpec("level", int, default=1, help_text="Scan depth (1=query params, 2=+headers, 3=+cookies)"),
            ParamSpec("crawl", bool, default=False, help_text="Crawl the site and test all discovered endpoints"),
            ParamSpec("max_pages", int, default=50, help_text="Max pages to crawl"),
            ParamSpec("max_depth", int, default=3, help_text="Crawl depth limit"),
            ParamSpec("blind_callback", str, default="", help_text="OOB callback URL for blind XSS"),
            ParamSpec("browser", bool, default=False, help_text="Confirm XSS execution via headless Chromium"),
            ParamSpec("browser_headless", bool, default=True, help_text="Run browser in headless mode"),
            ParamSpec("test_stored", bool, default=False, help_text="Attempt stored XSS detection"),
            ParamSpec("poc", bool, default=False, help_text="Generate ready-to-use PoC payloads for confirmed findings"),
            ParamSpec("inject_headers", list, default=[], help_text="HTTP header names to inject into"),
            ParamSpec("custom_payloads", list, default=[], help_text="Additional payloads (accepted, list form currently unsupported server-side)"),
            ParamSpec("probe_filter", bool, default=True, help_text="Pre-probe each parameter to filter unusable payloads"),
            ParamSpec("graphql", bool, default=False, help_text="Test GraphQL endpoints discovered or specified"),
            ParamSpec("websocket", bool, default=False, help_text="Test WebSocket endpoints"),
            ParamSpec("additional_args", str, default="", help_text="Additional StingXSS arguments"),
        ],
        build_command=_stingxss_command,
        postprocess=_findings_as_success_postprocess,
        use_recovery=True,
    ),
    ToolSpec(
        name="whatweb",
        mcp_tool_name="whatweb_analyze",
        endpoint="/api/tools/web_recon/whatweb",
        category="web_scan",
        description="Execute WhatWeb for web technology fingerprinting.",
        params=[
            ParamSpec("url", str, required=True, help_text="The target website URL"),
        ],
        build_command=_whatweb_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="wpscan",
        mcp_tool_name="wpscan_analyze",
        endpoint="/api/tools/wpscan",
        category="web_scan",
        description="Execute WPScan for WordPress vulnerability scanning.",
        params=[
            ParamSpec("url", str, required=True, help_text="The WordPress site URL"),
            ParamSpec("additional_args", str, default="", help_text="Additional WPScan arguments"),
        ],
        build_command=_wpscan_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="xsser",
        mcp_tool_name="xsser_scan",
        endpoint="/api/tools/xsser",
        category="web_scan",
        description="Execute XSSer for XSS vulnerability testing.",
        params=[
            ParamSpec("url", str, required=True, help_text="The target URL"),
            ParamSpec("params", str, default="", help_text="Parameters to test"),
            ParamSpec("additional_args", str, default="", help_text="Additional XSSer arguments"),
        ],
        build_command=_xsser_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="zap",
        mcp_tool_name="zap_scan",
        endpoint="/api/tools/zap",
        category="web_scan",
        description="Execute OWASP ZAP.",
        params=[
            ParamSpec("target", str, default="", help_text="Target URL"),
            ParamSpec("scan_type", str, default="baseline", help_text="Type of scan (baseline, full, api)"),
            ParamSpec("api_key", str, default="", help_text="ZAP API key"),
            ParamSpec("daemon", bool, default=False, help_text="Run in daemon mode"),
            ParamSpec("port", str, default="8090", help_text="Port for ZAP daemon"),
            ParamSpec("host", str, default="0.0.0.0", help_text="Host for ZAP daemon"),
            ParamSpec("format", str, default="xml", help_text="Output format (xml, json, html)"),
            ParamSpec("output_file", str, default="", help_text="Output file path"),
            ParamSpec("additional_args", str, default="", help_text="Additional ZAP arguments"),
        ],
        build_command=_zap_command,
        use_recovery=True,
    ),
]
