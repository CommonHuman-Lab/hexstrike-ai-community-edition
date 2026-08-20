import logging
import re
import time
from datetime import datetime
from urllib.parse import urlparse

from commonhuman_core.js_api_discover import js_api_discover
from commonhuman_core.source_map import fetch_source_maps
from commonhuman_core.ws import WEBSOCKET_AVAILABLE, discover_ws_urls, ws_inject
from backend.server_api.web_framework.browser_agent import browser_agent
from backend.server_api.web_framework.http_framework import http_framework
from backend.server_core import ModernVisualEngine
from backend.server_core.tool_spec import ParamSpec, ToolSpec, ToolValidationError

logger = logging.getLogger(__name__)

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src="([^"]*\.js[^"]*)"', re.IGNORECASE)
_WS_HOST_CONCAT_RE = re.compile(
    r"""new\s+WebSocket\s*\(\s*['"`]wss?://['"`]\s*\+\s*(?:window\.)?location\.host\s*\+\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)


def _discover_ws_host_concat(text: str, page_url: str) -> list:
    parsed = urlparse(page_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return [f"{scheme}://{parsed.netloc}{m.group(1)}" for m in _WS_HOST_CONCAT_RE.finditer(text)]


def _browser_agent_handler(p: dict) -> dict:
    action = p["action"]
    url = p["url"]
    headless = p["headless"]
    wait_time = p["wait_time"]
    proxy_port = p.get("proxy_port") or None
    active_tests = p["active_tests"]

    logger.info(ModernVisualEngine.create_section_header("BROWSER AGENT", "🌐", "CRIMSON"))

    if action == "navigate":
        if not url:
            raise ToolValidationError("URL parameter is required for navigate action")

        with browser_agent.lock:
            if not browser_agent.driver:
                if not browser_agent.setup_browser(headless, proxy_port):
                    raise RuntimeError("Failed to setup browser")

            result = browser_agent.navigate_and_inspect(url, wait_time)
        if result.get("success") and active_tests:
            active_results = browser_agent.run_active_tests(result.get("page_info", {}))
            result["active_tests"] = active_results
            if active_results["active_findings"]:
                logger.warning(ModernVisualEngine.format_error_card(
                    "WARNING", "BrowserAgent", f"Active findings: {len(active_results['active_findings'])}",
                ))
        return result

    elif action == "screenshot":
        result = browser_agent.take_screenshot()
        if not result.get("success"):
            raise ToolValidationError(result.get("error", "Browser not initialized. Use navigate action first."))
        return result

    elif action == "close":
        browser_agent.close_browser()
        return {"success": True, "message": "Browser closed successfully"}

    elif action == "status":
        return browser_agent.get_status()

    raise ToolValidationError(f"Unknown action: {action}")


def _http_request_handler(p: dict) -> dict:
    url = p["url"]
    if not url:
        raise ToolValidationError("URL parameter is required for request action")
    return http_framework.intercept_request(url, p["method"], p["data"], p["headers"], p["cookies"])


def _http_spider_handler(p: dict) -> dict:
    url = p["url"]
    if not url:
        raise ToolValidationError("URL parameter is required for spider action")
    return http_framework.spider_website(url, p["max_depth"], p["max_pages"])


def _js_api_discover_handler(p: dict) -> dict:
    url = p["url"]
    if not url:
        raise ToolValidationError("URL parameter is required")
    endpoints = js_api_discover(url, session=http_framework.session, max_bundles=p["max_bundles"])
    return {
        "success": True,
        "endpoints": [{"method": m, "url": u, "template": t} for m, u, t in endpoints],
        "total": len(endpoints),
    }


def _source_map_recover_handler(p: dict) -> dict:
    url = p["url"]
    if not url:
        raise ToolValidationError("URL parameter is required")

    js_urls = list(p["js_urls"])
    if not js_urls:
        try:
            page = http_framework.session.get(url, timeout=15)
        except Exception as e:
            raise ToolValidationError(f"Failed to fetch {url}: {e}")
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for src in _SCRIPT_SRC_RE.findall(page.text):
            js_urls.append(src if src.startswith("http") else origin.rstrip("/") + "/" + src.lstrip("/"))

    if not js_urls:
        return {"success": False, "error": "No JavaScript bundle URLs found on the page or provided explicitly"}

    result = fetch_source_maps(
        js_urls,
        fetcher=lambda u: http_framework.session.get(u, timeout=15).text,
        base_url=url,
        max_maps=p["max_maps"],
    )

    max_chars = p["max_source_chars"]
    sources = {
        path: (text if len(text) <= max_chars else text[:max_chars] + "...[truncated]")
        for path, text in result.sources.items()
    }

    return {
        "success": len(result) > 0,
        "js_bundles_probed": len(js_urls),
        "total_sources_recovered": len(result),
        "mapping": result.mapping,
        "sources": sources,
    }


def _ws_discover_handler(p: dict) -> dict:
    url = p["url"]
    if not url:
        raise ToolValidationError("URL parameter is required")

    try:
        page = http_framework.session.get(url, timeout=15)
    except Exception as e:
        raise ToolValidationError(f"Failed to fetch {url}: {e}")

    found = discover_ws_urls(page.text, base_url=url)
    for ws_url in _discover_ws_host_concat(page.text, url):
        if ws_url not in found:
            found.append(ws_url)

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    js_urls = [
        src if src.startswith("http") else origin.rstrip("/") + "/" + src.lstrip("/")
        for src in _SCRIPT_SRC_RE.findall(page.text)
    ]
    for js_url in js_urls[: p["max_bundles"]]:
        try:
            js_text = http_framework.session.get(js_url, timeout=15).text
        except Exception:
            continue
        for ws_url in discover_ws_urls(js_text, base_url=url):
            if ws_url not in found:
                found.append(ws_url)
        for ws_url in _discover_ws_host_concat(js_text, url):
            if ws_url not in found:
                found.append(ws_url)

    return {"success": True, "websocket_urls": found, "total": len(found)}


def _ws_inject_handler(p: dict) -> dict:
    url = p["url"]
    payloads = p["payloads"]
    if not url:
        raise ToolValidationError("url parameter is required")
    if not payloads:
        raise ToolValidationError("payloads parameter is required (non-empty list)")
    if not WEBSOCKET_AVAILABLE:
        raise ToolValidationError("websocket-client is not installed — pip install 'commonhuman-core[websocket]'")

    cookies = p["cookies"] or "; ".join(f"{k}={v}" for k, v in http_framework.session.cookies.get_dict().items())

    results = ws_inject(
        url,
        payloads,
        cookies=cookies,
        headers=p["headers"] or None,
        timeout=p["timeout"],
        marker=p["marker"],
        max_recv=p["max_recv"],
    )

    return {
        "success": True,
        "results": [
            {
                "payload": r.payload,
                "responses": r.responses,
                "reflected": r.reflected,
                "error": r.error,
            }
            for r in results
        ],
        "total_tested": len(results),
        "total_reflected": sum(1 for r in results if r.reflected),
    }


def _http_authenticate_handler(p: dict) -> dict:
    auth_type = p["auth_type"]
    if not auth_type:
        raise ToolValidationError("auth_type parameter is required")
    return http_framework.authenticate(
        auth_type,
        login_url=p["login_url"],
        username=p["username"],
        password=p["password"],
        username_field=p["username_field"],
        password_field=p["password_field"],
        extra_fields=p["extra_fields"],
        token_url=p["token_url"],
        client_id=p["client_id"],
        client_secret=p["client_secret"],
        grant_type=p["grant_type"],
        auth_cred=p["auth_cred"],
    )


def _http_proxy_history_handler(p: dict) -> dict:
    return {
        "success": True,
        "history": http_framework.proxy_history[-100:],
        "total_requests": len(http_framework.proxy_history),
        "vulnerabilities": http_framework.vulnerabilities,
    }


def _http_set_rules_handler(p: dict) -> dict:
    rules = p["rules"]
    http_framework.set_match_replace_rules(rules)
    return {"success": True, "rules_set": len(rules)}


def _http_set_scope_handler(p: dict) -> dict:
    host = p["host"]
    if not host:
        raise ToolValidationError("host parameter required")
    http_framework.set_scope(host, p["include_subdomains"])
    return {"success": True, "scope": http_framework.scope}


def _http_repeater_handler(p: dict) -> dict:
    return http_framework.send_custom_request(p["request_spec"])


def _http_intruder_handler(p: dict) -> dict:
    url = p["url"]
    if not url:
        raise ToolValidationError("URL parameter required")
    return http_framework.intruder_sniper(
        url, p["method"], p["location"], p["params"], p["payloads"], p["base_data"], p["max_requests"]
    )


SPECS = [
    ToolSpec(
        name="browser_agent",
        mcp_tool_name="browser_agent_inspect",
        endpoint="/api/tools/browser-agent",
        category="web_framework",
        description="AI-powered browser agent for comprehensive web application inspection and security analysis.",
        params=[
            ParamSpec("url", str, default="", help_text="Target URL to inspect (required for the navigate action)"),
            ParamSpec("headless", bool, default=True, help_text="Run browser in headless mode"),
            ParamSpec("wait_time", int, default=5, help_text="Time to wait after page load, in seconds"),
            ParamSpec("action", str, default="navigate", help_text="Action to perform: navigate, screenshot, close, status"),
            ParamSpec("proxy_port", int, default=0, help_text="Optional proxy port for request interception (0 = none)"),
            ParamSpec("active_tests", bool, default=False, help_text="Run lightweight active reflected XSS tests (safe GET-only)"),
        ],
        handler=_browser_agent_handler,
    ),
    ToolSpec(
        name="http_framework_test",
        mcp_tool_name="http_framework_test",
        endpoint="/api/tools/http-framework/request",
        category="web_framework",
        description="Enhanced HTTP testing framework (Burp Suite alternative) for comprehensive web security testing.",
        params=[
            ParamSpec("url", str, required=True, help_text="Target URL to test"),
            ParamSpec("method", str, default="GET", help_text="HTTP method (GET, POST, PUT, DELETE, etc.)"),
            ParamSpec("data", dict, default={}, help_text="Request data/parameters"),
            ParamSpec("headers", dict, default={}, help_text="Custom headers"),
            ParamSpec("cookies", dict, default={}, help_text="Custom cookies"),
        ],
        handler=_http_request_handler,
    ),
    ToolSpec(
        name="http_spider",
        mcp_tool_name="http_spider",
        endpoint="/api/tools/http-framework/spider",
        category="web_framework",
        description="Spider a website to discover endpoints and forms.",
        params=[
            ParamSpec("url", str, required=True, help_text="Base URL to spider"),
            ParamSpec("max_depth", int, default=3, help_text="Maximum crawling depth"),
            ParamSpec("max_pages", int, default=100, help_text="Maximum pages to discover"),
        ],
        handler=_http_spider_handler,
    ),
    ToolSpec(
        name="js_api_discover",
        mcp_tool_name="js_api_discover",
        endpoint="/api/tools/http-framework/js-api-discover",
        category="web_framework",
        description="Extract REST/JSON API endpoints from an SPA's JavaScript bundles (React/Vue/Angular) — parses fetch/axios calls and hardcoded paths that a plain crawl won't surface.",
        params=[
            ParamSpec("url", str, required=True, help_text="SPA page URL to inspect for JS bundles"),
            ParamSpec("max_bundles", int, default=20, help_text="Maximum number of JS bundles to fetch and parse"),
        ],
        handler=_js_api_discover_handler,
    ),
    ToolSpec(
        name="source_map_recover",
        mcp_tool_name="source_map_recover",
        endpoint="/api/tools/http-framework/source-map-recover",
        category="web_framework",
        description="Recover original pre-minified JS source via sourceMappingURL/.map files — far more useful than minified bundles for DOM-XSS/source review.",
        params=[
            ParamSpec("url", str, required=True, help_text="Page URL to inspect for JS bundles (used to auto-discover <script src> tags if js_urls is empty)"),
            ParamSpec("js_urls", list, default=[], help_text="Explicit list of JS bundle URLs to probe (skips auto-discovery from the page)"),
            ParamSpec("max_maps", int, default=10, help_text="Maximum number of source maps to fetch"),
            ParamSpec("max_source_chars", int, default=20000, help_text="Truncate each recovered source file to this many characters"),
        ],
        handler=_source_map_recover_handler,
    ),
    ToolSpec(
        name="ws_discover",
        mcp_tool_name="ws_discover",
        endpoint="/api/tools/http-framework/ws-discover",
        category="web_framework",
        description="Discover WebSocket endpoints referenced in a page's HTML and JS bundles (new WebSocket(...) calls, ws:// or wss:// literals).",
        params=[
            ParamSpec("url", str, required=True, help_text="Page URL to scan for WebSocket references"),
            ParamSpec("max_bundles", int, default=20, help_text="Maximum number of linked JS bundles to also scan"),
        ],
        handler=_ws_discover_handler,
    ),
    ToolSpec(
        name="ws_inject",
        mcp_tool_name="ws_inject",
        endpoint="/api/tools/http-framework/ws-inject",
        category="web_framework",
        description="Send payloads over a WebSocket connection and collect responses — for XSS/injection testing against WS endpoints (e.g. chat, real-time features).",
        params=[
            ParamSpec("url", str, required=True, help_text="WebSocket URL (ws:// or wss://)"),
            ParamSpec("payloads", list, default=[], help_text="Payloads to send, one connection per payload"),
            ParamSpec("cookies", str, default="", help_text="Cookie header value; defaults to the shared session's cookies if empty"),
            ParamSpec("headers", dict, default={}, help_text="Additional WS handshake headers"),
            ParamSpec("timeout", int, default=10, help_text="Connection + receive timeout in seconds"),
            ParamSpec("marker", str, default="", help_text="String to search for in responses to flag reflection"),
            ParamSpec("max_recv", int, default=5, help_text="Maximum response frames to collect per payload"),
        ],
        handler=_ws_inject_handler,
    ),
    ToolSpec(
        name="http_authenticate",
        mcp_tool_name="http_authenticate",
        endpoint="/api/tools/http-framework/authenticate",
        category="web_framework",
        description="Authenticate the shared HTTP framework session via form login, OAuth2 client-credentials, or HTTP Basic/Digest/NTLM — subsequent http_request/http_spider/http_intruder calls reuse the session.",
        params=[
            ParamSpec("auth_type", str, required=True, help_text="form | bearer | basic | digest | ntlm"),
            ParamSpec("login_url", str, default="", help_text="[form] Login page URL"),
            ParamSpec("username", str, default="", help_text="[form] Username"),
            ParamSpec("password", str, default="", help_text="[form] Password"),
            ParamSpec("username_field", str, default="username", help_text="[form] Username field name"),
            ParamSpec("password_field", str, default="password", help_text="[form] Password field name"),
            ParamSpec("extra_fields", dict, default={}, help_text="[form] Extra form fields to submit"),
            ParamSpec("token_url", str, default="", help_text="[bearer] OAuth2 token endpoint"),
            ParamSpec("client_id", str, default="", help_text="[bearer] OAuth2 client ID"),
            ParamSpec("client_secret", str, default="", help_text="[bearer] OAuth2 client secret"),
            ParamSpec("grant_type", str, default="client_credentials", help_text="[bearer] OAuth2 grant type"),
            ParamSpec("auth_cred", str, default="", help_text="[basic|digest|ntlm] Credentials as 'username:password'"),
        ],
        handler=_http_authenticate_handler,
    ),
    ToolSpec(
        name="http_proxy_history",
        mcp_tool_name="http_proxy_history",
        endpoint="/api/tools/http-framework/proxy-history",
        category="web_framework",
        description="Get the HTTP framework's proxy request/response history and discovered vulnerabilities.",
        params=[],
        handler=_http_proxy_history_handler,
    ),
    ToolSpec(
        name="http_set_rules",
        mcp_tool_name="http_set_rules",
        endpoint="/api/tools/http-framework/set-rules",
        category="web_framework",
        description=(
            "Set match/replace rules used to rewrite parts of URL/query/headers/body before sending. "
            "Rule format: {'where':'url|query|headers|body','pattern':'regex','replacement':'string'}"
        ),
        params=[
            ParamSpec("rules", list, required=True, help_text="List of match/replace rule objects"),
        ],
        handler=_http_set_rules_handler,
    ),
    ToolSpec(
        name="http_set_scope",
        mcp_tool_name="http_set_scope",
        endpoint="/api/tools/http-framework/set-scope",
        category="web_framework",
        description="Define in-scope host (and optionally subdomains) so out-of-scope requests are skipped.",
        params=[
            ParamSpec("host", str, required=True, help_text="In-scope host"),
            ParamSpec("include_subdomains", bool, default=True, help_text="Also treat subdomains of host as in-scope"),
        ],
        handler=_http_set_scope_handler,
    ),
    ToolSpec(
        name="http_repeater",
        mcp_tool_name="http_repeater",
        endpoint="/api/tools/http-framework/repeater",
        category="web_framework",
        description="Send a crafted request (Burp Repeater equivalent).",
        params=[
            ParamSpec("request_spec", dict, required=True, help_text="Request spec with keys: url, method, headers, cookies, data"),
        ],
        handler=_http_repeater_handler,
    ),
    ToolSpec(
        name="http_intruder",
        mcp_tool_name="http_intruder",
        endpoint="/api/tools/http-framework/intruder",
        category="web_framework",
        description="Simple Intruder (sniper) fuzzing. Iterates payloads over each param individually.",
        params=[
            ParamSpec("url", str, required=True, help_text="Target URL"),
            ParamSpec("method", str, default="GET", help_text="HTTP method"),
            ParamSpec("location", str, default="query", help_text="Where to inject payloads: query|body|headers|cookie"),
            ParamSpec("params", list, default=[], help_text="Parameter names to fuzz"),
            ParamSpec("payloads", list, default=[], help_text="Payloads to try per parameter"),
            ParamSpec("base_data", dict, default={}, help_text="Base request data/parameters"),
            ParamSpec("max_requests", int, default=100, help_text="Maximum number of requests to send"),
        ],
        handler=_http_intruder_handler,
    ),
]
