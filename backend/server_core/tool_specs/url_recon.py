import shlex

from commonhuman_core.dorker import DorkEngine, dork
from backend.server_core.tool_spec import ParamSpec, ToolSpec, ToolValidationError


def _gau_command(p: dict) -> str:
    argv = ["gau", p["domain"]]
    if p["providers"] != "wayback,commoncrawl,otx,urlscan":
        argv.append("--providers")
        argv.append(p["providers"])
    if p["include_subs"]:
        argv.append("--subs")
    if p["blacklist"]:
        argv.append("--blacklist")
        argv.append(p["blacklist"])
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


def _waybackurls_command(p: dict) -> str:
    argv = ["waybackurls", p["domain"]]
    if p["get_versions"]:
        argv.append("--get-versions")
    if p["no_subs"]:
        argv.append("--no-subs")
    if p["additional_args"]:
        argv.extend(shlex.split(p["additional_args"]))
    return shlex.join(argv)


_DORK_ENGINES = {DorkEngine.DDG, DorkEngine.BING, DorkEngine.YAHOO, DorkEngine.ALL}


def _dork_search_handler(p: dict) -> dict:
    query = p["query"]
    if not query:
        raise ToolValidationError("query parameter is required")
    engine = p["engine"]
    if engine not in _DORK_ENGINES:
        raise ToolValidationError(f"engine must be one of {sorted(_DORK_ENGINES)}, got {engine!r}")

    urls = dork(query, max_results=p["max_results"], proxy=p["proxy"], timeout=p["timeout"], engine=engine)
    return {"success": True, "query": query, "engine": engine, "urls": urls, "total": len(urls)}


SPECS = [
    ToolSpec(
        name="gau",
        mcp_tool_name="gau_discovery",
        endpoint="/api/tools/gau",
        category="url_recon",
        description="Execute Gau (Get All URLs) for URL discovery from multiple sources.",
        params=[
            ParamSpec("domain", str, required=True, help_text="The target domain"),
            ParamSpec("providers", str, default="wayback,commoncrawl,otx,urlscan", help_text="Data providers to use"),
            ParamSpec("include_subs", bool, default=True, help_text="Include subdomains"),
            ParamSpec("blacklist", str, default="png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", help_text="File extensions to blacklist"),
            ParamSpec("additional_args", str, default="", help_text="Additional Gau arguments"),
        ],
        build_command=_gau_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="waybackurls",
        mcp_tool_name="waybackurls_discovery",
        endpoint="/api/tools/waybackurls",
        category="url_recon",
        description="Execute Waybackurls for historical URL discovery.",
        params=[
            ParamSpec("domain", str, required=True, help_text="The target domain"),
            ParamSpec("get_versions", bool, default=False, help_text="Get all versions of URLs"),
            ParamSpec("no_subs", bool, default=False, help_text="Don't include subdomains"),
            ParamSpec("additional_args", str, default="", help_text="Additional Waybackurls arguments"),
        ],
        build_command=_waybackurls_command,
        use_recovery=True,
    ),
    ToolSpec(
        name="dork_search",
        mcp_tool_name="dork_search",
        endpoint="/api/tools/dork-search",
        category="url_recon",
        description="Search DuckDuckGo, Bing, and/or Yahoo for URLs matching a dork query (e.g. 'site:example.com inurl:search') — returns only URLs carrying query parameters, no API keys required.",
        params=[
            ParamSpec("query", str, required=True, help_text="Dork query, e.g. 'site:example.com inurl:search'"),
            ParamSpec("engine", str, default=DorkEngine.DDG, help_text="ddg | bing | yahoo | all"),
            ParamSpec("max_results", int, default=20, help_text="Maximum URLs to return per engine"),
            ParamSpec("proxy", str, default="", help_text="Optional HTTP proxy URL"),
            ParamSpec("timeout", int, default=15, help_text="Request timeout in seconds"),
        ],
        handler=_dork_search_handler,
    ),
]
