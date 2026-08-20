from datetime import datetime

from backend.server_core.intelligence.cve_intelligence_manager import CVEIntelligenceManager
from backend.server_core.modern_visual_engine import ModernVisualEngine
from backend.server_core.tool_spec import ParamSpec, ToolSpec


def _create_vulnerability_card_handler(p: dict) -> dict:
    card = CVEIntelligenceManager().render_vulnerability_card(p)
    return {
        "success": True,
        "vulnerability_card": card,
        "timestamp": datetime.now().isoformat(),
    }


def _create_vulnerability_report_handler(p: dict) -> dict:
    vuln_data = p["vulnerabilities"]
    target = p["target"]
    scan_type = p["scan_type"]

    cve_intelligence = CVEIntelligenceManager()
    vulnerability_cards = [cve_intelligence.render_vulnerability_card(vuln) for vuln in vuln_data]

    summary_data = {
        "target": target,
        "tools_used": [scan_type],
        "execution_time": 0,
        "vulnerabilities": vuln_data,
        "findings": "",
    }
    summary_report = ModernVisualEngine().create_summary_report(summary_data)

    return {
        "success": True,
        "vulnerability_cards": vulnerability_cards,
        "summary_report": summary_report,
        "total_vulnerabilities": len(vuln_data),
        "timestamp": datetime.now().isoformat(),
    }


def _format_tool_output_handler(p: dict) -> str:
    visual_engine = ModernVisualEngine()
    return visual_engine.format_tool_output(p["tool_name"], p["output"], p["success"])


def _format_tool_output_postprocess(raw: str, p: dict) -> dict:
    return {
        "success": True,
        "formatted_output": raw,
        "timestamp": datetime.now().isoformat(),
    }


def _create_scan_summary_handler(p: dict) -> str:
    tools_used = p["tools_used"]
    tools_list = tools_used if isinstance(tools_used, list) else [tool.strip() for tool in tools_used.split(",")]
    summary_data = {
        "target": p["target"],
        "tools_used": tools_list,
        "execution_time": p["execution_time"],
        "vulnerabilities": [{"severity": "info"}] * p["vulnerabilities_found"],
        "findings": p["findings"],
    }
    visual_engine = ModernVisualEngine()
    return visual_engine.create_summary_report(summary_data)


def _create_scan_summary_postprocess(raw: str, p: dict) -> dict:
    return {
        "success": True,
        "summary_report": raw,
        "timestamp": datetime.now().isoformat(),
    }


SPECS = [
    ToolSpec(
        name="format_tool_output_visual",
        mcp_tool_name="format_tool_output_visual",
        endpoint="/api/visual/tool-output",
        category="visual",
        description="Format tool output with beautiful visual styling, syntax highlighting, and structure.",
        params=[
            ParamSpec("tool_name", str, required=True, help_text="Name of the security tool"),
            ParamSpec("output", str, required=True, help_text="Raw output from the tool"),
            ParamSpec("success", bool, default=True, help_text="Whether the tool execution was successful"),
        ],
        handler=_format_tool_output_handler,
        postprocess=_format_tool_output_postprocess,
    ),
    ToolSpec(
        name="create_scan_summary",
        mcp_tool_name="create_scan_summary",
        endpoint="/api/visual/summary-report",
        category="visual",
        description="Create a comprehensive scan summary report with beautiful visual formatting.",
        params=[
            ParamSpec("target", str, required=True, help_text="Target that was scanned"),
            ParamSpec("tools_used", str, required=True, help_text="Comma-separated list of tools used"),
            ParamSpec("vulnerabilities_found", int, default=0, help_text="Number of vulnerabilities discovered"),
            ParamSpec("execution_time", float, default=0.0, help_text="Total execution time in seconds"),
            ParamSpec("findings", str, default="", help_text="Additional findings or notes"),
        ],
        handler=_create_scan_summary_handler,
        postprocess=_create_scan_summary_postprocess,
    ),
    ToolSpec(
        name="create_vulnerability_card",
        mcp_tool_name="create_vulnerability_card",
        endpoint="/api/visual/vulnerability-card",
        category="visual",
        description="Create a beautiful vulnerability card with severity-based styling and visual indicators.",
        params=[
            ParamSpec("severity", str, default="info", help_text="Vulnerability severity (critical, high, medium, low, info)"),
            ParamSpec("title", str, default="Unknown Vulnerability", help_text="Vulnerability title"),
            ParamSpec("url", str, default="N/A", help_text="Affected URL/target"),
            ParamSpec("description", str, default="No description available", help_text="Vulnerability description"),
            ParamSpec("cvss_score", float, default=0.0, help_text="CVSS score (0.0-10.0)"),
        ],
        handler=_create_vulnerability_card_handler,
    ),
    ToolSpec(
        name="create_vulnerability_report",
        mcp_tool_name="create_vulnerability_report",
        endpoint="/api/visual/vulnerability-report",
        category="visual",
        description="Create a beautiful vulnerability report with severity-based styling and visual indicators for each finding, plus a summary.",
        params=[
            ParamSpec("vulnerabilities", list, required=True, help_text="List of vulnerability objects (severity, title, url, description, cvss_score)"),
            ParamSpec("target", str, default="", help_text="Target that was scanned"),
            ParamSpec("scan_type", str, default="comprehensive", help_text="Type of scan performed"),
        ],
        handler=_create_vulnerability_report_handler,
    ),
]
