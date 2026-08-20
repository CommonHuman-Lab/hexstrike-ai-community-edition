import time

from flask import current_app
from werkzeug.local import LocalProxy

from backend.server_core.tool_spec import ParamSpec, ToolSpec


def _comprehensive_api_audit_handler(p: dict) -> dict:
    from backend.server_api.ops.vulnerability_intelligence import execute_tool_via_registered_endpoint

    base_url = p["base_url"]
    schema_url = p["schema_url"]
    jwt_token = p["jwt_token"]
    graphql_endpoint = p["graphql_endpoint"]

    app = current_app._get_current_object() if isinstance(current_app, LocalProxy) else current_app

    audit_results = {
        "base_url": base_url,
        "audit_timestamp": time.time(),
        "tests_performed": [],
        "total_vulnerabilities": 0,
        "summary": {},
        "recommendations": [],
    }

    fuzz_result = execute_tool_via_registered_endpoint(app, "api_fuzzer", {"base_url": base_url})
    if fuzz_result.get("success"):
        audit_results["tests_performed"].append("api_fuzzing")
        audit_results["api_fuzzing"] = fuzz_result

    if schema_url:
        schema_result = execute_tool_via_registered_endpoint(app, "api_schema_analyzer", {"schema_url": schema_url})
        if schema_result.get("success"):
            audit_results["tests_performed"].append("schema_analysis")
            audit_results["schema_analysis"] = schema_result
            schema_data = schema_result.get("schema_analysis_results", {})
            audit_results["total_vulnerabilities"] += len(schema_data.get("security_issues", []))

    if jwt_token:
        jwt_result = execute_tool_via_registered_endpoint(app, "jwt_analyzer", {"jwt_token": jwt_token, "target_url": base_url})
        if jwt_result.get("success"):
            audit_results["tests_performed"].append("jwt_analysis")
            audit_results["jwt_analysis"] = jwt_result
            jwt_data = jwt_result.get("jwt_analysis_results", {})
            audit_results["total_vulnerabilities"] += len(jwt_data.get("vulnerabilities", []))

    if graphql_endpoint:
        graphql_result = execute_tool_via_registered_endpoint(app, "graphql_scanner", {"endpoint": graphql_endpoint})
        if graphql_result.get("success"):
            audit_results["tests_performed"].append("graphql_scanning")
            audit_results["graphql_scanning"] = graphql_result
            graphql_data = graphql_result.get("graphql_scan_results", {})
            audit_results["total_vulnerabilities"] += len(graphql_data.get("vulnerabilities", []))

    audit_results["recommendations"] = [
        "Implement proper authentication and authorization",
        "Use HTTPS for all API communications",
        "Validate and sanitize all input parameters",
        "Implement rate limiting and request throttling",
        "Add comprehensive logging and monitoring",
        "Regular security testing and code reviews",
        "Keep API documentation updated and secure",
        "Implement proper error handling",
    ]

    audit_results["summary"] = {
        "tests_performed": len(audit_results["tests_performed"]),
        "total_vulnerabilities": audit_results["total_vulnerabilities"],
        "audit_coverage": "comprehensive" if len(audit_results["tests_performed"]) >= 3 else "partial",
    }

    return {
        "success": True,
        "comprehensive_audit": audit_results,
    }


SPECS = [
    ToolSpec(
        name="comprehensive_api_audit",
        mcp_tool_name="comprehensive_api_audit",
        endpoint="/api/audit/comprehensive-api-audit",
        category="api_audit",
        description="Comprehensive API security audit combining endpoint fuzzing, schema analysis, JWT analysis, and GraphQL scanning.",
        params=[
            ParamSpec("base_url", str, required=True, help_text="Base URL of the API"),
            ParamSpec("schema_url", str, default="", help_text="Optional API schema URL — enables schema analysis"),
            ParamSpec("jwt_token", str, default="", help_text="Optional JWT token — enables JWT analysis"),
            ParamSpec("graphql_endpoint", str, default="", help_text="Optional GraphQL endpoint — enables GraphQL scanning"),
        ],
        handler=_comprehensive_api_audit_handler,
    ),
]
