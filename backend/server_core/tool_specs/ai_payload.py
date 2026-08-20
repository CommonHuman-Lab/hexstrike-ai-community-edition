import time
from datetime import datetime

from backend.server_core.generators.payload_generator import ai_payload_generator
from backend.server_core.tool_spec import ParamSpec, ToolSpec


def _ai_generate_payload_handler(p: dict) -> dict:
    target_info = {
        "attack_type": p["attack_type"],
        "complexity": p["complexity"],
        "technology": p["technology"],
        "url": p["url"],
    }
    result = ai_payload_generator.generate_contextual_payload(target_info)

    return {
        "success": True,
        "ai_payload_generation": result,
        "timestamp": datetime.now().isoformat(),
    }


def _ai_generate_attack_suite_handler(p: dict) -> dict:
    target_url = p["target_url"]
    attack_list = [attack.strip() for attack in p["attack_types"].split(",")]

    results = {
        "target_url": target_url,
        "attack_types": attack_list,
        "payload_suites": {},
        "summary": {"total_payloads": 0, "high_risk_payloads": 0, "test_cases": 0},
    }

    for attack_type in attack_list:
        payload_data = ai_payload_generator.generate_contextual_payload({
            "attack_type": attack_type,
            "complexity": "advanced",
            "technology": "",
            "url": target_url,
        })
        results["payload_suites"][attack_type] = payload_data
        results["summary"]["total_payloads"] += payload_data.get("payload_count", 0)
        results["summary"]["test_cases"] += len(payload_data.get("test_cases", []))

        for payload_info in payload_data.get("payloads", []):
            if payload_info.get("risk_level") == "HIGH":
                results["summary"]["high_risk_payloads"] += 1

    return {
        "success": True,
        "attack_suite": results,
        "timestamp": time.time(),
    }


def _ai_test_payload_command(p: dict) -> str:
    payload = p["payload"]
    target_url = p["target_url"]
    method = p["method"]

    if method.upper() == "GET":
        encoded_payload = payload.replace(" ", "%20").replace("'", "%27")
        return f"curl -s '{target_url}?test={encoded_payload}'"
    return f"curl -s -X POST -d 'test={payload}' '{target_url}'"


def _ai_test_payload_postprocess(raw: dict, p: dict) -> dict:
    payload = p["payload"]
    target_url = p["target_url"]
    method = p["method"]

    analysis = {
        "payload_tested": payload,
        "target_url": target_url,
        "method": method,
        "response_size": len(raw.get("stdout", "")),
        "success": raw.get("success", False),
        "potential_vulnerability": payload.lower() in raw.get("stdout", "").lower(),
        "recommendations": [
            "Analyze response for payload reflection",
            "Check for error messages indicating vulnerability",
            "Monitor application behavior changes",
        ],
    }

    return {
        "success": True,
        "test_result": raw,
        "ai_analysis": analysis,
        "timestamp": datetime.now().isoformat(),
    }


SPECS = [
    ToolSpec(
        name="ai_generate_payload",
        mcp_tool_name="ai_generate_payload",
        endpoint="/api/ai/generate_payload",
        category="ai_payload",
        description="Generate AI-powered contextual payloads for security testing.",
        params=[
            ParamSpec("attack_type", str, required=True, help_text="Type of attack (xss, sqli, lfi, cmd_injection, ssti, xxe)"),
            ParamSpec("complexity", str, default="basic", help_text="Complexity level (basic, advanced, bypass)"),
            ParamSpec("technology", str, default="", help_text="Target technology (php, asp, jsp, python, nodejs)"),
            ParamSpec("url", str, default="", help_text="Target URL for context"),
        ],
        handler=_ai_generate_payload_handler,
    ),
    ToolSpec(
        name="ai_generate_attack_suite",
        mcp_tool_name="ai_generate_attack_suite",
        endpoint="/api/ai/generate-attack-suite",
        category="ai_payload",
        description="Generate a comprehensive attack suite with multiple payload types.",
        params=[
            ParamSpec("target_url", str, required=True, help_text="Target URL for testing"),
            ParamSpec("attack_types", str, default="xss,sqli,lfi", help_text="Comma-separated list of attack types"),
        ],
        handler=_ai_generate_attack_suite_handler,
    ),
    ToolSpec(
        name="ai_test_payload",
        mcp_tool_name="ai_test_payload",
        endpoint="/api/ai/test_payload",
        category="ai_payload",
        description="Test generated payload against target with AI analysis.",
        params=[
            ParamSpec("payload", str, required=True, help_text="The payload to test"),
            ParamSpec("target_url", str, required=True, help_text="Target URL to test against"),
            ParamSpec("method", str, default="GET", help_text="HTTP method (GET, POST)"),
        ],
        build_command=_ai_test_payload_command,
        postprocess=_ai_test_payload_postprocess,
        use_cache=False,
    ),
]
