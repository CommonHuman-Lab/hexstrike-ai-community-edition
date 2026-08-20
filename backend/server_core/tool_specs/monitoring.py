import json
import logging
import time
from datetime import datetime

import backend.server_api.ops.system_monitoring as system_monitoring_api
import backend.server_core.config_core as config_core
from backend.server_api.ops.sessions import _summary_from_data
from backend.server_core.session_flow import load_session_any, normalize_step, update_session
from backend.server_core.singletons import cache, llm_client, telemetry
from backend.server_core.tool_spec import ParamSpec, ToolNotFoundError, ToolSpec
from tool_registry import SUGGESTED_APPROACHES, classify_intent

logger = logging.getLogger(__name__)


def _server_health_handler(p: dict) -> dict:
    tools_status = system_monitoring_api._get_tool_availability()

    essential_tools = system_monitoring_api.HEALTH_TOOL_CATEGORIES["essential"]
    all_essential_tools_available = all(tools_status.get(t, False) for t in essential_tools)

    category_stats = {
        cat: {
            "total": len(tools),
            "available": sum(1 for t in tools if tools_status.get(t, False)),
        }
        for cat, tools in system_monitoring_api.HEALTH_TOOL_CATEGORIES.items()
    }

    all_tools_count = len(tools_status)

    return {
        "status": "healthy",
        "message": "NyxStrike Tools API Server is operational",
        "version": config_core.get("VERSION", "unknown"),
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "total_tools_available": sum(1 for available in tools_status.values() if available),
        "total_tools_count": all_tools_count,
        "category_stats": category_stats,
        "plugin_install_hints": system_monitoring_api._get_plugin_install_hints(),
        "cache_stats": cache.get_stats(),
        "telemetry": telemetry.get_stats(),
        "uptime": time.time() - telemetry.stats["start_time"],
        "tool_availability_age_seconds": round(
            time.time() - system_monitoring_api._tool_availability_last_refresh, 1
        ),
    }


def _get_cache_stats_handler(p: dict) -> dict:
    return cache.get_stats()


def _clear_cache_handler(p: dict) -> dict:
    cache.clear()
    logger.info("Cache cleared")
    return {"success": True, "message": "Cache cleared"}


def _get_telemetry_handler(p: dict) -> dict:
    return telemetry.get_stats()


def _build_continuation_plan(session: dict) -> list:
    steps = session.get("workflow_steps", []) if isinstance(session, dict) else []
    if not isinstance(steps, list):
        steps = []

    plan = []
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        plan.append({
            "order": idx + 1,
            "tool": step.get("tool", ""),
            "parameters": step.get("parameters", {}),
            "expected_outcome": step.get("expected_outcome", ""),
            "success_probability": step.get("success_probability", 0),
            "execution_time_estimate": step.get("execution_time_estimate", 0),
            "dependencies": step.get("dependencies", []),
        })
    return plan


def _build_execution_progress(session: dict) -> dict:
    steps = session.get("workflow_steps", [])
    if not isinstance(steps, list):
        steps = []
    total_steps = len(steps)

    tools_executed = session.get("tools_executed", [])
    if not isinstance(tools_executed, list):
        tools_executed = []
    completed_steps = len(tools_executed)

    return {
        "total_steps": total_steps,
        "completed_steps": completed_steps,
        "pending_steps": max(0, total_steps - completed_steps),
        "iterations": session.get("iterations", 0),
        "total_findings": session.get("total_findings", 0),
    }


def _build_prior_handovers(session: dict, limit: int = 3) -> list:
    history = session.get("handover_history", [])
    if not isinstance(history, list):
        return []
    recent = history[-limit:] if len(history) > limit else history[:]
    recent.reverse()
    return recent


def _handover_session_handler(p: dict) -> dict:
    session_id = p["session_id"]
    note = p["note"]

    loaded = load_session_any(session_id)
    if not loaded:
        raise ToolNotFoundError(f"Session '{session_id}' not found")

    session_data, _state = loaded

    raw_steps = session_data.get("workflow_steps")
    if isinstance(raw_steps, list):
        target = session_data.get("target", "")
        cleaned_steps = [ns for ns in (normalize_step(s, target) for s in raw_steps) if ns]
        if cleaned_steps != raw_steps:
            session_data["workflow_steps"] = cleaned_steps
            session_data["tools_executed"] = [s.get("tool", "") for s in cleaned_steps if isinstance(s, dict)]
            update_session(session_id, {"workflow_steps": cleaned_steps})

    step_names = [
        s.get("tool", "")
        for s in (session_data.get("workflow_steps", []) if isinstance(session_data.get("workflow_steps"), list) else [])
        if isinstance(s, dict)
    ]
    if not step_names:
        step_names = session_data.get("tools_executed", []) if isinstance(session_data.get("tools_executed"), list) else []

    description = "\n".join([
        f"Session ID: {session_id}",
        f"Target: {session_data.get('target', 'unknown')}",
        f"Status: {session_data.get('status', 'active')}",
        f"Objective: {session_data.get('objective', '')}",
        f"Tools: {', '.join(step_names)}",
        f"Findings: {session_data.get('total_findings', 0)}",
        f"Iterations: {session_data.get('iterations', 0)}",
        f"Metadata: {json.dumps(session_data.get('metadata', {}))}",
        f"Note: {note}",
        "Classify next best action for manual execution.",
    ])

    category, confidence = classify_intent(description, llm_client if llm_client.is_available() else None)
    handover_result = {
        "timestamp": datetime.now().isoformat(),
        "session_id": session_id,
        "category": category,
        "confidence": confidence,
        "note": note,
    }

    history = session_data.get("handover_history", [])
    if not isinstance(history, list):
        history = []
    history.append(handover_result)

    updated = update_session(session_id, {"handover_history": history})
    session = _summary_from_data(updated or session_data, session_id)

    return {
        "success": True,
        "session_id": session_id,
        "session": session,
        "handover": handover_result,
        "continuation_context": {
            "target": session.get("target", ""),
            "status": session.get("status", "active"),
            "objective": session.get("objective", ""),
            "source": session.get("source", ""),
            "suggested_approach": SUGGESTED_APPROACHES.get(category, ""),
            "next_steps": _build_continuation_plan(session),
        },
        "execution_progress": _build_execution_progress(session),
        "prior_handovers": _build_prior_handovers(session),
    }


SPECS = [
    ToolSpec(
        name="server_health",
        mcp_tool_name="server_health",
        endpoint="/health",
        category="monitoring",
        description="Check the health status of the API server, including tool availability and telemetry.",
        method="GET",
        handler=_server_health_handler,
    ),
    ToolSpec(
        name="get_cache_stats",
        mcp_tool_name="get_cache_stats",
        endpoint="/api/cache/stats",
        category="monitoring",
        description="Get cache statistics from the API server.",
        method="GET",
        handler=_get_cache_stats_handler,
    ),
    ToolSpec(
        name="clear_cache",
        mcp_tool_name="clear_cache",
        endpoint="/api/cache/clear",
        category="monitoring",
        description="Clear the cache on the API server.",
        method="POST",
        handler=_clear_cache_handler,
    ),
    ToolSpec(
        name="get_telemetry",
        mcp_tool_name="get_telemetry",
        endpoint="/api/telemetry",
        category="monitoring",
        description="Get system telemetry from the API server.",
        method="GET",
        handler=_get_telemetry_handler,
    ),
    ToolSpec(
        name="handover_session",
        mcp_tool_name="handover_session",
        endpoint="/api/sessions/<session_id>/handover-context",
        category="monitoring",
        description=(
            "Handover a persisted session to AI using session ID and return full continuation context: "
            "session state, classified next action with a suggested approach, the full workflow plan, "
            "execution progress, and prior handover history."
        ),
        params=[
            ParamSpec("session_id", str, required=True, help_text="Existing session ID from the Sessions page/API"),
            ParamSpec("note", str, default="", help_text="Optional operator note/context for this handover"),
        ],
        method="POST",
        handler=_handover_session_handler,
    ),
]
