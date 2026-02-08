"""
Scan Intelligence API Routes
Handles scan sessions, result analysis, finding correlation, and iterative scanning.

Design notes (senior-engineering/architecture):
  - New blueprint, no modifications to existing routes
  - Dependencies injected via init_app() — same pattern as intelligence.py
  - Guard clauses for all input validation
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

scan_intelligence_bp = Blueprint("scan_intelligence", __name__, url_prefix="/api/scan-intelligence")

# ── Constants ──────────────────────────────────────────────────────────────
MAX_PARALLEL_TOOLS = 10

# Dependencies injected via init_app
decision_engine = None
tool_executors = None
session_manager = None
result_analyzer = None
finding_correlator = None


def init_app(dec_engine, executors, sess_mgr, res_analyzer, find_correlator):
    """Initialize blueprint with dependencies."""
    global decision_engine, tool_executors, session_manager
    global result_analyzer, finding_correlator
    decision_engine = dec_engine
    tool_executors = executors
    session_manager = sess_mgr
    result_analyzer = res_analyzer
    finding_correlator = find_correlator


# ════════════════════════════════════════════════════════════════════
# SESSION MANAGEMENT
# ════════════════════════════════════════════════════════════════════


@scan_intelligence_bp.route("/sessions", methods=["POST"])
def create_session():
    """Create a new scan session for a target."""
    try:
        data = request.get_json()
        if not data or "target" not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data["target"]

        # Analyze target to populate profile
        profile = decision_engine.analyze_target(target)
        session = session_manager.create(target, profile.to_dict())

        logger.info(f"📋 Session created: {session.session_id} for {target}")
        return jsonify(
            {
                "success": True,
                "session": session.get_summary(),
                "target_profile": profile.to_dict(),
            }
        )
    except Exception as e:
        logger.error(f"💥 Error creating session: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_intelligence_bp.route("/sessions", methods=["GET"])
def list_sessions():
    """List all active scan sessions."""
    try:
        sessions = session_manager.list_sessions()
        return jsonify({"success": True, "sessions": sessions, "count": len(sessions)})
    except Exception as e:
        logger.error(f"💥 Error listing sessions: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_intelligence_bp.route("/sessions/<session_id>", methods=["GET"])
def get_session(session_id):
    """Get full session state including all findings."""
    try:
        session = session_manager.get(session_id)
        if not session:
            return jsonify({"error": "Session not found or expired"}), 404

        return jsonify({"success": True, "session": session.to_dict()})
    except Exception as e:
        logger.error(f"💥 Error getting session: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_intelligence_bp.route("/sessions/<session_id>", methods=["DELETE"])
def delete_session(session_id):
    """Delete a scan session."""
    try:
        deleted = session_manager.delete(session_id)
        if not deleted:
            return jsonify({"error": "Session not found"}), 404
        return jsonify({"success": True, "message": f"Session {session_id} deleted"})
    except Exception as e:
        logger.error(f"💥 Error deleting session: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ════════════════════════════════════════════════════════════════════
# RESULT ANALYSIS & CORRELATION
# ════════════════════════════════════════════════════════════════════


@scan_intelligence_bp.route("/analyze-results", methods=["POST"])
def analyze_results():
    """Parse raw tool output into structured findings."""
    try:
        data = request.get_json()
        if not data or "tool" not in data or "target" not in data:
            return jsonify({"error": "tool and target are required"}), 400

        tool_name = data["tool"]
        target = data["target"]
        tool_result = data.get("result", {})
        session_id = data.get("session_id")

        findings = result_analyzer.analyze(tool_name, target, tool_result)

        # Persist to session if provided
        if session_id:
            session = session_manager.get(session_id)
            if session:
                for f in findings:
                    session.add_finding(f)
                session.add_tool_result(tool_name, tool_result)

        findings_dicts = [f.to_dict() for f in findings]
        return jsonify(
            {
                "success": True,
                "findings": findings_dicts,
                "finding_count": len(findings_dicts),
            }
        )
    except Exception as e:
        logger.error(f"💥 Error analyzing results: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_intelligence_bp.route("/correlate", methods=["POST"])
def correlate_findings():
    """Correlate and deduplicate findings from a session."""
    try:
        data = request.get_json()
        session_id = data.get("session_id") if data else None

        if not session_id:
            return jsonify({"error": "session_id is required"}), 400

        session = session_manager.get(session_id)
        if not session:
            return jsonify({"error": "Session not found or expired"}), 404

        correlated = finding_correlator.correlate(session.findings)
        summary = finding_correlator.summarize(correlated)

        return jsonify(
            {
                "success": True,
                "correlated_findings": correlated,
                "summary": summary,
            }
        )
    except Exception as e:
        logger.error(f"💥 Error correlating findings: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ════════════════════════════════════════════════════════════════════
# ITERATIVE SCAN (Agent Loop: Think → Decide → Act → Observe)
# ════════════════════════════════════════════════════════════════════


@scan_intelligence_bp.route("/iterative-scan", methods=["POST"])
def iterative_scan():
    """
    Execute one iteration of an intelligent scan loop.

    Each call:
    1. THINK: Analyze target and current session state
    2. DECIDE: Select tools (initial or follow-up based on prior findings)
    3. ACT: Execute selected tools in parallel
    4. OBSERVE: Parse results, correlate findings, update session

    Call repeatedly for multi-iteration scanning.
    """
    try:
        data = request.get_json()
        if not data or "target" not in data:
            return jsonify({"error": "target is required"}), 400

        target = data["target"]
        session_id = data.get("session_id")
        objective = data.get("objective", "comprehensive")
        max_tools = data.get("max_tools", 5)

        # ── THINK: Get or create session ────────────────────────────
        if session_id:
            session = session_manager.get(session_id)
            if not session:
                return jsonify({"error": "Session not found or expired"}), 404
            # Reuse the session's stored profile — avoids redundant DNS/heuristic
            # work and keeps subtype detection deterministic across iterations
            from agents.decision_engine import TargetProfile

            profile = TargetProfile.from_dict(session.target_profile)
        else:
            profile = decision_engine.analyze_target(target)
            session = session_manager.create(target, profile.to_dict())
            session_id = session.session_id

        already_run = [t["tool"] for t in session.tools_executed]

        # ── DECIDE: Select tools ────────────────────────────────────
        if session.iteration == 0:
            # First iteration: use standard AI tool selection
            selected_tools = decision_engine.select_optimal_tools(profile, objective)[:max_tools]
        else:
            # Follow-up iteration: adapt based on findings
            finding_dicts = [f.to_dict() for f in session.findings]
            selected_tools = decision_engine.adapt_tools_from_findings(
                profile, finding_dicts, already_run, max_followups=max_tools
            )

        if not selected_tools:
            # No more tools to run — scan is converged
            correlated = finding_correlator.correlate(session.findings)
            summary = finding_correlator.summarize(correlated)
            return jsonify(
                {
                    "success": True,
                    "status": "converged",
                    "message": "No additional tools recommended. Scan complete.",
                    "session": session.get_summary(),
                    "correlated_findings": correlated,
                    "summary": summary,
                }
            )

        # ── ACT: Execute tools in parallel ──────────────────────────
        iteration_results = _run_tools_parallel(selected_tools, profile, target)

        # ── OBSERVE: Parse results and update session ───────────────
        new_findings = []
        for tr in iteration_results:
            tool_name = tr.get("tool", "unknown")
            session.add_tool_result(tool_name, tr)
            parsed = result_analyzer.analyze(tool_name, target, tr)
            for f in parsed:
                session.add_finding(f)
                new_findings.append(f)

        correlated = finding_correlator.correlate(session.findings)
        summary = finding_correlator.summarize(correlated)

        # Suggest next iteration's tools for the LLM
        next_tools = decision_engine.adapt_tools_from_findings(
            profile,
            [f.to_dict() for f in new_findings],
            [t["tool"] for t in session.tools_executed],
            max_followups=max_tools,
        )

        logger.info(
            f"🔄 Iteration {session.iteration} complete for {target}: "
            f"{len(selected_tools)} tools run, {len(new_findings)} new findings"
        )

        return jsonify(
            {
                "success": True,
                "status": "iteration_complete",
                "session_id": session_id,
                "iteration": session.iteration,
                "tools_executed_this_iteration": selected_tools,
                "new_findings_count": len(new_findings),
                "session_summary": session.get_summary(),
                "correlated_findings": correlated,
                "summary": summary,
                "recommended_next_tools": next_tools,
                "has_more_iterations": len(next_tools) > 0,
                "timestamp": datetime.now().isoformat(),
            }
        )

    except Exception as e:
        logger.error(f"💥 Error in iterative scan: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ════════════════════════════════════════════════════════════════════
# SHARED TOOL EXECUTION
# ════════════════════════════════════════════════════════════════════

# Retry strategies: tool_name → list of (error_pattern, param_overrides) pairs.
# When a tool fails and the error matches a pattern, retry once with merged params.
RETRY_STRATEGIES = {
    "sqlmap": [
        ("waf", {"additional_args": "--tamper=space2comment,between --random-agent"}),
        ("timeout", {"additional_args": "--timeout=60 --retries=3"}),
    ],
    "nmap": [
        ("timeout", {"additional_args": "-T2 --host-timeout 300s"}),
        ("host unreachable", {"additional_args": "-Pn -T2"}),
        ("filtered", {"additional_args": "-Pn -sS"}),
    ],
    "nuclei": [
        ("rate limit", {"additional_args": "-rate-limit 20 -concurrency 5"}),
        ("timeout", {"additional_args": "-timeout 15 -retries 3"}),
    ],
    "gobuster": [
        ("timeout", {"additional_args": "-t 5 --timeout 30s"}),
        ("connection refused", {"additional_args": "-t 2 --timeout 45s --delay 1s"}),
    ],
    "hydra": [
        ("timeout", {"additional_args": "-t 2 -w 60"}),
        ("connection refused", {"additional_args": "-t 1 -w 90"}),
    ],
    "ffuf": [
        ("rate limit", {"additional_args": "-rate 10 -t 5"}),
        ("timeout", {"additional_args": "-timeout 30 -t 5"}),
    ],
    "feroxbuster": [
        ("timeout", {"additional_args": "--timeout 30 --threads 5"}),
        ("rate limit", {"additional_args": "--rate-limit 10 --threads 3"}),
    ],
}


def _execute_single_tool(tool_name, executors, engine, profile, target):
    """Execute a single tool with optimized parameters.

    Shared by iterative_scan and parallel_execute endpoints.
    On failure, checks RETRY_STRATEGIES for error-specific parameter
    adjustments and retries once with merged params.
    """
    executor_key = tool_name.replace("-", "_")
    if executor_key not in executors:
        return {"tool": tool_name, "success": False, "error": "No executor"}

    try:
        optimized_params = engine.optimize_parameters(tool_name, profile)
        result = executors[executor_key](target, optimized_params)
        # Check if the tool itself reported failure
        if result.get("success", True):
            return {"tool": tool_name, **result}
        error_str = str(result.get("error", "")).lower()
    except Exception as ex:
        result = {"success": False, "error": str(ex)}
        error_str = str(ex).lower()

    # Attempt retry with adjusted parameters if a strategy matches
    strategies = RETRY_STRATEGIES.get(tool_name, [])
    for pattern, overrides in strategies:
        if pattern in error_str:
            try:
                retry_params = {**optimized_params, **overrides}
                retry_result = executors[executor_key](target, retry_params)
                retry_result["retried"] = True
                retry_result["retry_reason"] = f"Matched '{pattern}' — adjusted params"
                return {"tool": tool_name, **retry_result}
            except Exception as retry_ex:
                logger.debug(f"Retry failed for {tool_name} (pattern '{pattern}'): {retry_ex}")
                break  # Only one retry attempt

    return {"tool": tool_name, **result}


def _run_tools_parallel(tools, profile, target, max_workers=5):
    """Run multiple tools in parallel via ThreadPoolExecutor."""
    worker_count = min(len(tools), max_workers)
    results = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(_execute_single_tool, t, tool_executors, decision_engine, profile, target): t for t in tools
        }
        for future in futures:
            results.append(future.result())
    return results


# ════════════════════════════════════════════════════════════════════
# PARALLEL TOOL EXECUTION
# ════════════════════════════════════════════════════════════════════


@scan_intelligence_bp.route("/parallel-execute", methods=["POST"])
def parallel_execute():
    """Execute multiple tools in parallel against a target.

    Body: {
        "tools": ["nmap_scan", "nuclei_scan", ...],
        "target": "example.com",
        "session_id": "abc123"  (optional — results added to session)
    }
    """
    try:
        data = request.get_json()
        if not data or "tools" not in data or "target" not in data:
            return jsonify({"error": "tools and target are required"}), 400

        tools = data["tools"]
        target = data["target"]
        session_id = data.get("session_id")

        if not isinstance(tools, list) or not tools:
            return jsonify({"error": "tools must be a non-empty list"}), 400

        if len(tools) > MAX_PARALLEL_TOOLS:
            return jsonify({"error": f"Maximum {MAX_PARALLEL_TOOLS} tools per request"}), 400

        # Build target profile for parameter optimization
        profile = decision_engine.analyze_target(target)

        # Execute tools in parallel
        results = _run_tools_parallel(tools, profile, target)

        # Optionally update session with results
        new_findings = []
        if session_id:
            session = session_manager.get(session_id)
            if session:
                for tr in results:
                    tool_name = tr.get("tool", "unknown")
                    session.add_tool_result(tool_name, tr)
                    parsed = result_analyzer.analyze(tool_name, target, tr)
                    for f in parsed:
                        session.add_finding(f)
                        new_findings.append(f.to_dict())

        logger.info(f"Parallel execution: {len(tools)} tools run against {target}")
        return jsonify(
            {
                "success": True,
                "results": results,
                "tools_executed": len(results),
                "successful": sum(1 for r in results if r.get("success")),
                "failed": sum(1 for r in results if not r.get("success")),
                "new_findings": new_findings if session_id else None,
            }
        )

    except Exception as e:
        logger.error(f"💥 Error in parallel execution: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
