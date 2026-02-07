"""
Verification API Routes — Finding verification endpoints.

Exposes the FindingVerifier as REST endpoints for single and batch
verification of security findings within scan sessions.

Design notes (senior-engineering/clean-code):
  - Same blueprint + init_app() DI pattern as scan_intelligence.py
  - Guard clauses for input validation
  - Delegates all logic to FindingVerifier (SRP)
"""

import logging

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

verification_bp = Blueprint("verification", __name__, url_prefix="/api/verification")

# Dependencies injected via init_app
verifier = None
session_manager = None


def init_app(finding_verifier, sess_mgr):
    """Initialize blueprint with dependencies."""
    global verifier, session_manager
    verifier = finding_verifier
    session_manager = sess_mgr


@verification_bp.route("/verify-finding", methods=["POST"])
def verify_finding():
    """Verify a single finding from a scan session.

    Body: {
        "session_id": str,
        "finding_index": int,
        "methods": ["rescan", "http_probe", "cross_tool", "cve_lookup"]  (optional)
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        session_id = data.get("session_id")
        finding_index = data.get("finding_index")

        if not session_id:
            return jsonify({"error": "session_id is required"}), 400
        if finding_index is None:
            return jsonify({"error": "finding_index is required"}), 400

        session = session_manager.get(session_id)
        if not session:
            return jsonify({"error": f"Session '{session_id}' not found"}), 404

        if finding_index < 0 or finding_index >= len(session.findings):
            return (
                jsonify({"error": f"finding_index {finding_index} out of range (0-{len(session.findings) - 1})"}),
                400,
            )

        finding = session.findings[finding_index]
        methods = data.get("methods")

        result = verifier.verify_finding(finding, session.target, methods=methods)

        logger.info(f"Verified finding {finding_index} in session {session_id}: verified={result.verified}")
        return jsonify({"success": True, "verification": result.to_dict()})

    except Exception as e:
        logger.error(f"Error verifying finding: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@verification_bp.route("/batch-verify", methods=["POST"])
def batch_verify():
    """Batch-verify findings from a scan session above a severity threshold.

    Body: {
        "session_id": str,
        "min_severity": "medium"  (optional, default "medium"),
        "methods": ["rescan", "http_probe"]  (optional)
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        session_id = data.get("session_id")
        if not session_id:
            return jsonify({"error": "session_id is required"}), 400

        session = session_manager.get(session_id)
        if not session:
            return jsonify({"error": f"Session '{session_id}' not found"}), 404

        if not session.findings:
            return jsonify({"success": True, "results": [], "message": "No findings to verify"})

        min_severity = data.get("min_severity", "medium")
        methods = data.get("methods")

        results = verifier.batch_verify(session.findings, session.target, min_severity=min_severity, methods=methods)

        verified_count = sum(1 for r in results if r["verified"])
        logger.info(f"Batch verification for session {session_id}: {verified_count}/{len(results)} verified")

        return jsonify(
            {
                "success": True,
                "results": results,
                "summary": {
                    "total_checked": len(results),
                    "verified": verified_count,
                    "unverified": len(results) - verified_count,
                },
            }
        )

    except Exception as e:
        logger.error(f"Error in batch verification: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
