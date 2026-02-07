"""
Scan Memory API Routes
Handles episodic memory, semantic patterns, session archival, and memory consolidation.

Design notes (senior-engineering/architecture):
  - New blueprint, no modifications to existing routes
  - Dependencies injected via init_app() — same pattern as scan_intelligence.py
  - Guard clauses for all input validation
"""

import logging

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

scan_memory_bp = Blueprint("scan_memory", __name__, url_prefix="/api/scan-memory")

# Dependencies injected via init_app
session_manager = None
scan_memory_store = None


def init_app(sess_mgr, memory):
    """Initialize blueprint with dependencies."""
    global session_manager, scan_memory_store
    session_manager = sess_mgr
    scan_memory_store = memory


# ── Session Completion & Archival ─────────────────────────────────


@scan_memory_bp.route("/complete-session", methods=["POST"])
def complete_session():
    """Mark a scan session as complete — archive to disk and save episodic trace."""
    try:
        data = request.get_json()
        if not data or "session_id" not in data:
            return jsonify({"error": "session_id is required"}), 400

        session_id = data["session_id"]
        result = session_manager.complete_session(session_id)
        if not result:
            return jsonify({"error": "Session not found or already completed"}), 404

        return jsonify(
            {
                "success": True,
                "message": f"Session {session_id} completed and archived",
                "session": result,
            }
        )
    except Exception as e:
        logger.error(f"💥 Error completing session: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_memory_bp.route("/persist-session", methods=["POST"])
def persist_session():
    """Explicitly checkpoint a session to disk without completing it."""
    try:
        data = request.get_json()
        if not data or "session_id" not in data:
            return jsonify({"error": "session_id is required"}), 400

        session_id = data["session_id"]
        ok = session_manager.persist_session(session_id)
        if not ok:
            return jsonify({"error": "Session not found or persistence not available"}), 404

        return jsonify(
            {
                "success": True,
                "message": f"Session {session_id} checkpointed to disk",
            }
        )
    except Exception as e:
        logger.error(f"💥 Error persisting session: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ── Episodic Memory ───────────────────────────────────────────────


@scan_memory_bp.route("/episodes", methods=["GET"])
def list_episodes():
    """List recent episodic scan traces."""
    try:
        if not scan_memory_store:
            return jsonify({"error": "Memory system not available"}), 503

        limit = request.args.get("limit", 50, type=int)
        episodes = scan_memory_store.list_episodes(limit=limit)
        return jsonify(
            {
                "success": True,
                "count": len(episodes),
                "episodes": episodes,
            }
        )
    except Exception as e:
        logger.error(f"💥 Error listing episodes: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_memory_bp.route("/episodes/<session_id>", methods=["GET"])
def get_episode(session_id):
    """Get a specific episodic trace by session ID."""
    try:
        if not scan_memory_store:
            return jsonify({"error": "Memory system not available"}), 503

        episode = scan_memory_store.get_episode(session_id)
        if not episode:
            return jsonify({"error": "Episode not found"}), 404

        return jsonify({"success": True, "episode": episode})
    except Exception as e:
        logger.error(f"💥 Error getting episode: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_memory_bp.route("/episodes/search", methods=["POST"])
def search_episodes():
    """Search episodic memory by target, tool, or target type."""
    try:
        if not scan_memory_store:
            return jsonify({"error": "Memory system not available"}), 503

        data = request.get_json()
        if not data or "query" not in data:
            return jsonify({"error": "query is required"}), 400

        query = data["query"]
        limit = data.get("limit", 10)
        results = scan_memory_store.search_episodes(query, limit=limit)
        return jsonify(
            {
                "success": True,
                "count": len(results),
                "results": results,
            }
        )
    except Exception as e:
        logger.error(f"💥 Error searching episodes: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ── Semantic Memory (Patterns & Learnings) ────────────────────────


@scan_memory_bp.route("/patterns", methods=["GET"])
def get_patterns():
    """Get all learned semantic patterns."""
    try:
        if not scan_memory_store:
            return jsonify({"error": "Memory system not available"}), 503

        patterns = scan_memory_store.get_patterns()
        return jsonify(
            {
                "success": True,
                "count": len(patterns),
                "patterns": patterns,
            }
        )
    except Exception as e:
        logger.error(f"💥 Error getting patterns: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_memory_bp.route("/learnings", methods=["GET"])
def get_learnings():
    """Get all learnings (error/success observations)."""
    try:
        if not scan_memory_store:
            return jsonify({"error": "Memory system not available"}), 503

        learnings = scan_memory_store.get_learnings()
        return jsonify(
            {
                "success": True,
                "count": len(learnings),
                "learnings": learnings,
            }
        )
    except Exception as e:
        logger.error(f"💥 Error getting learnings: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_memory_bp.route("/learnings", methods=["POST"])
def add_learning():
    """Add a manual learning observation."""
    try:
        if not scan_memory_store:
            return jsonify({"error": "Memory system not available"}), 503

        data = request.get_json()
        if not data or "observation" not in data:
            return jsonify({"error": "observation is required"}), 400

        learning = {
            "observation": data["observation"],
            "category": data.get("category", "general"),
            "target_type": data.get("target_type", ""),
            "tool": data.get("tool", ""),
        }
        ok = scan_memory_store.add_learning(learning)
        if not ok:
            return jsonify({"error": "Failed to save learning"}), 500

        return jsonify({"success": True, "message": "Learning saved"})
    except Exception as e:
        logger.error(f"💥 Error adding learning: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ── Consolidation ─────────────────────────────────────────────────


@scan_memory_bp.route("/consolidate", methods=["POST"])
def consolidate_memory():
    """Consolidate episodic memory into semantic patterns.

    Extracts tool effectiveness, common tool chains, and severity profiles
    from past scan traces.
    """
    try:
        if not scan_memory_store:
            return jsonify({"error": "Memory system not available"}), 503

        result = scan_memory_store.consolidate()
        return jsonify({"success": True, **result})
    except Exception as e:
        logger.error(f"💥 Error consolidating memory: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ── Recommendations ───────────────────────────────────────────────


@scan_memory_bp.route("/recommendations", methods=["POST"])
def get_recommendations():
    """Get memory-based recommendations for a target.

    Combines episodic recall (similar past scans) with semantic patterns
    (tool effectiveness by target type).
    """
    try:
        if not scan_memory_store:
            return jsonify({"error": "Memory system not available"}), 503

        data = request.get_json()
        if not data or "target" not in data:
            return jsonify({"error": "target is required"}), 400

        target = data["target"]
        target_profile = data.get("target_profile")
        recs = scan_memory_store.get_recommendations(target, target_profile)
        return jsonify({"success": True, **recs})
    except Exception as e:
        logger.error(f"💥 Error getting recommendations: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ── Completed Sessions ────────────────────────────────────────────


@scan_memory_bp.route("/completed-sessions", methods=["GET"])
def list_completed_sessions():
    """List all completed (archived) scan sessions."""
    try:
        if not session_manager:
            return jsonify({"error": "Session manager not available"}), 503

        sessions = session_manager.list_completed_sessions()
        limit = request.args.get("limit", 0, type=int)
        if limit > 0:
            sessions = sessions[:limit]
        return jsonify(
            {
                "success": True,
                "count": len(sessions),
                "sessions": sessions,
            }
        )
    except Exception as e:
        logger.error(f"💥 Error listing completed sessions: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@scan_memory_bp.route("/completed-sessions/<session_id>", methods=["GET"])
def get_completed_session(session_id):
    """Get full details of a completed (archived) session."""
    try:
        if not session_manager:
            return jsonify({"error": "Session manager not available"}), 503

        session = session_manager.get_completed_session(session_id)
        if not session:
            return jsonify({"error": "Completed session not found"}), 404

        return jsonify({"success": True, "session": session})
    except Exception as e:
        logger.error(f"💥 Error getting completed session: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
