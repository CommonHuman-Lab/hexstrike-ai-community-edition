"""
Knowledge Graph API Routes — Entity-relationship graph endpoints.

Exposes the KnowledgeGraph for session ingestion, entity querying,
and attack path discovery.

Design notes (senior-engineering/clean-code):
  - Same blueprint + init_app() DI pattern as scan_intelligence.py
  - Guard clauses for input validation
  - Delegates all logic to KnowledgeGraph (SRP)
"""

import logging

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

knowledge_graph_bp = Blueprint("knowledge_graph", __name__, url_prefix="/api/knowledge-graph")

# Dependencies injected via init_app
graph = None
session_manager = None


def init_app(knowledge_graph, sess_mgr):
    """Initialize blueprint with dependencies."""
    global graph, session_manager
    graph = knowledge_graph
    session_manager = sess_mgr


@knowledge_graph_bp.route("/ingest", methods=["POST"])
def ingest_session():
    """Ingest a scan session's findings into the knowledge graph.

    Body: {"session_id": str}
    """
    try:
        data = request.get_json()
        if not data or "session_id" not in data:
            return jsonify({"error": "session_id is required"}), 400

        session_id = data["session_id"]
        session = session_manager.get(session_id)

        # Try completed sessions if not found in active
        if not session:
            completed = session_manager.get_completed_session(session_id)
            if completed:
                findings = completed.get("findings", [])
                target = completed.get("target", "")
                result = graph.ingest_findings(session_id, target, findings)
                return jsonify({"success": True, **result})
            return jsonify({"error": f"Session '{session_id}' not found"}), 404

        findings = [f.to_dict() for f in session.findings]
        result = graph.ingest_findings(session_id, session.target, findings)

        logger.info(f"Ingested session {session_id} into knowledge graph")
        return jsonify({"success": True, **result})

    except Exception as e:
        logger.error(f"Error ingesting to knowledge graph: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@knowledge_graph_bp.route("/entities", methods=["GET"])
def list_entities():
    """List or filter entities in the knowledge graph.

    Query params: type (host|service|vulnerability|credential), name (substring)
    """
    try:
        entity_type = request.args.get("type")
        name_filter = request.args.get("name")

        entities = graph.query(entity_type=entity_type)

        if name_filter:
            name_lower = name_filter.lower()
            entities = [e for e in entities if name_lower in e.get("name", "").lower()]

        return jsonify({"success": True, "entities": entities, "count": len(entities)})

    except Exception as e:
        logger.error(f"Error querying entities: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@knowledge_graph_bp.route("/paths", methods=["GET"])
def find_paths():
    """Find attack paths between entities.

    Query params: from_id (entity ID), to_type (entity type), max_depth (int, default 5)
    """
    try:
        from_id = request.args.get("from_id")
        to_type = request.args.get("to_type")

        if not from_id or not to_type:
            return jsonify({"error": "from_id and to_type are required"}), 400

        max_depth = request.args.get("max_depth", 5, type=int)
        paths = graph.find_attack_paths(from_id, to_type, max_depth=max_depth)

        return jsonify({"success": True, "paths": paths, "count": len(paths)})

    except Exception as e:
        logger.error(f"Error finding attack paths: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@knowledge_graph_bp.route("/related/<entity_id>", methods=["GET"])
def get_related(entity_id):
    """Get entities related to a given entity.

    Query params: rel_type (optional filter by relationship type)
    """
    try:
        rel_type = request.args.get("rel_type")
        related = graph.get_related(entity_id, rel_type=rel_type)

        return jsonify({"success": True, "related": related, "count": len(related)})

    except Exception as e:
        logger.error(f"Error getting related entities: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@knowledge_graph_bp.route("/summary", methods=["GET"])
def get_summary():
    """Get knowledge graph summary statistics."""
    try:
        summary = graph.get_summary()
        return jsonify({"success": True, **summary})

    except Exception as e:
        logger.error(f"Error getting graph summary: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
