from flask import Blueprint, jsonify
import logging
from datetime import datetime

from server_core.enhanced_process_manager import EnhancedProcessManager

logger = logging.getLogger(__name__)

api_process_pool_stats_bp = Blueprint("api_process_pool_stats", __name__)

enhanced_process_manager = EnhancedProcessManager()


@api_process_pool_stats_bp.route("/api/process/pool-stats", methods=["GET"])
def get_process_pool_stats():
    """Get process pool statistics and performance metrics"""
    try:
        stats = enhanced_process_manager.get_comprehensive_stats()

        logger.info(f"📊 Process pool stats retrieved | Active workers: {stats['process_pool']['active_workers']}")
        return jsonify({
            "success": True,
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting pool stats: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
