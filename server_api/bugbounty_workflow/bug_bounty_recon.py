from flask import Blueprint, request, jsonify
from datetime import datetime
import logging

from server_core.workflows.bugbounty.target import BugBountyTarget
from server_core.workflows.bugbounty.workflow import BugBountyWorkflowManager

logger = logging.getLogger(__name__)

api_bugbounty_workflow_bug_bounty_recon_bp = Blueprint("api_bugbounty_workflow_bug_bounty_recon", __name__)

bugbounty_manager = BugBountyWorkflowManager()


@api_bugbounty_workflow_bug_bounty_recon_bp.route("/api/bugbounty/reconnaissance-workflow", methods=["POST"])
def create_reconnaissance_workflow():
    """Create comprehensive reconnaissance workflow for bug bounty hunting"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']
        scope = data.get('scope', [])
        out_of_scope = data.get('out_of_scope', [])
        program_type = data.get('program_type', 'web')

        logger.info(f"Creating reconnaissance workflow for {domain}")

        target = BugBountyTarget(
            domain=domain,
            scope=scope,
            out_of_scope=out_of_scope,
            program_type=program_type
        )

        workflow = bugbounty_manager.create_reconnaissance_workflow(target)

        logger.info(f"Reconnaissance workflow created for {domain}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error creating reconnaissance workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
