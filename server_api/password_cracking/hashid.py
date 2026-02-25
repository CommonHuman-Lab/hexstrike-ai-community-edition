# server_api/password_cracking/hashid.py

from flask import Blueprint, request, jsonify
from server_core.command_executor import execute_command
import logging

logger = logging.getLogger(__name__)
api_password_cracking_hashid_bp = Blueprint("api_password_cracking_hashid", __name__)

@api_password_cracking_hashid_bp.route("/api/tools/password_cracking/hashid", methods=["POST"])
def hashid():
    """
    Identify the type of a given hash value using hashID.

    Endpoint: POST /api/tools/password_cracking/hashid

    Description:
        This endpoint identifies the type of a provided hash string using the hashID tool.
        It accepts a hash value and optional additional arguments for hashID, executes the identification,
        and returns the result.

    Request (application/json):
        {
            "hash_value": "<string, required> The hash string to identify.",
            "additional_args": "<string, optional> Extra CLI flags for hashID (e.g., '-m', '-e')."
        }

    Response (application/json):
        Success:
            {
                "success": true,
                "output": "<string> Raw output from hashID indicating possible hash types."
            }
        Error (missing hash_value):
            {
                "error": "hash_value parameter is required"
            }
        Error (internal failure):
            {
                "error": "An error occurred during hash identification",
                "details": "<string> Exception details"
            }

    Notes:
        - Only a single hash value is supported per request.
        - Additional hashID CLI arguments can be provided via 'additional_args'.
        - The endpoint returns the raw output from hashID, which may include multiple possible hash types.
    """
    try:
        params = request.json
        hash_value = params.get("hash_value", "")
        additional_args = params.get("additional_args", "")

        if not hash_value:
            logger.warning("🔍 Hash identifier called without hash_value parameter")
            return jsonify({
                "error": "hash_value parameter is required"
            }), 400

        command = f"hashid {hash_value} {additional_args}"
        result = execute_command(command, use_cache=True)
        if result.get("success"):
            logger.info(f"✅ Hash identification completed for {hash_value}")
        else:
            logger.error(f"❌ Hash identification failed for {hash_value}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"❌ Error during hash identification: {str(e)}")
        return jsonify({
            "error": "An error occurred during hash identification",
            "details": str(e)
        }), 500