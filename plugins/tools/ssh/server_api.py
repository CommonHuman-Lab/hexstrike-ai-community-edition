"""
Plugin: ssh_client — server_api.py
Flask Blueprint for the SSH metadata + execution-request plugin.
"""

import logging
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)

blueprint = Blueprint("plugin_ssh_client", __name__)


@blueprint.route("/api/plugins/ssh", methods=["POST"])
def ssh_metadata():
    """
    SSH execution-request endpoint.

    Expects JSON:
      {
        "host": "192.168.1.10",
        "port": 22,
        "username": "root",
        "password": "secret",
        "command": "ls -la"
      }
    """

    data = request.get_json(force=True) or {}

    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({
            "success": False,
            "error": "Missing required parameter: host"
        }), 400

    try:
        port = int(data.get("port", 22))
    except (TypeError, ValueError):
        port = 22

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    command = (data.get("command") or "").strip()

    # SAFE: No execution — only returning structured request
    return jsonify({
        "success": True,
        "action": "ssh_execute",
        "payload": {
            "host": host,
            "port": port,
            "username": username or None,
            "password": password or None,
            "command": command or None
        }
    })
