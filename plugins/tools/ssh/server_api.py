"""
Plugin: ssh_client — server_api.py
Flask Blueprint for the SSH metadata plugin.

This file is the server-side half of the plugin.
It must expose a module-level `blueprint` (a Flask Blueprint instance).
The plugin loader registers it with the Flask app automatically.
"""

import logging
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)

blueprint = Blueprint("plugin_ssh_client", __name__)


@blueprint.route("/api/plugins/ssh", methods=["POST"])
def ssh_metadata():
    """
    SSH metadata endpoint.

    Expects JSON:
      {
        "host": "192.168.1.10",   # required
        "port": 22,               # optional
        "username": "root"        # optional
      }

    Returns:
      {
        "success": true,
        "message": "SSH metadata received",
        "host": "...",
        "port": ...,
        "username": "..."
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

    # Safe placeholder — no command execution
    return jsonify({
        "success": True,
        "message": "SSH metadata received",
        "host": host,
        "port": port,
        "username": username or None
    })
