"""
Plugin: ssh_client — server_api.py
Flask Blueprint for the SSH metadata + execution-request plugin.

This file is the server-side half of the plugin.
It exposes a module-level `blueprint` (a Flask Blueprint instance).
The plugin loader registers it with the Flask app automatically.
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
        "host": "192.168.1.10",   # required
        "port": 22,               # optional
        "username": "root",       # optional
        "command": "ls -la"       # optional
      }

    Returns:
      {
        "success": true,
        "action": "ssh_execute",
        "payload": {
            "host": "...",
            "port": ...,
            "username": "...",
            "command": "..."
        }
      }
    """

    data = request.get_json(force=True) or {}

    # Required: host
    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({
            "success": False,
            "error": "Missing required parameter: host"
        }), 400

    # Optional: port
    try:
        port = int(data.get("port", 22))
    except (TypeError, ValueError):
        port = 22

    # Optional: username
    username = (data.get("username") or "").strip()

    # Optional: command
    command = (data.get("command") or "").strip()

    # SAFE: No execution here — only returning a structured request
    return jsonify({
        "success": True,
        "action": "ssh_execute",
        "payload": {
            "host": host,
            "port": port,
            "username": username or None,
            "command": command or None
        }
    })
