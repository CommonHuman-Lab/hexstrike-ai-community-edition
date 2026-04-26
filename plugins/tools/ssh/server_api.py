import logging
import paramiko
import uuid
import time
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
blueprint = Blueprint("plugin_ssh_client", __name__)

# 🔐 In-memory session store
ssh_sessions = {}

@blueprint.route("/api/plugins/ssh/connect", methods=["POST"])
def ssh_connect():
    data = request.get_json(force=True) or {}

    host = data.get("host")
    port = int(data.get("port", 22))
    username = data.get("username")
    password = data.get("password")

    if not host:
        return jsonify({"success": False, "error": "Missing host"}), 400

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(hostname=host, port=port, username=username, password=password)

        shell = client.invoke_shell()

        session_id = str(uuid.uuid4())

        ssh_sessions[session_id] = {
            "client": client,
            "shell": shell
        }

        return jsonify({"success": True, "session_id": session_id})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    
@blueprint.route("/api/plugins/ssh/send", methods=["POST"])
def ssh_send():
    data = request.get_json(force=True) or {}

    session_id = data.get("session_id")
    command = data.get("command")

    if session_id not in ssh_sessions:
        return jsonify({"success": False, "error": "Invalid session"}), 400

    shell = ssh_sessions[session_id]["shell"]

    try:
        shell.send(command + "\n")

        #time.sleep(0.5)

        output = ""
        while shell.recv_ready():
            output += shell.recv(4096).decode(errors="ignore")

        return jsonify({"success": True, "output": output})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    
@blueprint.route("/api/plugins/ssh/disconnect", methods=["POST"])
def ssh_disconnect():
    data = request.get_json(force=True) or {}

    session_id = data.get("session_id")

    if session_id not in ssh_sessions:
        return jsonify({"success": False, "error": "Invalid session"}), 400

    session = ssh_sessions.pop(session_id)

    session["shell"].close()
    session["client"].close()

    return jsonify({"success": True})