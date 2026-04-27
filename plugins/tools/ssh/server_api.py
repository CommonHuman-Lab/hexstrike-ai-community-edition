import logging
import paramiko
from flask import Blueprint, request, jsonify
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)
blueprint = Blueprint("plugin_ssh_client", __name__)

# -------------------------
# Thread pool (safe blocking SSH execution)
# -------------------------
executor = ThreadPoolExecutor(max_workers=10)

# -------------------------
# SSH session cache
# -------------------------
ssh_sessions = {}


def get_session_key(host, username, port):
    return f"{username}@{host}:{port}"


# -------------------------
# CONNECT
# -------------------------
def ssh_connect(host, port, username, password):
    logger.warning(f"[SSH CONNECT] initiating connection to {host}:{port} as {username}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=10
    )

    logger.warning(f"[SSH CONNECT] connection established to {host}:{port}")

    return client


# -------------------------
# EXECUTE COMMAND (RELIABLE)
# -------------------------
def ssh_execute(client, command):
    logger.warning(f"[SSH EXEC] command received: {command}")

    stdin, stdout, stderr = client.exec_command(command)

    exit_code = stdout.channel.recv_exit_status()

    output = stdout.read().decode(errors="ignore")
    error = stderr.read().decode(errors="ignore")

    logger.warning(
        f"[SSH OUTPUT] exit_code={exit_code} stdout={output} stderr={error}"
    )

    return {
        "exit_code": exit_code,
        "output": output,
        "error": error
    }


# -------------------------
# API ENTRY
# -------------------------
@blueprint.route("/api/plugins/ssh", methods=["POST"])
def ssh_entry():
    data = request.get_json(force=True) or {}

    host = data.get("host")
    port = int(data.get("port", 22))
    username = data.get("username")
    password = data.get("password")
    command = data.get("command")
    disconnect = data.get("disconnect", False)

    logger.warning(
        f"[SSH ENTRY] host={host}, port={port}, user={username}, "
        f"command={command}, disconnect={disconnect}"
    )

    if not host or not username:
        logger.error("[SSH ENTRY] missing host or username")
        return jsonify({"success": False, "error": "Missing host or username"}), 400

    key = get_session_key(host, username, port)

    try:
        # -------------------------
        # DISCONNECT
        # -------------------------
        if disconnect:
            logger.warning(f"[SSH DISCONNECT] key={key}")

            if key in ssh_sessions:
                try:
                    ssh_sessions[key].close()
                except Exception as e:
                    logger.error(f"[SSH DISCONNECT ERROR] {e}")

                ssh_sessions.pop(key, None)

            return jsonify({"success": True, "message": "Disconnected"})

        # -------------------------
        # CONNECT (if needed)
        # -------------------------
        if key not in ssh_sessions:
            if not password:
                logger.error("[SSH CONNECT] missing password")
                return jsonify({"success": False, "error": "Password required"}), 400

            logger.warning(f"[SSH SESSION] creating new session for {key}")

            client = ssh_connect(host, port, username, password)
            ssh_sessions[key] = client

        else:
            logger.warning(f"[SSH SESSION] reusing session for {key}")

        client = ssh_sessions[key]

        # -------------------------
        # EXECUTE COMMAND
        # -------------------------
        if command:
            logger.warning(f"[SSH EXECUTE REQUEST] {command}")

            future = executor.submit(ssh_execute, client, command)
            result = future.result()

            logger.warning(f"[SSH RESPONSE READY] {result}")

            return jsonify({
                "success": True,
                **result
            })

        # -------------------------
        # JUST CONNECTED
        # -------------------------
        logger.warning("[SSH ENTRY] connected without command")

        return jsonify({
            "success": True,
            "message": "Connected"
        })

    except Exception as e:
        logger.error(f"[SSH ERROR] {e}")

        if key in ssh_sessions:
            try:
                ssh_sessions[key].close()
            except Exception:
                pass
            ssh_sessions.pop(key, None)

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500