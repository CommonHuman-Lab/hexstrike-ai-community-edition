"""
Reconnaissance Tools API Routes
Handles OSINT, subdomain enumeration, and reconnaissance tools
"""

import logging

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# Create blueprint
tools_recon_bp = Blueprint("tools_recon", __name__, url_prefix="/api/tools")

# Dependencies will be injected via init_app
execute_command = None
execute_command_with_recovery = None


def init_app(exec_command, exec_command_with_recovery):
    """Initialize blueprint with dependencies"""
    global execute_command, execute_command_with_recovery
    execute_command = exec_command
    execute_command_with_recovery = exec_command_with_recovery


@tools_recon_bp.route("/theharvester", methods=["POST"])
def theharvester():
    """Execute theHarvester for email and subdomain harvesting"""
    try:
        params = request.json
        target = params.get("target", "")
        source = params.get("source", "all")
        limit = params.get("limit", 500)
        dns_brute = params.get("dns_brute", False)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 TheHarvester called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"theHarvester -d {target} -b {source} -l {limit}"

        if dns_brute:
            command += " -c"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting TheHarvester: {target}")
        result = execute_command(command)
        logger.info(f"📊 TheHarvester completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in theharvester endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_recon_bp.route("/sherlock", methods=["POST"])
def sherlock():
    """Execute Sherlock for username investigation across social networks"""
    try:
        params = request.json
        username = params.get("username", "")
        timeout = params.get("timeout", 60)
        print_found = params.get("print_found", True)
        csv_output = params.get("csv", False)
        additional_args = params.get("additional_args", "")

        if not username:
            logger.warning("🎯 Sherlock called without username parameter")
            return jsonify({"error": "Username parameter is required"}), 400

        command = f"sherlock {username} --timeout {timeout}"

        if print_found:
            command += " --print-found"

        if csv_output:
            command += " --csv"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Sherlock investigation: {username}")
        result = execute_command(command)
        logger.info(f"📊 Sherlock completed for {username}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in sherlock endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_recon_bp.route("/spiderfoot", methods=["POST"])
def spiderfoot():
    """Execute SpiderFoot for OSINT automation"""
    try:
        params = request.json
        target = params.get("target", "")
        modules = params.get("modules", "")
        output_format = params.get("output_format", "json")
        max_threads = params.get("max_threads", 10)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 SpiderFoot called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"spiderfoot -s {target} -o {output_format} --max-threads {max_threads} -q"

        if modules:
            command += f" -m {modules}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕷️ Starting SpiderFoot: {target}")
        result = execute_command(command)
        logger.info(f"📊 SpiderFoot completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in spiderfoot endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_recon_bp.route("/trufflehog", methods=["POST"])
def trufflehog():
    """Execute TruffleHog for Git repository secret scanning"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "git")
        only_verified = params.get("only_verified", False)
        json_output = params.get("json_output", True)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 TruffleHog called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"trufflehog {scan_type} {target} --no-update"

        if only_verified:
            command += " --only-verified"

        if json_output:
            command += " --json"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔑 Starting TruffleHog scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 TruffleHog completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in trufflehog endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_recon_bp.route("/aquatone", methods=["POST"])
def aquatone():
    """Execute Aquatone for visual inspection of websites"""
    try:
        params = request.json
        targets = params.get("targets", "")
        out_dir = params.get("out_dir", "/tmp/aquatone")
        threads = params.get("threads", 8)
        ports = params.get("ports", "80,443,8080,8443")
        additional_args = params.get("additional_args", "")

        if not targets:
            logger.warning("🎯 Aquatone called without targets parameter")
            return jsonify({"error": "Targets parameter is required"}), 400

        command = f"echo '{targets}' | aquatone -out {out_dir} -threads {threads} -ports {ports}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📸 Starting Aquatone visual inspection")
        result = execute_command(command)
        logger.info(f"📊 Aquatone completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in aquatone endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_recon_bp.route("/subjack", methods=["POST"])
def subjack():
    """Execute Subjack for subdomain takeover detection"""
    try:
        params = request.json
        target = params.get("target", "")
        input_file = params.get("input_file", "")
        threads = params.get("threads", 10)
        timeout = params.get("timeout", 30)
        ssl = params.get("ssl", False)
        additional_args = params.get("additional_args", "")

        if not target and not input_file:
            logger.warning("🎯 Subjack called without target or input_file parameter")
            return jsonify({"error": "Target or input_file parameter is required"}), 400

        if input_file:
            command = f"subjack -w {input_file} -t {threads} -timeout {timeout} -a -v"
        else:
            command = f"subjack -d {target} -t {threads} -timeout {timeout} -a -v"

        if ssl:
            command += " -ssl"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Subjack subdomain takeover check")
        result = execute_command(command)
        logger.info(f"📊 Subjack completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in subjack endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_recon_bp.route("/recon-ng", methods=["POST"])
def recon_ng():
    """Execute Recon-ng for web reconnaissance"""
    try:
        params = request.json
        target = params.get("target", "")
        workspace = params.get("workspace", "default")
        module = params.get("module", "")
        script = params.get("script", "")
        additional_args = params.get("additional_args", "")

        if not target and not script:
            logger.warning("🎯 Recon-ng called without target or script parameter")
            return jsonify({"error": "Target or script parameter is required"}), 400

        command = f"recon-ng -w {workspace} --no-check"

        if module:
            command += f" -m {module}"

        if target:
            command += f" -o SOURCE={target}"

        if script:
            command += f" -r {script}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Recon-ng: {target or 'script execution'}")
        result = execute_command(command)
        logger.info(f"📊 Recon-ng completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in recon-ng endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
