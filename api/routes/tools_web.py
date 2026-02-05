"""
Web Security Tools API Routes
Handles dirb, nikto, sqlmap, wpscan, ffuf, dalfox, xsser, jaeles, and zap tools
"""

import logging

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# Create blueprint
tools_web_bp = Blueprint("tools_web", __name__, url_prefix="/api/tools")

# Dependencies will be injected via init_app
execute_command = None


def init_app(exec_command):
    """Initialize blueprint with dependencies"""
    global execute_command
    execute_command = exec_command


@tools_web_bp.route("/dirb", methods=["POST"])
def dirb():
    """Execute dirb with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dirb called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"dirb {url} {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Dirb scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirb scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dirb endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/nikto", methods=["POST"])
def nikto():
    """Execute nikto with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Nikto called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"nikto -h {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Nikto scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 Nikto scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in nikto endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🎯 SQLMap called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"sqlmap -u {url} --batch"

        if data:
            command += f' --data="{data}"'

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 SQLMap scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in sqlmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 WPScan called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"wpscan --url {url}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting WPScan: {url}")
        result = execute_command(command)
        logger.info(f"📊 WPScan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wpscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/ffuf", methods=["POST"])
def ffuf():
    """Execute FFuf web fuzzer with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        mode = params.get("mode", "directory")
        match_codes = params.get("match_codes", "200,204,301,302,307,401,403")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 FFuf called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"ffuf"

        if mode == "directory":
            command += f" -u {url}/FUZZ -w {wordlist}"
        elif mode == "vhost":
            command += f" -u {url} -H 'Host: FUZZ' -w {wordlist}"
        elif mode == "parameter":
            command += f" -u {url}?FUZZ=value -w {wordlist}"
        else:
            command += f" -u {url} -w {wordlist}"

        command += f" -mc {match_codes}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")
        result = execute_command(command)
        logger.info(f"📊 FFuf fuzzing completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ffuf endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/dalfox", methods=["POST"])
def dalfox():
    """Execute dalfox XSS scanner with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dalfox called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"dalfox url {url}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Dalfox XSS scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dalfox scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dalfox endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/xsser", methods=["POST"])
def xsser():
    """Execute xsser cross-site scripting framework with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 XSSer called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"xsser --url {url}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting XSSer scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 XSSer scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in xsser endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/jaeles", methods=["POST"])
def jaeles():
    """Execute jaeles automated security testing with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Jaeles called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"jaeles scan -u {url}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Jaeles security test: {url}")
        result = execute_command(command)
        logger.info(f"📊 Jaeles test completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in jaeles endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/zap", methods=["POST"])
def zap():
    """Execute OWASP ZAP proxy with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 ZAP called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"zap-cli quick-scan {url}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting OWASP ZAP scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 ZAP scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in zap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/commix", methods=["POST"])
def commix():
    """Execute Commix for command injection testing"""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        level = params.get("level", 1)
        technique = params.get("technique", "")
        batch = params.get("batch", True)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Commix called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"commix -u {url} --level {level}"

        if data:
            command += f" --data={data}"

        if cookie:
            command += f" --cookie={cookie}"

        if technique:
            command += f" --technique={technique}"

        if batch:
            command += " --batch"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"💉 Starting Commix: {url}")
        result = execute_command(command)
        logger.info(f"📊 Commix completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in commix endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/nosqlmap", methods=["POST"])
def nosqlmap():
    """Execute NoSQLMap for NoSQL injection testing"""
    try:
        params = request.json
        url = params.get("url", "")
        database = params.get("database", "mongodb")
        post_data = params.get("post_data", "")
        cookie = params.get("cookie", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 NoSQLMap called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"nosqlmap -u {url} --dbtype {database}"

        if post_data:
            command += f" --data={post_data}"

        if cookie:
            command += f" --cookie={cookie}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"💉 Starting NoSQLMap: {url}")
        result = execute_command(command)
        logger.info(f"📊 NoSQLMap completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in nosqlmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/tplmap", methods=["POST"])
def tplmap():
    """Execute Tplmap for server-side template injection"""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        engine = params.get("engine", "")
        level = params.get("level", 1)
        os_cmd = params.get("os_cmd", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Tplmap called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"tplmap -u {url} --level {level}"

        if data:
            command += f" -d {data}"

        if cookie:
            command += f" --cookie={cookie}"

        if engine:
            command += f" -e {engine}"

        if os_cmd:
            command += f" --os-cmd={os_cmd}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"💉 Starting Tplmap: {url}")
        result = execute_command(command)
        logger.info(f"📊 Tplmap completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in tplmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@tools_web_bp.route("/sslyze", methods=["POST"])
def sslyze():
    """Execute SSLyze for SSL/TLS configuration analysis"""
    try:
        params = request.json
        target = params.get("target", "")
        certinfo = params.get("certinfo", True)
        heartbleed = params.get("heartbleed", True)
        robot = params.get("robot", True)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🔐 SSLyze called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"sslyze {target}"

        if certinfo:
            command += " --certinfo"

        if heartbleed:
            command += " --heartbleed"

        if robot:
            command += " --robot"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔐 Starting SSLyze: {target}")
        result = execute_command(command)
        logger.info(f"📊 SSLyze completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in sslyze endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
