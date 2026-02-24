import logging
import requests
import time
from typing import Dict, Any, Optional

import server_core.config_core as config_core

DEFAULT_HEXSTRIKE_SERVER = config_core.get("DEFAULT_HEXSTRIKE_SERVER", "http://127.0.0.1:8888")
DEFAULT_REQUEST_TIMEOUT = config_core.get("COMMAND_TIMEOUT", 300)
MAX_RETRIES = config_core.get("MAX_RETRIES", 3)

class HexStrikeClient:
    """Enhanced client for communicating with the HexStrike AI API Server"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

        connected = False
        for i in range(MAX_RETRIES):
            try:
                logging.info(f"🔗 Attempting to connect to HexStrike AI API at {server_url} (attempt {i+1}/{MAX_RETRIES})")
                try:
                    test_response = self.session.get(f"{self.server_url}/ping", timeout=5)
                    test_response.raise_for_status()
                    connected = True
                    break
                except requests.exceptions.ConnectionError:
                    logging.warning(f"🔌 Connection refused to {server_url}. Make sure the HexStrike AI server is running.")
                    time.sleep(2)
                except Exception as e:
                    logging.warning(f"⚠️  Connection test failed: {str(e)}")
                    time.sleep(2)
            except Exception as e:
                logging.warning(f"❌ Connection attempt {i+1} failed: {str(e)}")
                time.sleep(2)

        if not connected:
            error_msg = f"Failed to establish connection to HexStrike AI API Server at {server_url} after {MAX_RETRIES} attempts"
            logging.error(error_msg)

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if params is None:
            params = {}
        url = f"{self.server_url}/{endpoint}"
        try:
            logging.debug(f"📡 GET {url} with params: {params}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logging.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}/{endpoint}"
        try:
            logging.debug(f"📡 POST {url} with data: {json_data}")
            response = self.session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logging.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        return self.safe_post("api/command", {"command": command, "use_cache": use_cache})

    def check_health(self) -> Dict[str, Any]:
        return self.safe_get("health")