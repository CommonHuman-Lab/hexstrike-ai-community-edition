"""
Input Validator — Target and parameter validation for HexStrike API requests.

Validates target formats (IP, CIDR, domain, URL), detects private IP ranges,
and sanitizes input before tool execution. Operates at the Flask API boundary
to catch invalid input early.

Design notes (senior-engineering/clean-code):
  - No DNS resolution (avoids latency and DNS rebinding attacks)
  - Domains pass through private IP checks (only literal IPs are checked)
  - Guard clauses for all validation paths
"""

import ipaddress
import logging
import re
from typing import Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
MAX_TARGET_LENGTH = 500
ALLOWED_SCHEMES = {"http", "https"}

# RFC1918, loopback, link-local, and other non-routable ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Matches valid domain labels (RFC 1123)
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*" r"[a-zA-Z]{2,63}$")

_PORT_RANGE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


class InputValidator:
    """Validates and sanitizes targets and parameters for tool execution."""

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Validate a target string (IP, CIDR, domain, or URL).

        Returns:
            (is_valid, error_message) — error_message is empty when valid.
        """
        if not target or not target.strip():
            return False, "Target cannot be empty"

        target = target.strip()

        if len(target) > MAX_TARGET_LENGTH:
            return False, f"Target exceeds {MAX_TARGET_LENGTH} character limit"

        # URL format
        if "://" in target:
            return self._validate_url(target)

        # CIDR notation
        if "/" in target:
            return self._validate_cidr(target)

        # Bare IP address
        if self._is_ip_address(target):
            return True, ""

        # Domain name
        if _DOMAIN_RE.match(target):
            return True, ""

        # IP:port format
        if ":" in target:
            host, _, port = target.rpartition(":")
            if self._is_ip_address(host) and port.isdigit():
                return True, ""

        return False, f"Invalid target format: {target}"

    def is_private_ip(self, ip_str: str) -> bool:
        """Check if a literal IP address is in a private/non-routable range.

        Only checks if the input parses as an IP address. Domain names
        are NOT resolved and always return False.
        """
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        return any(addr in network for network in PRIVATE_NETWORKS)

    def validate_port_range(self, port_str: str) -> bool:
        """Validate a port or port range string (e.g. '80', '1-1024')."""
        if not port_str:
            return False

        match = _PORT_RANGE_RE.match(port_str.strip())
        if not match:
            return False

        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else start

        return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end

    def sanitize_target(self, target: str) -> str:
        """Strip whitespace and normalize URL schemes."""
        target = target.strip()
        if target.startswith("HTTP://"):
            target = "http://" + target[7:]
        elif target.startswith("HTTPS://"):
            target = "https://" + target[8:]
        return target

    # ── Private helpers ────────────────────────────────────────────────────

    def _validate_url(self, url: str) -> Tuple[bool, str]:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False, f"Scheme '{parsed.scheme}' not allowed. Use http or https."
        if not parsed.hostname:
            return False, "URL has no hostname"
        return True, ""

    def _validate_cidr(self, cidr: str) -> Tuple[bool, str]:
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True, ""
        except ValueError:
            return False, f"Invalid CIDR notation: {cidr}"

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
