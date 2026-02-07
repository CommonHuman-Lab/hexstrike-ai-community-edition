"""
Result Analyzer — Parses raw tool output into structured security findings.

Transforms noisy stdout/stderr from security tools into severity-classified,
LLM-friendly findings. Each tool gets a dedicated parser; unknown tools
fall back to keyword-based heuristic detection.

Design notes (senior-engineering/clean-code):
  - SRP: only parses output, does not execute tools or manage sessions
  - Guard clauses for early returns
  - Named constants for all thresholds
  - Small focused functions (< 20 lines each)
"""

import logging
import re
from typing import Any, Dict, List

from core.scan_session import Finding

logger = logging.getLogger(__name__)

# Severity keywords used by heuristic fallback parser
CRITICAL_KEYWORDS = [
    "remote code execution",
    "rce",
    "critical",
    "unauthenticated",
    "arbitrary code",
    "command injection",
    "pre-auth",
]
HIGH_KEYWORDS = [
    "high",
    "sql injection",
    "sqli",
    "xss",
    "cross-site scripting",
    "ssrf",
    "server-side request forgery",
    "lfi",
    "local file inclusion",
    "rfi",
    "remote file inclusion",
    "xxe",
    "deserialization",
    "privilege escalation",
    "authentication bypass",
]
MEDIUM_KEYWORDS = [
    "medium",
    "csrf",
    "cross-site request forgery",
    "open redirect",
    "information disclosure",
    "directory listing",
    "path traversal",
    "idor",
    "misconfiguration",
    "weak cipher",
]
LOW_KEYWORDS = [
    "low",
    "missing header",
    "cookie without",
    "x-frame-options",
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "clickjacking",
]

# Minimum output length worth analyzing
MIN_OUTPUT_LENGTH = 10


class ResultAnalyzer:
    """Parses security tool output into structured Finding objects."""

    def __init__(self) -> None:
        self._parsers: Dict[str, callable] = {
            "nmap": self._parse_nmap,
            "nuclei": self._parse_nuclei,
            "nikto": self._parse_nikto,
            "sqlmap": self._parse_sqlmap,
            "gobuster": self._parse_gobuster,
            "ffuf": self._parse_ffuf,
            "wpscan": self._parse_wpscan,
            "shodan": self._parse_shodan,
            "censys": self._parse_censys,
            "hibp": self._parse_hibp,
        }

    def analyze(self, tool_name: str, target: str, result: Dict[str, Any]) -> List[Finding]:
        """Parse a tool result dict into a list of Findings."""
        if not result.get("success"):
            return []

        output = result.get("stdout", "") or result.get("output", "")
        if isinstance(output, dict):
            return self._parse_api_result(tool_name, target, output)

        if len(str(output)) < MIN_OUTPUT_LENGTH:
            return []

        parser = self._parsers.get(tool_name.lower().replace("-", "_"))
        if parser:
            return parser(target, str(output))

        return self._heuristic_parse(tool_name, target, str(output))

    def _parse_api_result(self, tool_name: str, target: str, data: Dict[str, Any]) -> List[Finding]:
        """Route API-based tool results (dict output) to the right parser."""
        parser = self._parsers.get(tool_name.lower().replace("-", "_"))
        if not parser:
            return []
        # API parsers accept dict data via a second code path
        return parser(target, data)

    # ── Tool-specific parsers ────────────────────────────────────────

    def _parse_nmap(self, target: str, output) -> List[Finding]:
        if isinstance(output, dict):
            return []
        findings: List[Finding] = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Open port lines: "80/tcp open http Apache/2.4.41"
            port_match = re.match(r"(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)", line)
            if port_match:
                port, proto, service, version = port_match.groups()
                findings.append(
                    Finding(
                        tool="nmap",
                        severity="info",
                        title=f"Open port {port}/{proto}: {service}",
                        detail=version.strip() if version else "",
                        target=target,
                        confidence=0.95,
                    )
                )
            # Vulnerability scripts
            if "VULNERABLE" in line.upper():
                findings.append(
                    Finding(
                        tool="nmap",
                        severity="high",
                        title=f"Nmap script vulnerability detected",
                        detail=line,
                        target=target,
                        confidence=0.85,
                    )
                )
        return findings

    def _parse_nuclei(self, target: str, output) -> List[Finding]:
        if isinstance(output, dict):
            return []
        findings: List[Finding] = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Nuclei format: [template-id] [protocol] [severity] url
            nuclei_match = re.match(r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)", line)
            if nuclei_match:
                template_id, protocol, severity, url = nuclei_match.groups()
                severity = severity.strip().lower()
                if severity not in ("critical", "high", "medium", "low", "info"):
                    severity = "info"
                findings.append(
                    Finding(
                        tool="nuclei",
                        severity=severity,
                        title=f"{template_id} ({protocol})",
                        detail=url.strip(),
                        target=target,
                        confidence=0.90,
                    )
                )
        return findings

    def _parse_nikto(self, target: str, output) -> List[Finding]:
        if isinstance(output, dict):
            return []
        findings: List[Finding] = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or not line.startswith("+"):
                continue
            severity = self._classify_severity(line)
            findings.append(
                Finding(
                    tool="nikto",
                    severity=severity,
                    title=line.lstrip("+ "),
                    target=target,
                    confidence=0.75,
                )
            )
        return findings

    def _parse_sqlmap(self, target: str, output) -> List[Finding]:
        if isinstance(output, dict):
            return []
        findings: List[Finding] = []
        for line in output.split("\n"):
            line = line.strip()
            if "is vulnerable" in line.lower() or "injectable" in line.lower():
                findings.append(
                    Finding(
                        tool="sqlmap",
                        severity="critical",
                        title="SQL Injection confirmed",
                        detail=line,
                        target=target,
                        confidence=0.95,
                    )
                )
            elif "parameter" in line.lower() and "might be" in line.lower():
                findings.append(
                    Finding(
                        tool="sqlmap",
                        severity="high",
                        title="Potential SQL Injection",
                        detail=line,
                        target=target,
                        confidence=0.70,
                    )
                )
        return findings

    def _parse_gobuster(self, target: str, output) -> List[Finding]:
        if isinstance(output, dict):
            return []
        findings: List[Finding] = []
        for line in output.split("\n"):
            line = line.strip()
            match = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if match:
                path, status = match.groups()
                severity = "info"
                if status in ("200", "301", "302"):
                    severity = "low"
                if any(s in path.lower() for s in ["admin", "backup", "config", ".env", ".git"]):
                    severity = "medium"
                findings.append(
                    Finding(
                        tool="gobuster",
                        severity=severity,
                        title=f"Discovered: {path} (HTTP {status})",
                        target=target,
                        confidence=0.90,
                    )
                )
        return findings

    def _parse_ffuf(self, target: str, output) -> List[Finding]:
        if isinstance(output, dict):
            return []
        findings: List[Finding] = []
        for line in output.split("\n"):
            line = line.strip()
            match = re.match(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
            if match:
                path, status, size = match.groups()
                findings.append(
                    Finding(
                        tool="ffuf",
                        severity="info",
                        title=f"Fuzz hit: {path} (HTTP {status}, {size}B)",
                        target=target,
                        confidence=0.85,
                    )
                )
        return findings

    def _parse_wpscan(self, target: str, output) -> List[Finding]:
        if isinstance(output, dict):
            return []
        findings: List[Finding] = []
        for line in output.split("\n"):
            line = line.strip()
            if "[!]" in line:
                severity = self._classify_severity(line)
                findings.append(
                    Finding(
                        tool="wpscan",
                        severity=severity,
                        title=line.replace("[!]", "").strip(),
                        target=target,
                        confidence=0.85,
                    )
                )
        return findings

    def _parse_shodan(self, target: str, data) -> List[Finding]:
        if not isinstance(data, dict):
            return self._heuristic_parse("shodan", target, str(data))
        findings: List[Finding] = []
        vulns = data.get("vulns", {})
        if isinstance(vulns, dict):
            for cve_id in vulns:
                findings.append(
                    Finding(
                        tool="shodan",
                        severity="high",
                        title=f"Known vulnerability: {cve_id}",
                        detail=str(vulns[cve_id])[:200] if isinstance(vulns[cve_id], str) else "",
                        target=target,
                        confidence=0.80,
                    )
                )
        summary = data.get("summary", {})
        for port in summary.get("ports", []):
            findings.append(
                Finding(
                    tool="shodan",
                    severity="info",
                    title=f"Exposed port: {port}",
                    target=target,
                    confidence=0.95,
                )
            )
        return findings

    def _parse_censys(self, target: str, data) -> List[Finding]:
        if not isinstance(data, dict):
            return self._heuristic_parse("censys", target, str(data))
        findings: List[Finding] = []
        result = data.get("result", data)
        summary = result.get("summary", {})
        for port in summary.get("open_ports", []):
            findings.append(
                Finding(
                    tool="censys",
                    severity="info",
                    title=f"Exposed port: {port}",
                    target=target,
                    confidence=0.95,
                )
            )
        return findings

    def _parse_hibp(self, target: str, data) -> List[Finding]:
        if not isinstance(data, dict):
            return self._heuristic_parse("hibp", target, str(data))
        findings: List[Finding] = []
        if data.get("found"):
            count = data.get("breach_count", 0)
            findings.append(
                Finding(
                    tool="hibp",
                    severity="high" if count > 3 else "medium",
                    title=f"Email found in {count} data breach(es)",
                    detail=", ".join(data.get("breach_names", [])[:10]),
                    target=target,
                    confidence=0.95,
                )
            )
        return findings

    # ── Heuristic fallback ───────────────────────────────────────────

    def _heuristic_parse(self, tool_name: str, target: str, output: str) -> List[Finding]:
        """Keyword-based severity detection for tools without a dedicated parser."""
        findings: List[Finding] = []
        lines = output.split("\n")
        for line in lines:
            line_lower = line.strip().lower()
            if not line_lower or len(line_lower) < 5:
                continue
            severity = self._classify_severity(line_lower)
            if severity in ("critical", "high", "medium"):
                findings.append(
                    Finding(
                        tool=tool_name,
                        severity=severity,
                        title=line.strip()[:120],
                        target=target,
                        confidence=0.50,
                    )
                )
        return findings

    def _classify_severity(self, text: str) -> str:
        """Classify a single line of text into a severity bucket."""
        text_lower = text.lower()
        if any(kw in text_lower for kw in CRITICAL_KEYWORDS):
            return "critical"
        if any(kw in text_lower for kw in HIGH_KEYWORDS):
            return "high"
        if any(kw in text_lower for kw in MEDIUM_KEYWORDS):
            return "medium"
        if any(kw in text_lower for kw in LOW_KEYWORDS):
            return "low"
        return "info"
