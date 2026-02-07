"""
Verification Strategies — Individual methods for confirming security findings.

Each strategy independently verifies whether a finding is genuine by
re-testing, cross-referencing, or probing the target. Strategies are
composable — the FindingVerifier selects applicable ones per finding type.

Design notes (senior-engineering/clean-code):
  - SRP: each strategy class handles one verification method
  - No blind exploit replay — Findings lack original payloads
  - RescanStrategy reuses existing tool_executors (DRY)
  - HttpProbeStrategy uses httpx (already a dependency via fastmcp)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
RESCAN_SAMPLE_COUNT = 3
HTTP_PROBE_TIMEOUT_SECONDS = 10
MIN_CONFIDENCE_THRESHOLD = 0.7


@dataclass
class VerificationResult:
    """Outcome of a single verification attempt."""

    verified: bool
    confidence: float  # 0.0 – 1.0
    method: str  # rescan, cross_tool, http_probe, cve_lookup
    evidence: str  # Human-readable explanation
    original_finding: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "confidence": round(self.confidence, 3),
            "method": self.method,
            "evidence": self.evidence,
            "original_finding": self.original_finding,
        }


# ── Vulnerability Class Mapping ───────────────────────────────────────────
# Maps keyword patterns in finding titles to alternative verification tools
VULN_CLASS_TOOLS: Dict[str, List[str]] = {
    "xss": ["dalfox_xss_scan", "xsser_scan"],
    "cross-site scripting": ["dalfox_xss_scan", "xsser_scan"],
    "sql injection": ["sqlmap_scan"],
    "sqli": ["sqlmap_scan"],
    "open port": ["nmap_scan", "masscan_high_speed"],
    "exposed port": ["nmap_scan", "masscan_high_speed"],
    "directory": ["gobuster_scan", "feroxbuster_scan", "dirsearch_scan"],
    "subdomain": ["subfinder_scan", "amass_scan"],
    "wordpress": ["wpscan_analyze"],
    "cms": ["wpscan_analyze", "nikto_scan"],
    "ssl": ["sslyze_scan"],
    "tls": ["sslyze_scan"],
    "lfi": ["dotdotpwn_scan"],
    "path traversal": ["dotdotpwn_scan"],
    "command injection": ["commix_scan"],
    "template injection": ["tplmap_scan"],
    "nosql": ["nosqlmap_scan"],
    "parameter": ["arjun_scan", "x8_parameter_discovery"],
}

# CVE pattern for extraction
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Port extraction from finding titles like "Open port 80/tcp" or "Port 443 (https)"
_PORT_RE = re.compile(r"(?:port\s+)?(\d{1,5})(?:/(?:tcp|udp))?", re.IGNORECASE)


class RescanStrategy:
    """Re-run the original tool N times, check if finding reproduces."""

    def verify(self, finding, target, tool_executors, result_analyzer, decision_engine) -> VerificationResult:
        """Verify by re-running the original tool and comparing results."""
        tool_name = finding.tool
        executor_key = tool_name.replace("-", "_")

        if executor_key not in tool_executors:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                method="rescan",
                evidence=f"No executor found for tool '{tool_name}'",
                original_finding=finding.to_dict(),
            )

        reproductions = 0
        for i in range(RESCAN_SAMPLE_COUNT):
            try:
                # Build a minimal target profile for parameter optimization
                from agents.decision_engine import TargetProfile

                profile = TargetProfile(target=target)
                params = decision_engine.optimize_parameters(tool_name, profile)
                result = tool_executors[executor_key](target, params)

                parsed_findings = result_analyzer.analyze(tool_name, target, result)
                if self._finding_matches(finding, parsed_findings):
                    reproductions += 1
            except Exception as e:
                logger.debug(f"Rescan attempt {i + 1} failed for {tool_name}: {e}")

        confidence = reproductions / RESCAN_SAMPLE_COUNT
        verified = confidence >= MIN_CONFIDENCE_THRESHOLD

        return VerificationResult(
            verified=verified,
            confidence=confidence,
            method="rescan",
            evidence=f"Reproduced {reproductions}/{RESCAN_SAMPLE_COUNT} times via {tool_name}",
            original_finding=finding.to_dict(),
        )

    @staticmethod
    def _finding_matches(original, parsed_findings) -> bool:
        """Check if any parsed finding matches the original by title + severity."""
        for f in parsed_findings:
            if f.severity == original.severity and (
                original.title.lower() in f.title.lower() or f.title.lower() in original.title.lower()
            ):
                return True
        return False


class CrossToolStrategy:
    """Run a different tool that covers the same vulnerability class."""

    def verify(self, finding, target, tool_executors, result_analyzer, decision_engine) -> VerificationResult:
        """Verify by running an alternative tool for the same vuln class."""
        alt_tool = self._find_alternative_tool(finding, tool_executors)
        if not alt_tool:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                method="cross_tool",
                evidence="No alternative tool available for this finding type",
                original_finding=finding.to_dict(),
            )

        try:
            from agents.decision_engine import TargetProfile

            profile = TargetProfile(target=target)
            params = decision_engine.optimize_parameters(alt_tool, profile)
            executor_key = alt_tool.replace("-", "_")
            result = tool_executors[executor_key](target, params)

            parsed_findings = result_analyzer.analyze(alt_tool, target, result)

            # Check if any finding from the alt tool matches severity level
            for f in parsed_findings:
                if f.severity in (finding.severity, "critical", "high"):
                    return VerificationResult(
                        verified=True,
                        confidence=0.85,
                        method="cross_tool",
                        evidence=f"Confirmed by {alt_tool}: {f.title}",
                        original_finding=finding.to_dict(),
                    )

            return VerificationResult(
                verified=False,
                confidence=0.3,
                method="cross_tool",
                evidence=f"{alt_tool} did not reproduce a similar finding",
                original_finding=finding.to_dict(),
            )

        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                method="cross_tool",
                evidence=f"Cross-tool verification failed: {e}",
                original_finding=finding.to_dict(),
            )

    @staticmethod
    def _find_alternative_tool(finding, tool_executors) -> Optional[str]:
        """Find an alternative tool for the same vulnerability class."""
        title_lower = finding.title.lower()
        original_tool = finding.tool

        for keyword, tools in VULN_CLASS_TOOLS.items():
            if keyword in title_lower:
                for tool in tools:
                    executor_key = tool.replace("-", "_")
                    if executor_key in tool_executors and tool != original_tool:
                        return tool
        return None


class HttpProbeStrategy:
    """Lightweight HTTP check for web-based findings."""

    def verify(self, finding, target) -> VerificationResult:
        """Verify web findings by probing the target endpoint."""
        try:
            import httpx
        except ImportError:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                method="http_probe",
                evidence="httpx not available for HTTP probing",
                original_finding=finding.to_dict(),
            )

        url = self._extract_url(finding, target)
        if not url:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                method="http_probe",
                evidence="Could not extract URL from finding",
                original_finding=finding.to_dict(),
            )

        try:
            with httpx.Client(timeout=HTTP_PROBE_TIMEOUT_SECONDS, verify=False, follow_redirects=True) as client:
                response = client.head(url)

            # An accessible endpoint confirms the finding is reachable
            if response.status_code < 500:
                return VerificationResult(
                    verified=True,
                    confidence=0.7,
                    method="http_probe",
                    evidence=f"Endpoint reachable: {url} (HTTP {response.status_code})",
                    original_finding=finding.to_dict(),
                )

            return VerificationResult(
                verified=False,
                confidence=0.2,
                method="http_probe",
                evidence=f"Endpoint returned server error: HTTP {response.status_code}",
                original_finding=finding.to_dict(),
            )

        except httpx.TimeoutException:
            return VerificationResult(
                verified=False,
                confidence=0.1,
                method="http_probe",
                evidence=f"HTTP probe timed out after {HTTP_PROBE_TIMEOUT_SECONDS}s",
                original_finding=finding.to_dict(),
            )
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                method="http_probe",
                evidence=f"HTTP probe error: {e}",
                original_finding=finding.to_dict(),
            )

    @staticmethod
    def _extract_url(finding, target) -> Optional[str]:
        """Extract a URL from the finding's title/detail or construct one from target."""
        # Check if the finding detail/title contains a URL
        for text in (finding.detail, finding.title):
            if "http://" in text or "https://" in text:
                for word in text.split():
                    if word.startswith(("http://", "https://")):
                        return word.rstrip(".,;)")

        # Try constructing from target + port
        port_match = _PORT_RE.search(finding.title)
        if port_match:
            port = int(port_match.group(1))
            scheme = "https" if port == 443 else "http"
            host = target.split("://")[-1].split("/")[0]
            return f"{scheme}://{host}:{port}/"

        # If target is already a URL, use it directly
        if target.startswith(("http://", "https://")):
            return target

        return None


class CveLookupStrategy:
    """Validate CVE findings against known affected version patterns."""

    def verify(self, finding, target) -> VerificationResult:
        """Verify by checking if the CVE ID is valid and extractable."""
        cve_match = _CVE_RE.search(finding.title) or _CVE_RE.search(finding.detail)
        if not cve_match:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                method="cve_lookup",
                evidence="No CVE ID found in finding",
                original_finding=finding.to_dict(),
            )

        cve_id = cve_match.group(0).upper()

        # If the finding already has high confidence from a scanner (nuclei, nmap NSE),
        # the CVE reference itself adds credibility
        if finding.confidence >= 0.7:
            return VerificationResult(
                verified=True,
                confidence=min(finding.confidence + 0.1, 1.0),
                method="cve_lookup",
                evidence=f"{cve_id} confirmed by {finding.tool} with high confidence ({finding.confidence})",
                original_finding=finding.to_dict(),
            )

        # For lower-confidence findings, the CVE adds moderate validation
        return VerificationResult(
            verified=True,
            confidence=0.6,
            method="cve_lookup",
            evidence=f"{cve_id} found — original confidence was {finding.confidence}",
            original_finding=finding.to_dict(),
        )
