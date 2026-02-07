"""
Finding Correlator — Deduplicates and cross-references findings from multiple tools.

When Shodan, Censys, and Nmap all report the same open port, this module
merges them into a single correlated finding with higher confidence.

Design notes (senior-engineering/clean-code):
  - SRP: only correlates, does not parse or manage sessions
  - DRY: single dedup key function used everywhere
  - KISS: string-similarity heuristic, no ML needed
"""

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List

from core.scan_session import Finding

logger = logging.getLogger(__name__)

# Two findings are "same" if their dedup keys match
CONFIDENCE_BOOST_PER_CORROBORATION = 0.05
MAX_CONFIDENCE = 0.99


def _dedup_key(finding: Finding) -> str:
    """Deterministic key that groups equivalent findings across tools."""
    severity = finding.severity.lower()
    title_norm = finding.title.lower().strip()

    # Normalize common port-finding patterns
    # "Open port 80/tcp: http" and "Exposed port: 80" → same key
    port_match = re.search(r"port[:\s]*(\d+)", title_norm)
    if port_match:
        return f"port:{port_match.group(1)}:{severity}"

    # Normalize CVE references
    cve_match = re.search(r"(cve-\d{4}-\d+)", title_norm)
    if cve_match:
        return f"cve:{cve_match.group(1)}"

    # Normalize breach findings
    if "breach" in title_norm:
        return f"breach:{finding.target}:{severity}"

    # Fallback: first 60 chars of normalized title + severity
    return f"{title_norm[:60]}:{severity}"


class FindingCorrelator:
    """Merges duplicate findings and boosts confidence for corroborated ones."""

    def correlate(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Deduplicate and correlate a list of findings.

        Returns a list of correlated finding dicts, each with:
          - All original fields from the highest-confidence instance
          - corroborated_by: list of tools that reported the same thing
          - correlated_confidence: boosted confidence value
        """
        if not findings:
            return []

        groups: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            key = _dedup_key(f)
            groups[key].append(f)

        correlated: List[Dict[str, Any]] = []
        for key, group in groups.items():
            # Pick the finding with highest confidence as the primary
            primary = max(group, key=lambda f: f.confidence)
            tools = sorted({f.tool for f in group})

            boost = CONFIDENCE_BOOST_PER_CORROBORATION * (len(tools) - 1)
            correlated_confidence = min(primary.confidence + boost, MAX_CONFIDENCE)

            entry = primary.to_dict()
            entry["corroborated_by"] = tools
            entry["corroboration_count"] = len(tools)
            entry["correlated_confidence"] = round(correlated_confidence, 3)
            entry["dedup_key"] = key
            correlated.append(entry)

        # Sort: critical first, then by correlated confidence desc
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        correlated.sort(
            key=lambda e: (
                severity_order.get(e["severity"], 5),
                -e["correlated_confidence"],
            )
        )

        logger.info(
            f"🔗 Correlated {len(findings)} findings → {len(correlated)} unique "
            f"({len(findings) - len(correlated)} duplicates removed)"
        )
        return correlated

    def summarize(self, correlated: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate an LLM-friendly summary from correlated findings."""
        if not correlated:
            return {
                "total_unique_findings": 0,
                "severity_breakdown": {},
                "top_findings": [],
                "narrative": "No findings to report.",
            }

        severity_counts: Dict[str, int] = defaultdict(int)
        for f in correlated:
            severity_counts[f["severity"]] += 1

        top_findings = correlated[:10]

        # Build concise narrative
        parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count > 0:
                parts.append(f"{count} {sev}")

        narrative = f"Found {len(correlated)} unique findings: {', '.join(parts)}."

        multi_tool = [f for f in correlated if f["corroboration_count"] > 1]
        if multi_tool:
            narrative += f" {len(multi_tool)} finding(s) confirmed by multiple tools."

        return {
            "total_unique_findings": len(correlated),
            "severity_breakdown": dict(severity_counts),
            "multi_tool_confirmed": len(multi_tool),
            "top_findings": top_findings,
            "narrative": narrative,
        }
