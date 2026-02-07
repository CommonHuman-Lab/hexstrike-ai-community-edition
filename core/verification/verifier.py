"""
Finding Verifier — Multi-strategy verification engine for HexStrike findings.

Orchestrates verification strategies to confirm whether security findings
are genuine. Selects applicable strategies based on finding type and runs
them with bounded concurrency.

Design notes (senior-engineering/clean-code):
  - Delegates actual verification to strategy classes (SRP)
  - Strategy selection is finding-type-aware (no pointless probes)
  - Bounded concurrency via ThreadPoolExecutor cap
  - Integrates with risk_classifier to skip dangerous re-runs
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from core.verification.strategies import (
    CrossToolStrategy,
    CveLookupStrategy,
    HttpProbeStrategy,
    RescanStrategy,
    VerificationResult,
)

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
MAX_CONCURRENT_VERIFICATIONS = 3
VERIFICATION_TIMEOUT_SECONDS = 120

# Severity ordering for filtering
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class FindingVerifier:
    """Orchestrates multi-strategy verification of security findings."""

    def __init__(self, tool_executors, result_analyzer, decision_engine, risk_classifier=None):
        """
        Args:
            tool_executors: Dict of {executor_key: callable} from hexstrike_server.
            result_analyzer: ResultAnalyzer instance for parsing re-scan output.
            decision_engine: IntelligentDecisionEngine for parameter optimization.
            risk_classifier: Optional risk_classifier module for safety checks.
        """
        self._tool_executors = tool_executors
        self._result_analyzer = result_analyzer
        self._decision_engine = decision_engine
        self._risk_classifier = risk_classifier

        # Initialize strategy instances
        self._strategies = {
            "rescan": RescanStrategy(),
            "cross_tool": CrossToolStrategy(),
            "http_probe": HttpProbeStrategy(),
            "cve_lookup": CveLookupStrategy(),
        }

    def verify_finding(
        self,
        finding,
        target: str,
        methods: Optional[List[str]] = None,
    ) -> VerificationResult:
        """Verify a single finding using selected strategies.

        Args:
            finding: Finding dataclass instance from scan_session.
            target: Target string (IP, domain, URL).
            methods: List of strategy names to try. Defaults to ["rescan", "http_probe"].

        Returns:
            Best VerificationResult (highest confidence).
        """
        if methods is None:
            methods = ["rescan", "http_probe"]

        applicable = self._select_strategies(finding, methods)
        if not applicable:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                method="none",
                evidence="No applicable verification strategies for this finding type",
                original_finding=finding.to_dict(),
            )

        results = []
        for strategy_name in applicable:
            try:
                result = self._run_strategy(strategy_name, finding, target)
                results.append(result)
                # Short-circuit: if we got high-confidence verification, stop
                if result.verified and result.confidence >= 0.85:
                    break
            except Exception as e:
                logger.warning(f"Strategy '{strategy_name}' failed: {e}")

        if not results:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                method="none",
                evidence="All verification strategies failed",
                original_finding=finding.to_dict(),
            )

        # Return the result with highest confidence
        return max(results, key=lambda r: r.confidence)

    def batch_verify(
        self,
        findings: list,
        target: str,
        min_severity: str = "medium",
        methods: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Verify multiple findings in parallel with bounded concurrency.

        Args:
            findings: List of Finding instances.
            target: Target string.
            min_severity: Minimum severity to verify (skip low/info).
            methods: Strategy names to use.

        Returns:
            List of VerificationResult dicts.
        """
        min_level = SEVERITY_ORDER.get(min_severity, 2)
        filtered = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_level]

        if not filtered:
            return []

        results = []
        worker_count = min(len(filtered), MAX_CONCURRENT_VERIFICATIONS)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {executor.submit(self.verify_finding, f, target, methods): f for f in filtered}
            for future in as_completed(future_map):
                try:
                    result = future.result(timeout=VERIFICATION_TIMEOUT_SECONDS)
                    results.append(result.to_dict())
                except Exception as e:
                    finding = future_map[future]
                    results.append(
                        VerificationResult(
                            verified=False,
                            confidence=0.0,
                            method="error",
                            evidence=f"Verification error: {e}",
                            original_finding=finding.to_dict(),
                        ).to_dict()
                    )

        logger.info(
            f"Batch verification complete: {len(results)} findings verified, "
            f"{sum(1 for r in results if r['verified'])} confirmed"
        )
        return results

    def _select_strategies(self, finding, requested: List[str]) -> List[str]:
        """Filter strategies based on finding type and safety."""
        applicable = []
        title_lower = finding.title.lower()
        tool_name = finding.tool

        for strategy_name in requested:
            if strategy_name not in self._strategies:
                continue

            # Skip cross_tool for exploit-class tools (don't auto-run exploits)
            if strategy_name == "cross_tool" and self._risk_classifier:
                from core.security.risk_classifier import is_exploit

                if is_exploit(tool_name):
                    logger.debug(f"Skipping cross_tool for exploit tool '{tool_name}'")
                    continue

            # http_probe only applies to web/port findings
            if strategy_name == "http_probe":
                is_web_finding = any(
                    kw in title_lower for kw in ("http", "port", "endpoint", "url", "directory", "path", "web")
                )
                if not is_web_finding:
                    continue

            # cve_lookup only applies to CVE findings
            if strategy_name == "cve_lookup":
                if "cve" not in title_lower and "cve" not in finding.detail.lower():
                    continue

            applicable.append(strategy_name)

        return applicable

    def _run_strategy(self, strategy_name: str, finding, target: str) -> VerificationResult:
        """Execute a single verification strategy."""
        strategy = self._strategies[strategy_name]

        if strategy_name in ("rescan", "cross_tool"):
            return strategy.verify(
                finding,
                target,
                self._tool_executors,
                self._result_analyzer,
                self._decision_engine,
            )
        else:
            # http_probe and cve_lookup only need finding + target
            return strategy.verify(finding, target)
