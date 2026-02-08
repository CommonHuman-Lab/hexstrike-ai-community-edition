"""
Effectiveness Tracker — Dynamic tool effectiveness learning for HexStrike.

Replaces hardcoded tool effectiveness floats in the decision engine with
learned scores from actual scan history. Reads from ScanMemory's existing
patterns.json (no duplicate data store) and blends learned data with
defaults using a configurable confidence weight.

Design notes (senior-engineering/clean-code):
  - Read adapter over ScanMemory — no separate persistence
  - Write path: record_outcome() → ScanMemory.add_learning() →
    consolidate() extracts patterns → patterns.json updated
  - Backward compatible: falls back to hardcoded defaults when no data
  - Thread-safe reads via pattern snapshot on refresh()
"""

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
DEFAULT_EFFECTIVENESS = 0.5
MIN_OBSERVATIONS_FOR_OVERRIDE = 3
LEARNED_WEIGHT = 0.7  # How much learned data weighs vs hardcoded defaults


class EffectivenessTracker:
    """Bridges scan memory patterns with the decision engine's tool selection."""

    def __init__(self, scan_memory, default_scores: Dict[str, Dict[str, float]]):
        """
        Args:
            scan_memory: ScanMemory instance (reads patterns via get_patterns()).
            default_scores: The hardcoded effectiveness map from
                IntelligentDecisionEngine._initialize_tool_effectiveness().
        """
        self._scan_memory = scan_memory
        self._default_scores = default_scores
        self._learned_cache: Dict[str, Dict[str, float]] = {}
        self._observation_counts: Dict[str, Dict[str, int]] = {}
        self.refresh()

    def get_effectiveness(self, tool: str, target_type: str, target_subtype: str = "") -> float:
        """Get blended effectiveness score for a tool against a target type.

        When target_subtype is provided, tries compound key first (e.g.
        "web_application:wordpress") for subtype-specific scores, then
        falls back to the base target_type key.

        Priority:
          1. Learned score (if enough observations) blended with default
          2. Default hardcoded score
          3. DEFAULT_EFFECTIVENESS fallback
        """
        default = self._default_scores.get(target_type, {}).get(tool, DEFAULT_EFFECTIVENESS)

        # Try subtype-specific learned score first, then base target_type
        learned = None
        observations = 0
        if target_subtype:
            compound_key = f"{target_type}:{target_subtype}"
            learned = self._learned_cache.get(compound_key, {}).get(tool)
            observations = self._observation_counts.get(compound_key, {}).get(tool, 0)

        if learned is None:
            learned = self._learned_cache.get(target_type, {}).get(tool)
            observations = self._observation_counts.get(target_type, {}).get(tool, 0)

        if learned is None:
            return default

        if observations < MIN_OBSERVATIONS_FOR_OVERRIDE:
            return default

        # Blend: weighted average of learned and default
        return (LEARNED_WEIGHT * learned) + ((1 - LEARNED_WEIGHT) * default)

    def get_best_tools(self, target_type: str, top_n: int = 10, target_subtype: str = "") -> List[Tuple[str, float]]:
        """Get the top N tools for a target type, ranked by blended effectiveness."""
        # Merge all known tools from both sources
        all_tools = set(self._default_scores.get(target_type, {}).keys())
        all_tools |= set(self._learned_cache.get(target_type, {}).keys())
        if target_subtype:
            all_tools |= set(self._learned_cache.get(f"{target_type}:{target_subtype}", {}).keys())

        scored = [
            (tool, self.get_effectiveness(tool, target_type, target_subtype=target_subtype)) for tool in all_tools
        ]
        scored.sort(key=lambda x: -x[1])
        return scored[:top_n]

    def get_comparison(self, target_type: str, target_subtype: str = "") -> List[Dict[str, Any]]:
        """Get a comparison of learned vs default scores for a target type."""
        all_tools = set(self._default_scores.get(target_type, {}).keys())
        all_tools |= set(self._learned_cache.get(target_type, {}).keys())
        if target_subtype:
            all_tools |= set(self._learned_cache.get(f"{target_type}:{target_subtype}", {}).keys())

        comparison = []
        for tool in sorted(all_tools):
            default_score = self._default_scores.get(target_type, {}).get(tool)
            learned_score = self._learned_cache.get(target_type, {}).get(tool)
            observations = self._observation_counts.get(target_type, {}).get(tool, 0)
            blended = self.get_effectiveness(tool, target_type, target_subtype=target_subtype)

            comparison.append(
                {
                    "tool": tool,
                    "default": default_score,
                    "learned": learned_score,
                    "observations": observations,
                    "blended": round(blended, 3),
                    "source": "learned" if observations >= MIN_OBSERVATIONS_FOR_OVERRIDE else "default",
                }
            )
        return comparison

    def record_outcome(self, tool: str, target_type: str, findings: List[Dict], target_subtype: str = "") -> None:
        """Record a tool execution outcome for future learning.

        Appends to ScanMemory's learning store. Actual pattern extraction
        happens when ScanMemory.consolidate() runs.
        """
        finding_count = len(findings)
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        learning = {
            "type": "tool_outcome",
            "tool": tool,
            "target_type": target_type,
            "target_subtype": target_subtype,
            "finding_count": finding_count,
            "severity_counts": severity_counts,
            "has_critical": severity_counts.get("critical", 0) > 0,
            "has_high": severity_counts.get("high", 0) > 0,
        }

        try:
            self._scan_memory.add_learning(learning)
            logger.debug(f"Recorded outcome for {tool} on {target_type}: {finding_count} findings")
        except Exception as e:
            logger.warning(f"Failed to record tool outcome: {e}")

    def refresh(self) -> None:
        """Reload learned patterns from ScanMemory's patterns.json.

        Scan memory produces tool_effectiveness patterns in this format:
          - conditions: "target_type=web_application" (or with subtype)
          - tool_details: [{"tool": "nuclei", "effectiveness": 0.95}, ...]
          - source_episodes: int (observation count)

        Uses copy-on-write: builds new caches in locals, then swaps references
        atomically so concurrent readers never see partially populated data.
        """
        try:
            patterns = self._scan_memory.get_patterns()
        except Exception:
            patterns = []

        # Build in locals — no mutation of live caches during parsing
        new_learned: Dict[str, Dict[str, float]] = {}
        new_counts: Dict[str, Dict[str, int]] = {}

        for pattern in patterns:
            if pattern.get("category") != "tool_effectiveness":
                continue

            # Parse target_type and optional target_subtype from conditions
            # e.g. "target_type=web_application" or "target_type=web_application,target_subtype=wordpress"
            conditions = pattern.get("conditions", "")
            target_type = ""
            target_subtype = ""
            for part in conditions.split(","):
                part = part.strip()
                if part.startswith("target_type="):
                    target_type = part.split("=", 1)[1]
                elif part.startswith("target_subtype="):
                    target_subtype = part.split("=", 1)[1]

            if not target_type:
                continue

            # Use compound key when subtype is present for granular scoring
            cache_key = f"{target_type}:{target_subtype}" if target_subtype else target_type

            tool_details = pattern.get("tool_details", [])
            observation_count = pattern.get("source_episodes", 0)

            for entry in tool_details:
                tool = entry.get("tool", "")
                score = entry.get("effectiveness", DEFAULT_EFFECTIVENESS)
                if not tool:
                    continue

                new_learned.setdefault(cache_key, {})[tool] = score
                new_counts.setdefault(cache_key, {})[tool] = observation_count

        # Atomic swap — readers see either the old or new state, never partial
        self._learned_cache = new_learned
        self._observation_counts = new_counts

        learned_count = sum(len(v) for v in new_learned.values())
        if learned_count:
            logger.info(f"Loaded {learned_count} learned effectiveness scores from scan memory")
