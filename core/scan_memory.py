"""
Scan Memory — Episodic and semantic memory for scan intelligence.

Implements the memory hierarchy from skills/autonomous-mode/loki-mode/references/memory-system.md:
  - Episodic memory: specific scan traces (what happened during scan X?)
  - Semantic memory: generalized patterns (target type Y benefits from tools Z)

Also implements consolidation (episodic → semantic) and retrieval.

Design notes (senior-engineering/architecture):
  - SRP: this module only manages memory CRUD and pattern extraction
  - KISS: JSON files, no vector DB — substring matching for retrieval
  - Named constants, guard clauses, early returns
  - Separate from session_store.py (sessions are live state, memory is knowledge)
"""

import json
import logging
import os
import time
from collections import Counter
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Named constants
MEMORY_DIR_NAME = "memory"
EPISODIC_DIR_NAME = "episodic"
SEMANTIC_FILE_NAME = "patterns.json"
LEARNINGS_FILE_NAME = "learnings.json"
MAX_EPISODIC_TRACES = 500
MIN_PATTERN_OCCURRENCES = 2
PATTERN_CONFIDENCE_BASE = 0.6
PATTERN_CONFIDENCE_BOOST = 0.1


class ScanMemory:
    """Manages episodic and semantic memory for scan intelligence.

    Directory layout:
        <data_dir>/memory/episodic/   — one JSON per completed scan trace
        <data_dir>/memory/patterns.json — extracted tool-effectiveness patterns
        <data_dir>/memory/learnings.json — extracted error/success learnings
    """

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._memory_dir = os.path.join(data_dir, MEMORY_DIR_NAME)
        self._episodic_dir = os.path.join(self._memory_dir, EPISODIC_DIR_NAME)
        self._patterns_path = os.path.join(self._memory_dir, SEMANTIC_FILE_NAME)
        self._learnings_path = os.path.join(self._memory_dir, LEARNINGS_FILE_NAME)
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        os.makedirs(self._episodic_dir, exist_ok=True)

    # ══════════════════════════════════════════════════════════════════
    # EPISODIC MEMORY — Specific scan traces
    # ══════════════════════════════════════════════════════════════════

    def save_episode(self, session_dict: Dict[str, Any]) -> bool:
        """Save a completed scan session as an episodic trace."""
        session_id = session_dict.get("session_id", "unknown")
        trace = {
            "id": f"ep-{session_id}",
            "session_id": session_id,
            "target": session_dict.get("target", ""),
            "target_profile": session_dict.get("target_profile", {}),
            "timestamp": time.time(),
            "iterations": session_dict.get("iterations", 0),
            "tools_executed": session_dict.get("tools_executed", []),
            "total_findings": session_dict.get("total_findings", 0),
            "severity_counts": session_dict.get("severity_counts", {}),
            "findings_summary": self._summarize_findings(session_dict.get("findings", [])),
            "outcome": self._determine_outcome(session_dict),
        }
        try:
            path = os.path.join(self._episodic_dir, f"{session_id}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(trace, f, indent=2, default=str)
            self._prune_episodic()
            logger.info(f"🧠 Saved episodic trace for session {session_id}")
            return True
        except (OSError, TypeError) as exc:
            logger.error(f"🧠 Failed to save episode {session_id}: {exc}")
            return False

    def list_episodes(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List episodic traces, most recent first."""
        if not os.path.isdir(self._episodic_dir):
            return []
        episodes = []
        for fname in os.listdir(self._episodic_dir):
            if not fname.endswith(".json"):
                continue
            path = os.path.join(self._episodic_dir, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                episodes.append(data)
            except (json.JSONDecodeError, OSError):
                continue
        episodes.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
        return episodes[:limit]

    def get_episode(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific episodic trace."""
        path = os.path.join(self._episodic_dir, f"{session_id}.json")
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def search_episodes(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search episodic traces by target or tool name (substring match)."""
        query_lower = query.lower()
        results = []
        for episode in self.list_episodes(limit=MAX_EPISODIC_TRACES):
            target = episode.get("target", "").lower()
            tools = " ".join(episode.get("tools_executed", [])).lower()
            profile_type = episode.get("target_profile", {}).get("target_type", "").lower()
            if query_lower in target or query_lower in tools or query_lower in profile_type:
                results.append(episode)
                if len(results) >= limit:
                    break
        return results

    # ══════════════════════════════════════════════════════════════════
    # SEMANTIC MEMORY — Generalized patterns
    # ══════════════════════════════════════════════════════════════════

    def get_patterns(self) -> List[Dict[str, Any]]:
        """Load all learned patterns."""
        if not os.path.exists(self._patterns_path):
            return []
        try:
            with open(self._patterns_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

    def get_learnings(self) -> List[Dict[str, Any]]:
        """Load all learnings (error/success observations)."""
        if not os.path.exists(self._learnings_path):
            return []
        try:
            with open(self._learnings_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

    def get_recommendations(self, target: str, target_profile: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Retrieve memory-based recommendations for a target.

        Combines episodic recall (similar past scans) with semantic patterns
        (tool effectiveness by target type). This is the 'before_task_execution'
        pattern from the memory-system reference.
        """
        similar_scans = self.search_episodes(target, limit=5)
        patterns = self.get_patterns()
        target_type = (target_profile or {}).get("target_type", "")

        relevant_patterns = [
            p for p in patterns if target_type and target_type.lower() in p.get("conditions", "").lower()
        ]

        recommended_tools = []
        avoid_tools = []
        for p in relevant_patterns:
            if p.get("category") == "tool_effectiveness":
                if p.get("confidence", 0) >= 0.7:
                    recommended_tools.extend(p.get("recommended_tools", []))
                elif p.get("confidence", 0) < 0.3:
                    avoid_tools.extend(p.get("avoid_tools", []))

        return {
            "similar_past_scans": len(similar_scans),
            "past_scan_summaries": [
                {
                    "target": s.get("target"),
                    "tools": s.get("tools_executed", []),
                    "findings": s.get("total_findings", 0),
                    "outcome": s.get("outcome", "unknown"),
                }
                for s in similar_scans[:3]
            ],
            "relevant_patterns": [
                {"pattern": p.get("pattern"), "confidence": p.get("confidence")} for p in relevant_patterns[:5]
            ],
            "recommended_tools": list(set(recommended_tools))[:10],
            "avoid_tools": list(set(avoid_tools))[:5],
        }

    # ══════════════════════════════════════════════════════════════════
    # CONSOLIDATION — Episodic → Semantic
    # ══════════════════════════════════════════════════════════════════

    def consolidate(self) -> Dict[str, Any]:
        """Extract patterns from episodic memory into semantic memory.

        Implements the episodic-to-semantic consolidation from
        skills/autonomous-mode/loki-mode/references/memory-system.md.

        Extracts:
          1. Tool effectiveness by target type
          2. Common tool chains (tools that work well together)
          3. Error patterns (tools that often fail for certain targets)
        """
        episodes = self.list_episodes(limit=MAX_EPISODIC_TRACES)
        if len(episodes) < MIN_PATTERN_OCCURRENCES:
            return {"patterns_extracted": 0, "message": "Not enough episodes to consolidate"}

        patterns = []

        # Pattern 1: Tool effectiveness per target type
        patterns.extend(self._extract_tool_effectiveness(episodes))

        # Pattern 2: Common tool chains
        patterns.extend(self._extract_tool_chains(episodes))

        # Pattern 3: Target type → typical finding severity distribution
        patterns.extend(self._extract_severity_profiles(episodes))

        # Save patterns
        try:
            with open(self._patterns_path, "w", encoding="utf-8") as f:
                json.dump(patterns, f, indent=2, default=str)
        except (OSError, TypeError) as exc:
            logger.error(f"🧠 Failed to save patterns: {exc}")
            return {"patterns_extracted": 0, "error": str(exc)}

        logger.info(f"🧠 Consolidated {len(patterns)} patterns from {len(episodes)} episodes")
        return {"patterns_extracted": len(patterns), "episodes_analyzed": len(episodes)}

    def add_learning(self, learning: Dict[str, Any]) -> bool:
        """Add a specific learning (e.g., from an error or success observation)."""
        learnings = self.get_learnings()
        entry = {**learning, "timestamp": time.time()}
        learnings.append(entry)
        # Keep most recent 200
        learnings = learnings[-200:]
        try:
            with open(self._learnings_path, "w", encoding="utf-8") as f:
                json.dump(learnings, f, indent=2, default=str)
            return True
        except (OSError, TypeError):
            return False

    # ══════════════════════════════════════════════════════════════════
    # Internal helpers
    # ══════════════════════════════════════════════════════════════════

    def _summarize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Extract compact summaries from finding dicts."""
        return [
            {"tool": f.get("tool", ""), "severity": f.get("severity", "info"), "title": f.get("title", "")}
            for f in findings[:50]
        ]

    def _determine_outcome(self, session_dict: Dict[str, Any]) -> str:
        """Classify scan outcome based on findings."""
        sev = session_dict.get("severity_counts", {})
        if sev.get("critical", 0) > 0 or sev.get("high", 0) > 0:
            return "significant_findings"
        if session_dict.get("total_findings", 0) > 0:
            return "minor_findings"
        if session_dict.get("iterations", 0) > 0:
            return "clean"
        return "incomplete"

    def _extract_tool_effectiveness(self, episodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract which tools produce findings for which target types."""
        # Group by target type
        type_tool_findings: Dict[str, Dict[str, int]] = {}
        type_tool_runs: Dict[str, Dict[str, int]] = {}

        for ep in episodes:
            ttype = ep.get("target_profile", {}).get("target_type", "unknown")
            tools = ep.get("tools_executed", [])
            finding_tools = [f.get("tool", "") for f in ep.get("findings_summary", [])]

            if ttype not in type_tool_findings:
                type_tool_findings[ttype] = Counter()
                type_tool_runs[ttype] = Counter()

            for tool in tools:
                type_tool_runs[ttype][tool] += 1
            for tool in finding_tools:
                type_tool_findings[ttype][tool] += 1

        patterns = []
        for ttype, tool_findings in type_tool_findings.items():
            tool_runs = type_tool_runs.get(ttype, {})
            effective = []
            for tool, finding_count in tool_findings.items():
                run_count = tool_runs.get(tool, 1)
                if finding_count >= MIN_PATTERN_OCCURRENCES:
                    effectiveness = min(finding_count / max(run_count, 1), 1.0)
                    effective.append({"tool": tool, "effectiveness": round(effectiveness, 2)})

            if effective:
                effective.sort(key=lambda x: -x["effectiveness"])
                type_episode_count = sum(
                    1 for ep in episodes if ep.get("target_profile", {}).get("target_type", "unknown") == ttype
                )
                confidence = min(
                    PATTERN_CONFIDENCE_BASE + PATTERN_CONFIDENCE_BOOST * type_episode_count,
                    0.95,
                )
                patterns.append(
                    {
                        "id": f"sem-eff-{ttype}",
                        "category": "tool_effectiveness",
                        "pattern": f"For {ttype} targets, these tools produce findings most often",
                        "conditions": f"target_type={ttype}",
                        "recommended_tools": [t["tool"] for t in effective[:10]],
                        "tool_details": effective[:10],
                        "confidence": round(confidence, 2),
                        "source_episodes": len(episodes),
                        "last_updated": time.time(),
                    }
                )

        return patterns

    def _extract_tool_chains(self, episodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract common tool execution sequences."""
        chain_counter: Counter = Counter()
        for ep in episodes:
            tools = ep.get("tools_executed", [])
            if len(tools) < 2:
                continue
            # Count consecutive pairs
            for i in range(len(tools) - 1):
                pair = f"{tools[i]} -> {tools[i + 1]}"
                chain_counter[pair] += 1

        patterns = []
        for chain, count in chain_counter.most_common(20):
            if count < MIN_PATTERN_OCCURRENCES:
                break
            patterns.append(
                {
                    "id": f"sem-chain-{chain.replace(' -> ', '-').replace(' ', '_')}",
                    "category": "tool_chain",
                    "pattern": f"Tool chain '{chain}' appears frequently in successful scans",
                    "chain": chain,
                    "occurrences": count,
                    "confidence": round(min(PATTERN_CONFIDENCE_BASE + count * 0.05, 0.95), 2),
                    "last_updated": time.time(),
                }
            )

        return patterns

    def _extract_severity_profiles(self, episodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract typical severity distributions per target type."""
        type_severities: Dict[str, List[Dict[str, int]]] = {}
        for ep in episodes:
            ttype = ep.get("target_profile", {}).get("target_type", "unknown")
            sev = ep.get("severity_counts", {})
            if not sev:
                continue
            if ttype not in type_severities:
                type_severities[ttype] = []
            type_severities[ttype].append(sev)

        patterns = []
        for ttype, sev_list in type_severities.items():
            if len(sev_list) < MIN_PATTERN_OCCURRENCES:
                continue
            avg_sev = {}
            for key in ("critical", "high", "medium", "low", "info"):
                vals = [s.get(key, 0) for s in sev_list]
                avg_sev[key] = round(sum(vals) / len(vals), 1)
            patterns.append(
                {
                    "id": f"sem-sev-{ttype}",
                    "category": "severity_profile",
                    "pattern": f"Typical severity distribution for {ttype} targets",
                    "conditions": f"target_type={ttype}",
                    "average_severities": avg_sev,
                    "sample_size": len(sev_list),
                    "confidence": round(min(PATTERN_CONFIDENCE_BASE + len(sev_list) * 0.05, 0.95), 2),
                    "last_updated": time.time(),
                }
            )

        return patterns

    def _prune_episodic(self) -> None:
        """Keep only the most recent MAX_EPISODIC_TRACES episodes."""
        if not os.path.isdir(self._episodic_dir):
            return
        files = []
        for fname in os.listdir(self._episodic_dir):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(self._episodic_dir, fname)
            files.append((fpath, os.path.getmtime(fpath)))

        if len(files) <= MAX_EPISODIC_TRACES:
            return

        files.sort(key=lambda x: x[1])
        to_remove = files[: len(files) - MAX_EPISODIC_TRACES]
        for fpath, _ in to_remove:
            try:
                os.remove(fpath)
            except OSError:
                pass
