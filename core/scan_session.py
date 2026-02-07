"""
Scan Session Manager — Stateful context for multi-step pentests.

Persists target profile + findings between MCP tool calls so the LLM
doesn't have to carry everything in its own context window.

Now with optional disk persistence via SessionStore (checkpoint/resume
pattern from skills/autonomous-mode/autonomous-agent-patterns Section 5.2)
and episodic memory via ScanMemory (skills/autonomous-mode/loki-mode/
references/memory-system.md).

Design notes (senior-engineering/architecture):
  - SRP: this module only manages session CRUD, no analysis logic
  - Persistence is optional — works in-memory-only if no store provided
  - KISS: delegate disk I/O to SessionStore, memory to ScanMemory
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Named constants (clean-code: no magic numbers)
SESSION_TTL_SECONDS = 7200  # 2 hours
MAX_SESSIONS = 50
MAX_FINDINGS_PER_SESSION = 500


@dataclass
class Finding:
    """A single security finding from a tool execution."""

    tool: str
    severity: str  # critical, high, medium, low, info
    title: str
    detail: str = ""
    target: str = ""
    confidence: float = 0.0
    raw_output: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "target": self.target,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanSession:
    """Holds accumulated state for a multi-step scan."""

    session_id: str
    target: str
    target_profile: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    tools_executed: List[Dict[str, Any]] = field(default_factory=list)
    iteration: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.updated_at) > SESSION_TTL_SECONDS

    def touch(self) -> None:
        self.updated_at = time.time()

    def add_finding(self, finding: Finding) -> None:
        if len(self.findings) >= MAX_FINDINGS_PER_SESSION:
            return
        self.findings.append(finding)
        self.touch()

    def add_tool_result(self, tool_name: str, result: Dict[str, Any]) -> None:
        self.tools_executed.append(
            {
                "tool": tool_name,
                "success": result.get("success", False),
                "timestamp": time.time(),
            }
        )
        self.iteration += 1
        self.touch()

    def get_summary(self) -> Dict[str, Any]:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "session_id": self.session_id,
            "target": self.target,
            "iterations": self.iteration,
            "tools_run": len(self.tools_executed),
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "tools_executed": [t["tool"] for t in self.tools_executed],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.get_summary(),
            "target_profile": self.target_profile,
            "findings": [f.to_dict() for f in self.findings],
            "tools_executed_raw": self.tools_executed,
            "metadata": self.metadata,
        }


class ScanSessionManager:
    """In-memory session store with TTL eviction and optional disk persistence."""

    def __init__(self, session_store=None, scan_memory=None) -> None:
        self._sessions: Dict[str, ScanSession] = {}
        self._store = session_store  # Optional[SessionStore]
        self._memory = scan_memory  # Optional[ScanMemory]
        self._restore_from_disk()

    def create(self, target: str, target_profile: Optional[Dict[str, Any]] = None) -> ScanSession:
        self._evict_expired()

        if len(self._sessions) >= MAX_SESSIONS:
            self._evict_oldest()

        session_id = uuid.uuid4().hex[:12]
        session = ScanSession(
            session_id=session_id,
            target=target,
            target_profile=target_profile or {},
        )
        self._sessions[session_id] = session
        self._persist(session)
        logger.info(f"📋 Created scan session {session_id} for {target}")
        return session

    def get(self, session_id: str) -> Optional[ScanSession]:
        session = self._sessions.get(session_id)
        if not session:
            return None
        if session.is_expired:
            del self._sessions[session_id]
            return None
        return session

    def get_by_target(self, target: str) -> Optional[ScanSession]:
        """Get the most recent non-expired session for a target."""
        candidates = [s for s in self._sessions.values() if s.target == target and not s.is_expired]
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.updated_at)

    def delete(self, session_id: str) -> bool:
        if session_id in self._sessions:
            del self._sessions[session_id]
            if self._store:
                self._store.delete(session_id)
            return True
        return False

    def list_sessions(self) -> List[Dict[str, Any]]:
        self._evict_expired()
        return [s.get_summary() for s in self._sessions.values()]

    def list_completed_sessions(self) -> List[Dict[str, Any]]:
        """List completed (archived) sessions from disk."""
        if not self._store:
            return []
        return self._store.list_completed()

    def get_completed_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a completed session from disk by ID."""
        if not self._store:
            return None
        return self._store.load_completed(session_id)

    def _evict_expired(self) -> None:
        expired = [sid for sid, s in self._sessions.items() if s.is_expired]
        for sid in expired:
            del self._sessions[sid]

    def _evict_oldest(self) -> None:
        if not self._sessions:
            return
        oldest_id = min(self._sessions, key=lambda sid: self._sessions[sid].updated_at)
        del self._sessions[oldest_id]

    def persist_session(self, session_id: str) -> bool:
        """Explicitly persist a session to disk (called after mutations)."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        return self._persist(session)

    def complete_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Mark a session as complete: archive to disk + save episodic memory.

        Returns the final session dict or None if session not found.
        """
        session = self._sessions.get(session_id)
        if not session:
            return None
        session_dict = session.to_dict()

        if self._store:
            self._store.archive(session_id, session_dict)
        if self._memory:
            self._memory.save_episode(session_dict)

        del self._sessions[session_id]
        logger.info(f"✅ Completed and archived session {session_id}")
        return session_dict

    def _persist(self, session: ScanSession) -> bool:
        """Save session to disk if store is available."""
        if not self._store:
            return False
        return self._store.save(session.session_id, session.to_dict())

    def _restore_from_disk(self) -> None:
        """Restore active sessions from disk on startup."""
        if not self._store:
            return
        saved = self._store.load_all_active()
        restored = 0
        for data in saved:
            session = self._dict_to_session(data)
            if session and not session.is_expired:
                self._sessions[session.session_id] = session
                restored += 1
        if restored:
            logger.info(f"💾 Restored {restored} session(s) from disk")

    @staticmethod
    def _dict_to_session(data: Dict[str, Any]) -> Optional[ScanSession]:
        """Reconstruct a ScanSession from a serialized dict."""
        try:
            findings = []
            for fd in data.get("findings", []):
                findings.append(
                    Finding(
                        tool=fd.get("tool", ""),
                        severity=fd.get("severity", "info"),
                        title=fd.get("title", ""),
                        detail=fd.get("detail", ""),
                        target=fd.get("target", ""),
                        confidence=fd.get("confidence", 0.0),
                        timestamp=fd.get("timestamp", time.time()),
                    )
                )
            return ScanSession(
                session_id=data["session_id"],
                target=data["target"],
                target_profile=data.get("target_profile", {}),
                findings=findings,
                tools_executed=data.get("tools_executed_raw", []),
                iteration=data.get("iterations", 0),
                created_at=data.get("created_at", time.time()),
                updated_at=data.get("updated_at", time.time()),
                metadata=data.get("metadata", {}),
            )
        except (KeyError, TypeError) as exc:
            logger.warning(f"💾 Could not restore session: {exc}")
            return None
