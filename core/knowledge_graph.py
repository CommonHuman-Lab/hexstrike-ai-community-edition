"""
Knowledge Graph — Entity-relationship graph for attack path discovery.

Stores target → service → vulnerability → credential relationships
extracted from parsed Finding objects. Enables attack path discovery
via BFS traversal and entity querying.

Design notes (senior-engineering/clean-code):
  - Ingests parsed Findings only (structured fields), NOT raw tool output
  - Atomic JSON persistence (temp file + rename, same as session_store.py)
  - Entity deduplication by (type, name, source properties)
  - BFS bounded by MAX_PATH_DEPTH to prevent runaway traversals
"""

import json
import logging
import os
import re
import tempfile
import time
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
MAX_ENTITIES = 10000
MAX_RELATIONSHIPS = 50000
MAX_PATH_DEPTH = 5

# Entity types
ENTITY_HOST = "host"
ENTITY_SERVICE = "service"
ENTITY_VULNERABILITY = "vulnerability"
ENTITY_CREDENTIAL = "credential"

# Relationship types
REL_HOSTS = "HOSTS"
REL_HAS_VULN = "HAS_VULN"
REL_OBTAINED_FROM = "OBTAINED_FROM"
REL_LEADS_TO = "LEADS_TO"

# Patterns for extracting structured data from findings
_PORT_RE = re.compile(r"(?:port\s+)?(\d{1,5})(?:/(\w+))?", re.IGNORECASE)
_SERVICE_RE = re.compile(r"(?:service|running|detected)[\s:]+(\w[\w\-./]+)", re.IGNORECASE)
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)


@dataclass
class Entity:
    """A node in the knowledge graph."""

    id: str
    entity_type: str  # host, service, vulnerability, credential
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    source_session: str = ""
    engagement_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Relationship:
    """An edge in the knowledge graph."""

    id: str
    source_id: str
    target_id: str
    rel_type: str  # HOSTS, HAS_VULN, OBTAINED_FROM, LEADS_TO
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class KnowledgeGraph:
    """Entity-relationship graph for HexStrike attack path discovery."""

    def __init__(self, data_dir: str):
        self._data_dir = os.path.join(data_dir, "knowledge")
        os.makedirs(self._data_dir, exist_ok=True)
        self._graph_path = os.path.join(self._data_dir, "graph.json")

        self._entities: Dict[str, Entity] = {}
        self._relationships: Dict[str, Relationship] = {}
        # Indexes for fast lookup
        self._entity_name_index: Dict[str, str] = {}  # (type:name) → entity_id
        self._adjacency: Dict[str, List[str]] = defaultdict(list)  # entity_id → [rel_ids]

        self._load()

    # ── Entity Operations ──────────────────────────────────────────────

    def add_entity(self, entity: Entity) -> str:
        """Add an entity, returning its ID. Deduplicates by type + name (+ engagement when set)."""
        if entity.engagement_id:
            dedup_key = f"{entity.engagement_id}:{entity.entity_type}:{entity.name}"
        else:
            dedup_key = f"{entity.entity_type}:{entity.name}"
        if dedup_key in self._entity_name_index:
            existing_id = self._entity_name_index[dedup_key]
            # Merge properties
            self._entities[existing_id].properties.update(entity.properties)
            return existing_id

        if len(self._entities) >= MAX_ENTITIES:
            logger.warning(f"Knowledge graph entity limit reached ({MAX_ENTITIES})")
            return ""

        self._entities[entity.id] = entity
        self._entity_name_index[dedup_key] = entity.id
        return entity.id

    def add_relationship(self, rel: Relationship) -> str:
        """Add a relationship between two entities."""
        if rel.source_id not in self._entities or rel.target_id not in self._entities:
            return ""

        if len(self._relationships) >= MAX_RELATIONSHIPS:
            logger.warning(f"Knowledge graph relationship limit reached ({MAX_RELATIONSHIPS})")
            return ""

        self._relationships[rel.id] = rel
        self._adjacency[rel.source_id].append(rel.id)
        self._adjacency[rel.target_id].append(rel.id)
        return rel.id

    # ── Finding Ingestion ──────────────────────────────────────────────

    def ingest_findings(
        self, session_id: str, target: str, findings: List[Dict], engagement_id: str = ""
    ) -> Dict[str, Any]:
        """Ingest parsed Finding dicts into the graph.

        Maps findings to entities:
          - Port findings → Service entity + HOSTS relationship
          - CVE findings → Vulnerability entity + HAS_VULN on service/host
          - Breach findings → Credential entity + OBTAINED_FROM
          - Generic findings → Vulnerability entity with finding details

        When engagement_id is provided, entities are scoped to that engagement
        so different clients' findings don't cross-contaminate.

        Returns capacity info so callers know if data was dropped.
        """
        entities_created = 0
        relationships_created = 0

        # Create or get Host entity for the target
        host_id = self._ensure_host(target, session_id, engagement_id)
        if not host_id:
            at_capacity = len(self._entities) >= MAX_ENTITIES
            return {
                "entities_created": 0,
                "relationships_created": 0,
                "at_capacity": at_capacity,
                "warning": "Entity capacity reached — host could not be created" if at_capacity else "",
            }

        for finding in findings:
            title = finding.get("title", "")
            severity = finding.get("severity", "info")
            tool = finding.get("tool", "unknown")
            detail = finding.get("detail", "")

            title_lower = title.lower()

            # Port/Service findings
            port_match = _PORT_RE.search(title)
            if port_match and any(kw in title_lower for kw in ("port", "service", "open", "exposed")):
                port = port_match.group(1)
                proto = port_match.group(2) or "tcp"
                service_name = f"{target}:{port}/{proto}"

                svc_entity = Entity(
                    id=uuid.uuid4().hex[:12],
                    entity_type=ENTITY_SERVICE,
                    name=service_name,
                    properties={"port": int(port), "protocol": proto, "tool": tool},
                    source_session=session_id,
                    engagement_id=engagement_id,
                )
                svc_id = self.add_entity(svc_entity)
                if svc_id:
                    entities_created += 1
                    rel = Relationship(
                        id=uuid.uuid4().hex[:12],
                        source_id=host_id,
                        target_id=svc_id,
                        rel_type=REL_HOSTS,
                        properties={"discovered_by": tool},
                    )
                    if self.add_relationship(rel):
                        relationships_created += 1

                    # If the finding also has a CVE, link it to the service
                    cve_match = _CVE_RE.search(title) or _CVE_RE.search(detail)
                    if cve_match:
                        e_count, r_count = self._add_vulnerability(
                            cve_match.group(1), severity, tool, svc_id, session_id, engagement_id
                        )
                        entities_created += e_count
                        relationships_created += r_count
                continue

            # CVE findings (without port context)
            cve_match = _CVE_RE.search(title) or _CVE_RE.search(detail)
            if cve_match:
                e_count, r_count = self._add_vulnerability(
                    cve_match.group(1), severity, tool, host_id, session_id, engagement_id
                )
                entities_created += e_count
                relationships_created += r_count
                continue

            # Breach/credential findings
            if any(kw in title_lower for kw in ("breach", "credential", "password", "leaked", "exposed")):
                cred_entity = Entity(
                    id=uuid.uuid4().hex[:12],
                    entity_type=ENTITY_CREDENTIAL,
                    name=f"breach:{target}:{tool}",
                    properties={"severity": severity, "detail": detail[:200], "tool": tool},
                    source_session=session_id,
                    engagement_id=engagement_id,
                )
                cred_id = self.add_entity(cred_entity)
                if cred_id:
                    entities_created += 1
                    rel = Relationship(
                        id=uuid.uuid4().hex[:12],
                        source_id=cred_id,
                        target_id=host_id,
                        rel_type=REL_OBTAINED_FROM,
                        properties={"tool": tool},
                    )
                    if self.add_relationship(rel):
                        relationships_created += 1
                continue

            # Generic vulnerability findings
            if severity in ("critical", "high", "medium"):
                vuln_entity = Entity(
                    id=uuid.uuid4().hex[:12],
                    entity_type=ENTITY_VULNERABILITY,
                    name=title[:120],
                    properties={"severity": severity, "detail": detail[:200], "tool": tool},
                    source_session=session_id,
                    engagement_id=engagement_id,
                )
                vuln_id = self.add_entity(vuln_entity)
                if vuln_id:
                    entities_created += 1
                    rel = Relationship(
                        id=uuid.uuid4().hex[:12],
                        source_id=host_id,
                        target_id=vuln_id,
                        rel_type=REL_HAS_VULN,
                        properties={"severity": severity, "tool": tool},
                    )
                    if self.add_relationship(rel):
                        relationships_created += 1

        self._persist()

        entity_at_cap = len(self._entities) >= MAX_ENTITIES
        rel_at_cap = len(self._relationships) >= MAX_RELATIONSHIPS
        at_capacity = entity_at_cap or rel_at_cap

        logger.info(
            f"Ingested session {session_id}: " f"{entities_created} entities, {relationships_created} relationships"
        )
        if at_capacity:
            logger.warning(
                f"Knowledge graph near capacity: {len(self._entities)}/{MAX_ENTITIES} entities, "
                f"{len(self._relationships)}/{MAX_RELATIONSHIPS} relationships"
            )

        result = {"entities_created": entities_created, "relationships_created": relationships_created}
        if at_capacity:
            result["at_capacity"] = True
            result["warning"] = (
                f"Graph approaching limits ({len(self._entities)}/{MAX_ENTITIES} entities, "
                f"{len(self._relationships)}/{MAX_RELATIONSHIPS} relationships). "
                "Some findings may have been dropped. Consider using engagement_id to scope data."
            )
        return result

    # ── Query Operations ───────────────────────────────────────────────

    def find_attack_paths(
        self, from_entity_id: str, to_type: str, max_depth: int = MAX_PATH_DEPTH, engagement_id: str = ""
    ) -> List[List[Dict]]:
        """BFS to find paths from an entity to entities of the target type.

        When engagement_id is provided, only traverses entities belonging
        to that engagement (prevents cross-engagement path discovery).
        """
        if from_entity_id not in self._entities:
            return []

        paths = []
        queue: deque = deque([(from_entity_id, [from_entity_id])])
        visited: Set[str] = {from_entity_id}

        while queue:
            current_id, path = queue.popleft()

            if len(path) > max_depth + 1:
                continue

            # Check if current entity matches target type (skip the start node)
            if len(path) > 1 and self._entities[current_id].entity_type == to_type:
                paths.append([self._entities[eid].to_dict() for eid in path])
                continue

            # Expand neighbors
            for rel_id in self._adjacency.get(current_id, []):
                rel = self._relationships[rel_id]
                neighbor_id = rel.target_id if rel.source_id == current_id else rel.source_id
                if neighbor_id not in visited:
                    # Skip entities from other engagements when filtering
                    if engagement_id and neighbor_id in self._entities:
                        neighbor_eng = self._entities[neighbor_id].engagement_id
                        if neighbor_eng and neighbor_eng != engagement_id:
                            continue
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))

        return paths

    def get_related(self, entity_id: str, rel_type: Optional[str] = None) -> List[Dict]:
        """Get direct neighbors of an entity, optionally filtered by relationship type."""
        if entity_id not in self._entities:
            return []

        neighbors = []
        for rel_id in self._adjacency.get(entity_id, []):
            rel = self._relationships[rel_id]
            if rel_type and rel.rel_type != rel_type:
                continue

            neighbor_id = rel.target_id if rel.source_id == entity_id else rel.source_id
            if neighbor_id in self._entities:
                neighbors.append(
                    {
                        "entity": self._entities[neighbor_id].to_dict(),
                        "relationship": rel.to_dict(),
                    }
                )
        return neighbors

    def query(
        self, entity_type: Optional[str] = None, filters: Optional[Dict] = None, engagement_id: str = ""
    ) -> List[Dict]:
        """Query entities by type and property filters.

        When engagement_id is provided, only returns entities from that engagement.
        """
        results = []
        for entity in self._entities.values():
            if engagement_id and entity.engagement_id and entity.engagement_id != engagement_id:
                continue
            if entity_type and entity.entity_type != entity_type:
                continue
            if filters:
                match = all(entity.properties.get(k) == v for k, v in filters.items())
                if not match:
                    continue
            results.append(entity.to_dict())
        return results

    def get_summary(self, engagement_id: str = "") -> Dict[str, Any]:
        """Get entity and relationship counts by type.

        When engagement_id is provided, only counts entities/relationships from that engagement.
        """
        entity_counts: Dict[str, int] = defaultdict(int)
        included_entity_ids: Set[str] = set()
        for eid, e in self._entities.items():
            if engagement_id and e.engagement_id and e.engagement_id != engagement_id:
                continue
            entity_counts[e.entity_type] += 1
            included_entity_ids.add(eid)

        rel_counts: Dict[str, int] = defaultdict(int)
        total_rels = 0
        for r in self._relationships.values():
            if engagement_id and (r.source_id not in included_entity_ids or r.target_id not in included_entity_ids):
                continue
            rel_counts[r.rel_type] += 1
            total_rels += 1

        return {
            "total_entities": len(included_entity_ids),
            "total_relationships": total_rels,
            "entities_by_type": dict(entity_counts),
            "relationships_by_type": dict(rel_counts),
        }

    # ── Private Helpers ────────────────────────────────────────────────

    def _ensure_host(self, target: str, session_id: str, engagement_id: str = "") -> str:
        """Create or get a Host entity for the target."""
        host = Entity(
            id=uuid.uuid4().hex[:12],
            entity_type=ENTITY_HOST,
            name=target,
            properties={"first_seen": time.time()},
            source_session=session_id,
            engagement_id=engagement_id,
        )
        return self.add_entity(host)

    def _add_vulnerability(
        self, cve_id: str, severity: str, tool: str, parent_id: str, session_id: str, engagement_id: str = ""
    ):
        """Add a vulnerability entity and link it to a parent (host or service)."""
        entities_created = 0
        relationships_created = 0

        vuln_entity = Entity(
            id=uuid.uuid4().hex[:12],
            entity_type=ENTITY_VULNERABILITY,
            name=cve_id.upper(),
            properties={"severity": severity, "tool": tool},
            source_session=session_id,
            engagement_id=engagement_id,
        )
        vuln_id = self.add_entity(vuln_entity)
        if vuln_id:
            entities_created += 1
            rel = Relationship(
                id=uuid.uuid4().hex[:12],
                source_id=parent_id,
                target_id=vuln_id,
                rel_type=REL_HAS_VULN,
                properties={"severity": severity, "tool": tool},
            )
            if self.add_relationship(rel):
                relationships_created += 1

        return entities_created, relationships_created

    def _persist(self) -> None:
        """Atomic save to graph.json."""
        data = {
            "entities": {eid: e.to_dict() for eid, e in self._entities.items()},
            "relationships": {rid: r.to_dict() for rid, r in self._relationships.items()},
            "updated_at": time.time(),
        }
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self._data_dir, suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self._graph_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def _load(self) -> None:
        """Load graph from disk."""
        if not os.path.exists(self._graph_path):
            return

        try:
            with open(self._graph_path, "r") as f:
                data = json.load(f)

            for eid, edata in data.get("entities", {}).items():
                entity = Entity(**edata)
                self._entities[eid] = entity
                if entity.engagement_id:
                    dedup_key = f"{entity.engagement_id}:{entity.entity_type}:{entity.name}"
                else:
                    dedup_key = f"{entity.entity_type}:{entity.name}"
                self._entity_name_index[dedup_key] = eid

            for rid, rdata in data.get("relationships", {}).items():
                rel = Relationship(**rdata)
                self._relationships[rid] = rel
                self._adjacency[rel.source_id].append(rid)
                self._adjacency[rel.target_id].append(rid)

            logger.info(
                f"Loaded knowledge graph: {len(self._entities)} entities, " f"{len(self._relationships)} relationships"
            )
        except Exception as e:
            logger.warning(f"Failed to load knowledge graph: {e}")
