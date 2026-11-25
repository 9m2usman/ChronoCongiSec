"""Organizational Knowledge Intelligence & Controlled Memory Extraction."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from backend.app.enterprise.models import (
    ClaimTrustState,
    ClaimType,
    DiscoveredResourceDTO,
    EnterpriseMemoryLinkDTO,
    FreshnessStatus,
    KnowledgeClaimDTO,
    ResourceType,
)
from backend.app.enterprise.repository import EnterpriseRepository
from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.models import MemoryRecord, MemoryVersion, RecordType
from backend.app.memory.repository import MemoryRepository


INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"override\s+(amsc|security|policy|system)", re.IGNORECASE),
    re.compile(r"bypass\s+(gateway|approval|ceiling|policy)", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"transfer\s+\$?\d{4,}", re.IGNORECASE),
]


def screen_untrusted_content(text: str) -> Tuple[bool, List[str]]:
    """Treat retrieved enterprise documents/DB content as untrusted input for injection screening."""
    hits: List[str] = []
    for pat in INJECTION_PATTERNS:
        if pat.search(text):
            hits.append(pat.pattern)
    return len(hits) > 0, hits


class OrganizationalIntelligenceService:
    """Extracts structured organizational knowledge, preserves conflicts, and performs controlled memory extraction."""

    def __init__(
        self,
        enterprise_repo: EnterpriseRepository,
        memory_repo: Optional[MemoryRepository] = None,
    ) -> None:
        self._repo = enterprise_repo
        self._memory_repo = memory_repo

    async def extract_claims_from_resource(
        self,
        tenant_id: str,
        resource: DiscoveredResourceDTO,
        *,
        text_content: Optional[str] = None,
        structured_records: Optional[List[Dict[str, Any]]] = None,
    ) -> List[KnowledgeClaimDTO]:
        """Extract structured facts, entities, policies, and rules with traceable provenance & conflict detection."""
        claims_to_create: List[KnowledgeClaimDTO] = []
        provenance = {
            "connector_id": resource.connector_id,
            "resource_id": resource.id,
            "external_id": resource.external_id,
            "source_version": resource.source_version,
            "content_checksum": resource.content_checksum,
            "extracted_at": datetime.now(timezone.utc).isoformat(),
        }

        # Supersede prior claims from the same resource when a new version arrives
        existing_for_res = await self._repo.list_claims(tenant_id, resource_id=resource.id)
        for old in existing_for_res:
            if str(old.trust_state) not in {ClaimTrustState.SUPERSEDED.value, ClaimTrustState.REVOKED.value}:
                old.trust_state = ClaimTrustState.SUPERSEDED
                await self._repo.update_claim(old)

        if structured_records is not None:
            for idx, row in enumerate(structured_records[:25]):
                subj = str(
                    row.get("name")
                    or row.get("vendor_name")
                    or row.get("id")
                    or f"{resource.name}#row_{idx}"
                )
                summary = json.dumps(row, sort_keys=True, default=str)
                flagged, hits = screen_untrusted_content(summary)
                trust = ClaimTrustState.UNCERTAIN if flagged else ClaimTrustState.UNVERIFIED
                claims_to_create.append(
                    KnowledgeClaimDTO(
                        id=str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        resource_id=resource.id,
                        source_id=resource.source_id,
                        claim_type=ClaimType.ENTITY,
                        subject=subj,
                        predicate="RECORD_STATE",
                        object_value=summary,
                        department=str(row.get("department") or resource.metadata_json.get("department") or "OPERATIONS"),
                        provenance_json={**provenance, "injection_hits": hits},
                        trust_state=trust,
                        confidence=0.35 if flagged else 0.75,
                    )
                )

        if text_content:
            flagged, hits = screen_untrusted_content(text_content)
            lines = [ln.strip() for ln in text_content.splitlines() if ln.strip()]
            # Derive a normalized topic/subject from document heading if present
            doc_topic: Optional[str] = None
            for ln in lines[:5]:
                if ln.startswith("#"):
                    doc_topic = ln.lstrip("#").strip()[:255]
                    break
                if ":" not in ln and len(ln) <= 120:
                    doc_topic = ln.strip()[:255]
                    break

            # Extract key: value or policy/rule statements
            extracted_any = False
            for ln in lines[:40]:
                if ":" in ln and not ln.startswith("#"):
                    k, v = ln.split(":", 1)
                    k = k.strip()[:128]
                    v = v.strip()
                    if k and v:
                        extracted_any = True
                        is_policy = (
                            str(resource.resource_type) == ResourceType.POLICY_DOC.value
                            or "policy" in ln.lower()
                            or "limit" in ln.lower()
                            or "polic" in resource.name.lower()
                        )
                        ctype = ClaimType.POLICY if is_policy else ClaimType.FACT
                        claim_subject = doc_topic or ("Enterprise Policy" if is_policy else resource.name)
                        claims_to_create.append(
                            KnowledgeClaimDTO(
                                id=str(uuid.uuid4()),
                                tenant_id=tenant_id,
                                resource_id=resource.id,
                                source_id=resource.source_id,
                                claim_type=ctype,
                                subject=claim_subject,
                                predicate=k,
                                object_value=v,
                                department=str(resource.metadata_json.get("department") or "ENTERPRISE"),
                                provenance_json={**provenance, "injection_hits": hits},
                                trust_state=ClaimTrustState.UNCERTAIN if flagged else ClaimTrustState.UNVERIFIED,
                                confidence=0.25 if flagged else 0.7,
                            )
                        )
            if not extracted_any:
                claims_to_create.append(
                    KnowledgeClaimDTO(
                        id=str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        resource_id=resource.id,
                        source_id=resource.source_id,
                        claim_type=ClaimType.FACT,
                        subject=doc_topic or resource.name,
                        predicate="DOCUMENT_SUMMARY",
                        object_value=text_content[:500],
                        provenance_json={**provenance, "injection_hits": hits},
                        trust_state=ClaimTrustState.UNCERTAIN if flagged else ClaimTrustState.UNVERIFIED,
                        confidence=0.25 if flagged else 0.65,
                    )
                )

        # Conflict preservation: check all active claims for same (subject, predicate) with different object_value
        all_claims = await self._repo.list_claims(tenant_id)
        saved_claims: List[KnowledgeClaimDTO] = []
        for new_claim in claims_to_create:
            conflicts = [
                c
                for c in all_claims
                if c.resource_id != new_claim.resource_id
                and c.subject.lower() == new_claim.subject.lower()
                and c.predicate.lower() == new_claim.predicate.lower()
                and c.object_value != new_claim.object_value
                and str(c.trust_state) not in {ClaimTrustState.SUPERSEDED.value, ClaimTrustState.REVOKED.value}
            ]
            if conflicts:
                group_id = conflicts[0].conflict_group_id or str(uuid.uuid4())
                new_claim.conflict_group_id = group_id
                new_claim.trust_state = ClaimTrustState.CONFLICTING
                for c in conflicts:
                    c.conflict_group_id = group_id
                    c.trust_state = ClaimTrustState.CONFLICTING
                    await self._repo.update_claim(c)
            saved = await self._repo.create_claim(new_claim)
            saved_claims.append(saved)
            all_claims.append(saved)

        return saved_claims

    async def extract_controlled_memory(
        self,
        tenant_id: str,
        resource: DiscoveredResourceDTO,
        *,
        content: str,
        agent_id: Optional[str] = None,
        purpose: str = "ENTERPRISE_KNOWLEDGE_EXTRACTION",
    ) -> Tuple[MemoryRecord, MemoryVersion, EnterpriseMemoryLinkDTO]:
        """Create a governed memory record + snapshot link with full source lineage.

        Never promotes untrusted content to TRUSTED automatically; M4 trust evaluation governs promotion.
        """
        if self._memory_repo is None:
            raise RuntimeError("MemoryRepository is required for controlled memory extraction.")

        flagged, hits = screen_untrusted_content(content)
        registered_agent_id = agent_id
        if agent_id is not None:
            existing_agent = await self._memory_repo.get_agent(agent_id, tenant_id)
            if existing_agent is None:
                registered_agent_id = None
        rec, ver = await ingest_memory(
            tenant_id=tenant_id,
            content=content,
            agent_id=registered_agent_id,
            record_type=RecordType.KNOWLEDGE,
            source_id=resource.source_id,
            repository=self._memory_repo,
        )
        snapshot_payload = {
            "resource_id": resource.id,
            "external_id": resource.external_id,
            "source_version": resource.source_version,
            "content_checksum": resource.content_checksum,
            "memory_checksum": ver.checksum,
            "injection_screened": True,
            "injection_flagged": flagged,
            "injection_hits": hits,
            "purpose": purpose,
        }
        snapshot_checksum = hashlib.sha256(
            json.dumps(snapshot_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        link = EnterpriseMemoryLinkDTO(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            memory_record_id=rec.id,
            memory_version=ver.version,
            resource_id=resource.id,
            source_version=resource.source_version,
            agent_id=agent_id,
            extraction_purpose=purpose,
            confidence=0.2 if flagged else 0.8,
            freshness_status=FreshnessStatus.QUARANTINED if flagged else FreshnessStatus.CURRENT,
            snapshot_checksum=snapshot_checksum,
            snapshot_json=snapshot_payload,
        )
        saved_link = await self._repo.create_memory_link(link)
        return rec, ver, saved_link
