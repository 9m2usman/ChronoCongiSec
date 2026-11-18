"""FastAPI router for Knowledge Graph endpoints.

Module: backend.app.api.knowledge
Owner: M3 — Knowledge & Memory Systems Lead

Not yet registered in main.py: M1 to add app.include_router(...)

Implements Document 05 Section 5.1 Route Catalog:
- GET /knowledge/graph (Fetch bounded topological graph)
"""

import logging
from fastapi import APIRouter, Depends, Query, status

from backend.app.api.memory import get_memory_tenant_id, get_repository
from backend.app.knowledge.knowledge_graph import build_graph
from backend.app.memory.models import KnowledgeGraphResponse
from backend.app.memory.repository import MemoryRepository

logger = logging.getLogger("amsc.api.knowledge")

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.get(
    "/graph",
    response_model=KnowledgeGraphResponse,
    status_code=status.HTTP_200_OK,
    summary="Fetch bounded topological graph",
)
async def api_get_knowledge_graph(
    max_depth: int = Query(3, ge=1, le=5, description="Maximum traversal depth (1-5, default 3)"),
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> KnowledgeGraphResponse:
    """Fetch bounded topological knowledge and provenance graph for tenant."""
    return build_graph(
        tenant_id=tenant_id,
        max_depth=max_depth,
        repository=repo,
    )
