"""In-memory baseline repository helper for offline ML evaluation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class InMemoryEvalBaselineRepo:
    """Minimal read-only baseline repository implementing DetectionEngine's lookup interface."""

    def __init__(self, baselines: Dict[str, Dict[str, Any]]) -> None:
        self._baselines = baselines

    async def get_baseline_record(self, tenant_id: str, baseline_id: str) -> Optional[Dict[str, Any]]:
        rec = self._baselines.get(baseline_id)
        if rec and rec.get("tenant_id") == tenant_id:
            return rec
        return None

    async def get_baseline_versions(self, tenant_id: str, baseline_id: str) -> List[Dict[str, Any]]:
        rec = await self.get_baseline_record(tenant_id, baseline_id)
        if rec is None:
            return []
        return [{"version": 1, "content": rec.get("content", "")}]
