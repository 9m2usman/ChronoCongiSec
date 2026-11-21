"""Test-only helper: write a stored trust state directly through the repository.

``transition_memory_trust_state`` is restrict-only (F-2): promotions to TRUSTED, REJECTED,
SUPERSEDED and relaxations are decided by M4's ``TrustEvaluator``. Tests that only need a record
*in* a given state as a precondition (or that simulate an out-of-band write which M4 must
reconcile) use this helper instead. It is not importable from application code paths.
"""

from datetime import datetime, timezone
from typing import Any


def force_trust_state(tenant_id: str, record_id: str, new_trust_state: str, repository: Any = None) -> Any:
    if repository is None:
        raise ValueError("force_trust_state needs an explicit test repository")
    record = repository.get_record(record_id, tenant_id)
    if record is None:
        raise ValueError(f"no record {record_id!r} in tenant {tenant_id!r}")
    record.trust_state = str(getattr(new_trust_state, "value", new_trust_state)).upper()
    record.updated_at = datetime.now(timezone.utc)
    return repository.update_record(record)
