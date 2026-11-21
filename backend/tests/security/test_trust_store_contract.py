"""Contract tests for ``TrustDecisionStore`` (M4 protocol; durable implementation pending, M6).

Module: backend.tests.security.test_trust_store_contract
Owner: M4 — Security Engine & Incident Response Lead

Any durable store must pass ``TrustDecisionStoreContract``. To verify one, subclass it and
override ``make_store`` (and ``expect_persistent = True``):

    class TestAuditBackedStore(TrustDecisionStoreContract):
        expect_persistent = True
        def make_store(self):
            return AuditBackedTrustDecisionStore(...)

Today it runs against ``InMemoryTrustDecisionStore`` only (unit level, no database). It does
NOT prove durable persistence; no durable store exists yet (see
docs/security-design/m4-integration-contracts.md, "M6 — trust decision persistence").
"""

import dataclasses
import uuid
from datetime import datetime, timezone

import pytest

from backend.app.security.trust import (
    NON_DURABLE_ALLOWED_ENVIRONMENTS,
    InMemoryTrustDecisionStore,
    TrustDecision,
    TrustEvaluator,
)
from backend.app.memory import InMemoryMemoryRepository

T_A, T_B = "tenant-a-uuid-001", "tenant-b-uuid-002"


def make_decision(tenant=T_A, record="rec-1", **overrides) -> TrustDecision:
    values = dict(
        decision_id=str(uuid.uuid4()), allowed=True, applied=True, decision="APPLIED",
        reason_codes=("TRANSITION_APPLIED",), reason="analyst review", record_id=record, tenant_id=tenant,
        operation="VALIDATE", transition_id="T-02", current_state="UNVERIFIED", stored_state="UNVERIFIED",
        target_state="TRUSTED", resulting_state="TRUSTED", record_version=1, version_checksum="a" * 64,
        actor_type="USER", actor_id="analyst-1", actor_role="SECURITY_ANALYST", incident_id="inc-1",
        evidence_summary={"evidence_refs": ["det-001"]}, policy_version="amsc-trust/1.0.0",
        timestamp=datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc),
    )
    values.update(overrides)
    return TrustDecision(**values)


class TrustDecisionStoreContract:
    """Behaviour every TrustDecisionStore must have. Subclasses override ``make_store``."""

    expect_persistent = False

    def make_store(self):
        raise NotImplementedError

    def test_declares_persistence_honestly(self):
        assert self.make_store().is_persistent is self.expect_persistent

    def test_history_is_append_only_and_ordered(self):
        store = self.make_store()
        first, second = make_decision(), make_decision(operation="QUARANTINE", resulting_state="QUARANTINED")
        store.append(first)
        store.append(second)
        assert list(store.list_for_record(T_A, "rec-1")) == [first, second]

    def test_history_is_tenant_and_record_scoped(self):
        store = self.make_store()
        a, b, other = make_decision(), make_decision(tenant=T_B), make_decision(record="rec-2")
        for d in (a, b, other):
            store.append(d)
        assert list(store.list_for_record(T_A, "rec-1")) == [a]
        assert list(store.list_for_record(T_B, "rec-1")) == [b]
        assert list(store.list_for_record(T_A, "missing")) == []

    @pytest.mark.parametrize("tenant", [None, ""])
    def test_unscoped_decision_is_refused(self, tenant):
        store = self.make_store()
        with pytest.raises(Exception):
            store.append(make_decision(tenant=tenant))
        assert list(store.list_for_record(T_A, "rec-1")) == []

    def test_returned_history_cannot_be_used_to_rewrite_it(self):
        store = self.make_store()
        store.append(make_decision())
        history = store.list_for_record(T_A, "rec-1")
        with pytest.raises((TypeError, AttributeError)):
            history.append(make_decision(resulting_state="REJECTED"))   # tuple / read-only view
        with pytest.raises(dataclasses.FrozenInstanceError):
            history[0].resulting_state = "REJECTED"
        assert store.list_for_record(T_A, "rec-1")[0].resulting_state == "TRUSTED"

    def test_every_evidence_field_round_trips(self):
        store = self.make_store()
        d = make_decision()
        store.append(d)
        got = store.list_for_record(T_A, "rec-1")[0]
        for field in ("actor_type", "actor_id", "actor_role", "reason", "reason_codes", "record_version",
                      "version_checksum", "evidence_summary", "policy_version", "timestamp", "incident_id",
                      "transition_id", "stored_state", "current_state", "resulting_state", "decision_id"):
            assert getattr(got, field) == getattr(d, field), field


class TestInMemoryTrustDecisionStore(TrustDecisionStoreContract):
    expect_persistent = False

    def make_store(self):
        return InMemoryTrustDecisionStore()


# --- M4-F6: non-durable stores only in explicit non-production environments -------------------

def test_non_durable_allow_list_is_exact():
    assert NON_DURABLE_ALLOWED_ENVIRONMENTS == {"development", "test"}


@pytest.mark.parametrize("env", ["production", "PRODUCTION", " production ", "prod", "staging", "Staging",
                                 "", "unknown", 123])
def test_non_development_environments_refuse_in_memory_stores(env):
    with pytest.raises(RuntimeError):
        TrustEvaluator(InMemoryMemoryRepository(), InMemoryTrustDecisionStore(), app_env=env)


@pytest.mark.parametrize("env", ["development", "test", "TEST", " Development "])
def test_development_and_test_may_use_in_memory_stores(env):
    TrustEvaluator(InMemoryMemoryRepository(), InMemoryTrustDecisionStore(), app_env=env)
