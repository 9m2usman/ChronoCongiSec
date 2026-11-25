"""Migration lifecycle: clean -> fully seeded, forward and backward (DOC-006 Day 7 M6 row).

Owner: M6
Exit criterion: "Migration runs forward and backward cleanly".

1. Exact inverse: walking down one revision at a time must reproduce, at every step, the
   schema that walking up produced (schema_fingerprint), so no downgrade leaves objects
   behind or removes too much.
2. Seeded round trip: a fully seeded head database (seed_fixture: illustrative test data,
   not decisions) goes down revision by revision to 0001 and back up to head without
   losing a row, and ends intact (audit chains, protection report, rewind result). The
   documented downgrade effects are asserted explicitly (INTEGRATION-GUIDE.md).
"""

import asyncio

import asyncpg
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from backend.tests.database import helpers
from backend.tests.database.schema_fingerprint import describe_difference, schema_fingerprint
from backend.tests.database.seed_fixture import SeedResult, seed_dataset

EXPECTED_TABLES = 59


def _revisions() -> list[str]:
    script = ScriptDirectory.from_config(Config(str(helpers.ALEMBIC_INI)))
    return [r.revision for r in reversed(list(script.walk_revisions()))]  # base -> head


async def _with_conn(database: str, fn):
    conn = await asyncpg.connect(helpers.asyncpg_dsn(database))
    try:
        return await fn(conn)
    finally:
        await conn.close()


def _fingerprint(database: str) -> dict:
    return asyncio.run(_with_conn(database, schema_fingerprint))


def _row_counts(database: str) -> dict[str, int]:
    async def count(conn):
        tables = [r["tablename"] for r in await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'alembic_version'")]
        return {t: await conn.fetchval(f'SELECT count(*) FROM "{t}"') for t in sorted(tables)}
    return asyncio.run(_with_conn(database, count))


def _fetch(database: str, sql: str, *args):
    return asyncio.run(_with_conn(database, lambda c: c.fetch(sql, *args)))


def _fetchval(database: str, sql: str, *args):
    return asyncio.run(_with_conn(database, lambda c: c.fetchval(sql, *args)))


def _seed(database: str) -> SeedResult:
    async def run() -> SeedResult:
        engine = create_async_engine(helpers.sqlalchemy_url(database), poolclass=NullPool)
        try:
            return await seed_dataset(async_sessionmaker(engine, expire_on_commit=False, autoflush=False))
        finally:
            await engine.dispose()
    return asyncio.run(run())


# -- 1. exact inverse -------------------------------------------------------------------------------


def test_every_downgrade_is_the_exact_inverse_of_its_upgrade(empty_db: str) -> None:
    revisions = _revisions()
    forward = {"base": _fingerprint(empty_db)}
    for rev in revisions:
        helpers.upgrade(empty_db, rev)
        forward[rev] = _fingerprint(empty_db)

    for index in range(len(revisions) - 1, -1, -1):
        target = revisions[index - 1] if index > 0 else "base"
        helpers.downgrade(empty_db, target)
        actual = _fingerprint(empty_db)
        assert actual == forward[target], (
            f"downgrade {revisions[index]} -> {target} is not the exact inverse:\n"
            + describe_difference(forward[target], actual)
        )

    helpers.upgrade(empty_db, "head")
    assert _fingerprint(empty_db) == forward[revisions[-1]], "re-upgrade must reproduce the head schema"


def test_fingerprint_sees_every_kind_of_object(empty_db: str) -> None:
    """Guard against a vacuous exact-inverse test: the head fingerprint must contain real objects."""
    helpers.upgrade(empty_db, "head")
    fp = _fingerprint(empty_db)

    assert len({row[0] for row in fp["columns"]}) == EXPECTED_TABLES
    assert {row[1] for row in fp["triggers"]} >= {
        "trg_forbid_tenant_id_change", "trg_audit_events_no_update_delete", "trg_audit_events_chain",
        "trg_protect_recovery_snapshot", "trg_policy_decisions_permanent",
    }
    assert {row[0] for row in fp["functions"]} >= {"amsc_audit_chain_break", "amsc_audit_protection_report"}
    assert any(row[2] == "f" for row in fp["constraints"]) and any(row[2] == "c" for row in fp["constraints"])
    assert fp["indexes"]


# -- 2. clean -> fully seeded, down and up again -------------------------------------------------------


def _assert_intact(database: str, seed: SeedResult) -> None:
    for tenant in (seed.tenant_a, seed.tenant_b):
        assert _fetchval(database, "SELECT amsc_audit_chain_break($1)", tenant) is None
    report = _fetch(database, "SELECT check_name, ok FROM amsc_audit_protection_report()")
    assert report and all(r["ok"] for r in report), [dict(r) for r in report]
    assert _fetchval(database, "SELECT current_version FROM memory_records WHERE id = $1", seed.ids["rec1"]) == 1
    assert _fetchval(database, "SELECT executed_at IS NOT NULL FROM recovery_plans WHERE id = $1", seed.ids["plan"])


AUDIT_FIELDS = "id, tenant_id, actor_id, event_type, resource_id, action, outcome, trace_id, details_json, occurred_at"
DECISION_FIELDS = "id, proposal_id, decision, memory_trust, policy_result, reasons_json, incident_id, execution_status"


def test_seeded_database_goes_down_to_0001_and_back_up_without_losing_data(empty_db: str) -> None:
    revisions = _revisions()
    helpers.upgrade(empty_db, "head")
    seed = _seed(empty_db)

    counts = _row_counts(empty_db)
    assert len(counts) == EXPECTED_TABLES and all(n > 0 for n in counts.values()), (
        f"the fixture must populate every table: {[t for t, n in counts.items() if n == 0]}"
    )
    _assert_intact(empty_db, seed)
    audit_before = _fetch(empty_db, f"SELECT {AUDIT_FIELDS} FROM audit_events ORDER BY id")
    decisions_before = _fetch(empty_db, f"SELECT {DECISION_FIELDS} FROM policy_decisions ORDER BY id")
    snapshot_before = _fetchval(empty_db, "SELECT pre_recovery_snapshot_json::text FROM recovery_plans WHERE id = $1",
                                seed.ids["plan"])

    # Down, one revision at a time, to 0001 (0001 -> base would drop every table by design).
    for index in range(len(revisions) - 1, 0, -1):
        helpers.downgrade(empty_db, revisions[index - 1])
        if revisions[index] == "0015":
            for t in (
                "enterprise_connectors",
                "discovered_resources",
                "sync_jobs",
                "knowledge_claims",
                "enterprise_memory_links",
                "connector_audit_logs",
            ):
                counts.pop(t, None)
        elif revisions[index] == "0014":
            counts.pop("detection_results", None)
        elif revisions[index] == "0013":
            for t in (
                "observation_events",
                "agent_security_profiles",
                "baseline_governance_logs",
                "enterprise_baseline_versions",
                "enterprise_baseline_records",
                "trust_decisions",
            ):
                counts.pop(t, None)
        elif revisions[index] == "0011":
            # 0011 owns registration_requests; its downgrade intentionally drops that feature table.
            counts.pop("registration_requests", None)
        elif revisions[index] == "0017":
            # 0017 owns the Phase 2 company application tables; downgrade removes this feature schema.
            for t in (
                "company_workspaces", "company_files", "company_file_versions",
                "company_file_transfers", "company_tasks", "company_task_events",
                "company_messages", "company_notifications", "company_activity",
            ):
                counts.pop(t, None)
        assert _row_counts(empty_db) == counts, f"rows lost by downgrade {revisions[index]} -> {revisions[index - 1]}"

    # Up again, one revision at a time, to head (every pre-check must pass on this data).
    # Recreating 0011/0013/0014 creates empty feature tables; request/detection data was
    # intentionally removed by the documented downgrade above.
    for rev in revisions[1:]:
        helpers.upgrade(empty_db, rev)
        if rev == "0011":
            counts["registration_requests"] = 0
        elif rev == "0013":
            counts.update({
                "observation_events": 0,
                "agent_security_profiles": 0,
                "baseline_governance_logs": 0,
                "enterprise_baseline_versions": 0,
                "enterprise_baseline_records": 0,
                "trust_decisions": 0,
            })
        elif rev == "0014":
            counts["detection_results"] = 0
        elif rev == "0015":
            counts.update({
                "enterprise_connectors": 0,
                "discovered_resources": 0,
                "sync_jobs": 0,
                "knowledge_claims": 0,
                "enterprise_memory_links": 0,
                "connector_audit_logs": 0,
            })
        elif rev == "0017":
            # Re-upgrading recreates the company tables empty; their prior data was
            # intentionally removed when 0017 was downgraded.
            counts.update({
                "company_workspaces": 0,
                "company_files": 0,
                "company_file_versions": 0,
                "company_file_transfers": 0,
                "company_tasks": 0,
                "company_task_events": 0,
                "company_messages": 0,
                "company_notifications": 0,
                "company_activity": 0,
            })
        assert _row_counts(empty_db) == counts, f"rows lost by upgrade to {rev}"

    _assert_intact(empty_db, seed)
    assert _fetch(empty_db, f"SELECT {AUDIT_FIELDS} FROM audit_events ORDER BY id") == audit_before
    assert _fetch(empty_db, f"SELECT {DECISION_FIELDS} FROM policy_decisions ORDER BY id") == decisions_before
    assert _fetchval(empty_db, "SELECT pre_recovery_snapshot_json::text FROM recovery_plans WHERE id = $1",
                     seed.ids["plan"]) == snapshot_before

    # Documented downgrade effects (INTEGRATION-GUIDE.md, "What a downgrade loses"):
    statuses = {r["status"] for r in _fetch(empty_db, "SELECT status FROM memberships")}
    assert statuses == {"INACTIVE"}, "0003: status values are dropped; re-upgrade must not re-activate anyone"
    sources = {r["status"] for r in _fetch(empty_db, "SELECT status FROM sources")}
    assert sources == {"INACTIVE"}, "0006: source status values are dropped; re-upgrade sets INACTIVE"
    plan_hash = _fetchval(
        empty_db,
        "SELECT pre_recovery_snapshot_sha256 = encode(sha256(convert_to(pre_recovery_snapshot_json::text, 'UTF8')), "
        "'hex') FROM recovery_plans WHERE id = $1", seed.ids["plan"])
    assert plan_hash is True, "0008: the snapshot hash is rebuilt from the kept snapshot"


def test_seed_keeps_tenants_isolated(empty_db: str) -> None:
    helpers.upgrade(empty_db, "head")
    seed = _seed(empty_db)

    per_tenant = {r["tenant_id"]: r["n"] for r in _fetch(
        empty_db, "SELECT tenant_id, count(*) AS n FROM audit_events GROUP BY tenant_id")}
    assert per_tenant == {seed.tenant_a: 3, seed.tenant_b: 2}
    branches = {r["code"] for r in _fetch(empty_db, "SELECT code FROM branches WHERE tenant_id = $1", seed.tenant_a)}
    assert branches == {"HO", "LHR", "KHI", "ISB"}
    assert _fetchval(
        empty_db, "SELECT count(*) FROM memory_records WHERE tenant_id = $1", seed.tenant_b) == 1
