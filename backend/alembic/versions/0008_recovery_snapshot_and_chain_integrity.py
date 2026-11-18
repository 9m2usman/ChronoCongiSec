"""Pre-recovery snapshot preservation and recovery chain integrity (Day 5).

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-18

Owner: M6. DOC-006 Day 5 M6 row ("Implement atomic Agent Rewind rollback with
pre-recovery state preservation"; exit: "Pre-recovery snapshot committed before
rollback"), TRD section 18 and SEC-007 ("Pre-recovery state snapshot must be persisted
before any recovery rollback executes").

1. ``recovery_plans.pre_recovery_snapshot_sha256`` VARCHAR(64), NULL until captured.
   - ``ck_recovery_plans_snapshot_hash_consistent``: empty snapshot <=> NULL hash, and a
     captured snapshot's hash must equal sha256(snapshot::text) computed by PostgreSQL.
   - ``ck_recovery_plans_executed_requires_snapshot``: ``executed_at`` can only be set
     after the snapshot exists.
   - Trigger ``trg_protect_recovery_snapshot``: once captured, the snapshot and its hash
     cannot change, and the plan cannot be deleted.
   - Trigger ``trg_require_recovery_snapshot`` on recovery_actions: no action can be
     recorded for a plan whose snapshot was not captured.
2. ``UNIQUE (tenant_id, checkpoint_id, record_id)`` on checkpoint_items: a checkpoint holds
   each record at most once, so a rewind target is unambiguous.
3. ON DELETE CASCADE becomes RESTRICT on the recovery chain:
   checkpoint_items.checkpoint_id, recovery_plans.checkpoint_id, recovery_actions.plan_id,
   incident_evidence.incident_id.

Deliberately NOT included (OPEN-DEPENDENCIES): recovery plan status values/transitions,
action_taken/outcome values, rollback semantics (new version vs moving current_version)
and the checkpoint integrity_hash method.

Existing data:
- Snapshots that are already non-empty get their hash back-filled (computed from the
  stored snapshot; nothing else changes).
- The upgrade STOPS, listing ids and changing nothing, if it finds a checkpoint holding the
  same record twice, a plan with ``executed_at`` but no snapshot, or a recovery action whose
  plan has no snapshot. Nothing is deleted or invented. Offline mode skips the checks.

Downgrade restores the exact 0007 state. The hash column (and its values) is dropped;
snapshots themselves are kept. No rows are deleted.
The data below is frozen on purpose; do not import application models here.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

revision: str = "0008"
down_revision: Union[str, Sequence[str], None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SNAPSHOT_SHA256_SQL = "encode(sha256(convert_to(pre_recovery_snapshot_json::text, 'UTF8')), 'hex')"

HASH_CHECK = "ck_recovery_plans_snapshot_hash_consistent"
EXECUTED_CHECK = "ck_recovery_plans_executed_requires_snapshot"
ITEM_UNIQUE = "uq_checkpoint_items_tenant_id_checkpoint_id_record_id"

PROTECT_FUNCTION = "amsc_protect_recovery_snapshot"
PROTECT_TRIGGER = "trg_protect_recovery_snapshot"
REQUIRE_FUNCTION = "amsc_require_recovery_snapshot"
REQUIRE_TRIGGER = "trg_require_recovery_snapshot"

# (child_table, column, parent_table): two-column tenant FKs that change CASCADE -> RESTRICT.
RECOVERY_CHAIN = (
    ("checkpoint_items", "checkpoint_id", "checkpoints"),
    ("recovery_plans", "checkpoint_id", "checkpoints"),
    ("recovery_actions", "plan_id", "recovery_plans"),
    ("incident_evidence", "incident_id", "incidents"),
)

MAX_REPORTED_IDS = 20


def _set_chain_rule(table: str, column: str, parent: str, rule: str) -> None:
    name = f"fk_{table}_{column}_tenant"
    op.drop_constraint(name, table, type_="foreignkey")
    op.create_foreign_key(name, table, parent, ["tenant_id", column], ["tenant_id", "id"], ondelete=rule)


def _check_existing_data() -> None:
    if context.is_offline_mode():
        return
    bind = op.get_bind()
    problems = []

    duplicates = bind.execute(sa.text(
        f"""
        SELECT array_agg(id ORDER BY id) FROM checkpoint_items
        GROUP BY tenant_id, checkpoint_id, record_id HAVING count(*) > 1
        ORDER BY min(id) LIMIT {MAX_REPORTED_IDS}
        """
    )).scalars().all()
    if duplicates:
        problems.append(f"checkpoint_items holding the same record twice in one checkpoint: {duplicates}")

    executed_without_snapshot = bind.execute(sa.text(
        f"""
        SELECT id FROM recovery_plans
        WHERE executed_at IS NOT NULL AND pre_recovery_snapshot_json = '{{}}'::jsonb
        ORDER BY id LIMIT {MAX_REPORTED_IDS}
        """
    )).scalars().all()
    if executed_without_snapshot:
        problems.append(f"executed recovery_plans without a pre-recovery snapshot: {executed_without_snapshot}")

    actions_without_snapshot = bind.execute(sa.text(
        f"""
        SELECT a.id FROM recovery_actions a
        JOIN recovery_plans p ON p.tenant_id = a.tenant_id AND p.id = a.plan_id
        WHERE p.pre_recovery_snapshot_json = '{{}}'::jsonb
        ORDER BY a.id LIMIT {MAX_REPORTED_IDS}
        """
    )).scalars().all()
    if actions_without_snapshot:
        problems.append(f"recovery_actions whose plan has no pre-recovery snapshot: {actions_without_snapshot}")

    if problems:
        raise RuntimeError(
            "Migration 0008 stopped: existing recovery data violates the new rules. "
            "Nothing was changed; review these rows manually. " + " | ".join(problems)
        )


def upgrade() -> None:
    _check_existing_data()

    # 1. Snapshot fingerprint (back-filled for snapshots that already exist).
    op.add_column("recovery_plans", sa.Column("pre_recovery_snapshot_sha256", sa.String(64), nullable=True))
    op.execute(
        f"UPDATE recovery_plans SET pre_recovery_snapshot_sha256 = {SNAPSHOT_SHA256_SQL} "
        "WHERE pre_recovery_snapshot_json <> '{}'::jsonb"
    )
    op.create_check_constraint(
        op.f(HASH_CHECK),
        "recovery_plans",
        "(pre_recovery_snapshot_json = '{}'::jsonb AND pre_recovery_snapshot_sha256 IS NULL) OR "
        "(pre_recovery_snapshot_json <> '{}'::jsonb AND pre_recovery_snapshot_sha256 IS NOT NULL "
        f"AND pre_recovery_snapshot_sha256 = {SNAPSHOT_SHA256_SQL})",
    )
    op.create_check_constraint(
        op.f(EXECUTED_CHECK), "recovery_plans", "executed_at IS NULL OR pre_recovery_snapshot_sha256 IS NOT NULL"
    )

    # 2. One version per record per checkpoint.
    op.create_unique_constraint(op.f(ITEM_UNIQUE), "checkpoint_items", ["tenant_id", "checkpoint_id", "record_id"])

    # 3. Recovery chain is forensic evidence.
    for table, column, parent in RECOVERY_CHAIN:
        _set_chain_rule(table, column, parent, "RESTRICT")

    # 4. Snapshot immutability / delete protection, and "no action without snapshot".
    op.execute(
        f"""
        CREATE FUNCTION {PROTECT_FUNCTION}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                IF OLD.pre_recovery_snapshot_sha256 IS NOT NULL THEN
                    RAISE EXCEPTION 'recovery plan % has a captured pre-recovery snapshot and cannot be deleted', OLD.id
                        USING ERRCODE = '55000';
                END IF;
                RETURN OLD;
            END IF;
            IF OLD.pre_recovery_snapshot_sha256 IS NOT NULL AND (
                NEW.pre_recovery_snapshot_json IS DISTINCT FROM OLD.pre_recovery_snapshot_json
                OR NEW.pre_recovery_snapshot_sha256 IS DISTINCT FROM OLD.pre_recovery_snapshot_sha256
            ) THEN
                RAISE EXCEPTION 'pre-recovery snapshot of recovery plan % is immutable', OLD.id
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        f"CREATE TRIGGER {PROTECT_TRIGGER} BEFORE UPDATE OR DELETE ON recovery_plans "
        f"FOR EACH ROW EXECUTE FUNCTION {PROTECT_FUNCTION}()"
    )
    op.execute(
        f"""
        CREATE FUNCTION {REQUIRE_FUNCTION}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
            snapshot_hash varchar(64);
        BEGIN
            SELECT pre_recovery_snapshot_sha256 INTO snapshot_hash
            FROM recovery_plans WHERE tenant_id = NEW.tenant_id AND id = NEW.plan_id;
            IF FOUND AND snapshot_hash IS NULL THEN
                RAISE EXCEPTION 'recovery action requires a captured pre-recovery snapshot (plan %)', NEW.plan_id
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;  -- an unknown plan is rejected by the foreign key
        END;
        $$;
        """
    )
    op.execute(
        f"CREATE TRIGGER {REQUIRE_TRIGGER} BEFORE INSERT OR UPDATE OF plan_id, tenant_id ON recovery_actions "
        f"FOR EACH ROW EXECUTE FUNCTION {REQUIRE_FUNCTION}()"
    )


def downgrade() -> None:
    op.execute(f"DROP TRIGGER {REQUIRE_TRIGGER} ON recovery_actions")
    op.execute(f"DROP FUNCTION {REQUIRE_FUNCTION}()")
    op.execute(f"DROP TRIGGER {PROTECT_TRIGGER} ON recovery_plans")
    op.execute(f"DROP FUNCTION {PROTECT_FUNCTION}()")

    for table, column, parent in reversed(RECOVERY_CHAIN):
        _set_chain_rule(table, column, parent, "CASCADE")

    op.drop_constraint(op.f(ITEM_UNIQUE), "checkpoint_items", type_="unique")
    op.drop_constraint(op.f(EXECUTED_CHECK), "recovery_plans", type_="check")
    op.drop_constraint(op.f(HASH_CHECK), "recovery_plans", type_="check")
    op.drop_column("recovery_plans", "pre_recovery_snapshot_sha256")
