"""Hash-chained audit events, audit verification functions, permanent policy decisions (Day 6).

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-18

Owner: M6. DOC-006 Day 6 M6 row ("Verify append-only constraints on audit events table";
deliverable: audit verification DDL), TRD SEC-010, TRD section 8 "Append-Only Immutability"
(audit_events AND policy_decisions are permanent forensic records), doc 07 lines 144/549
("Append-only/hash-chained audit evidence", "tamper-evident evidence for decisions").

1. Per-tenant hash chain on audit_events:
   - new columns ``chain_seq`` (1, 2, 3 ... per tenant), ``prev_hash``, ``event_hash``;
   - ``amsc_audit_event_hash(...)``: SHA-256 over the previous hash and every audit field
     (fields separated by U+001F; timestamps as UTC epoch seconds, so the result does not
     depend on DateStyle or time zone settings);
   - BEFORE INSERT trigger ``trg_audit_events_chain`` takes a per-tenant advisory lock,
     reads the tenant's last event and fills the three columns. Caller values are ignored;
   - ``UNIQUE (tenant_id, chain_seq)`` and ``ck_audit_events_chain_link``.
2. Verification DDL:
   - ``amsc_audit_chain_break(tenant_id)``: first broken ``chain_seq`` (wrong hash, wrong
     link or a gap), NULL if intact;
   - ``amsc_audit_protection_report()``: append-only and chain triggers enabled, every
     tenant's chain intact.
3. ``trg_policy_decisions_permanent``: a policy decision can never be deleted, and only its
   ``execution_status`` may change (the gateway records the execution outcome there; OD-25).

ONE-TIME TRIGGER PAUSE (backfill): existing audit rows get their chain inside this
migration's transaction, ordered by (occurred_at, id) per tenant. Writing the three new
columns on existing rows is an UPDATE, which 0004's ``trg_audit_events_no_update_delete``
forbids, so that trigger is DISABLED for the backfill and ENABLED again right after, in
the same transaction. The backfill only writes chain_seq / prev_hash / event_hash; no
original audit field changes (covered by a test). If anything fails, the transaction rolls
back and the trigger stays enabled. This requires the migration to run as the table owner.

No pre-check is needed: no existing data can violate these rules (decisions are not
changed by the migration).

Downgrade restores the exact 0008 state: the chain columns (and their values), the
functions and both new triggers are removed. 0004's append-only triggers are untouched.
The data below is frozen on purpose; do not import application models here.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, Sequence[str], None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APPEND_ONLY_TRIGGER = "trg_audit_events_no_update_delete"  # created by 0004 (not renamed here)

HASH_FUNCTION = "amsc_audit_event_hash"
CHAIN_FUNCTION = "amsc_audit_events_chain"
CHAIN_TRIGGER = "trg_audit_events_chain"
BREAK_FUNCTION = "amsc_audit_chain_break"
REPORT_FUNCTION = "amsc_audit_protection_report"
DECISION_FUNCTION = "amsc_policy_decisions_permanent"
DECISION_TRIGGER = "trg_policy_decisions_permanent"

CHAIN_UNIQUE = "uq_audit_events_tenant_id_chain_seq"
CHAIN_CHECK = "ck_audit_events_chain_link"

HASH_SIGNATURE = (
    "prev_hash text, tenant_id text, event_id text, actor_id text, event_type text, resource_id text, "
    "action text, outcome text, trace_id text, details jsonb, occurred_at timestamptz"
)
HASH_ARG_TYPES = "text, text, text, text, text, text, text, text, text, jsonb, timestamptz"


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("chain_seq", sa.BigInteger(), nullable=True))
    op.add_column("audit_events", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column("audit_events", sa.Column("event_hash", sa.String(64), nullable=True))

    op.execute(
        f"""
        CREATE FUNCTION {HASH_FUNCTION}({HASH_SIGNATURE}) RETURNS text
        LANGUAGE sql STABLE AS $$
            SELECT encode(sha256(convert_to(concat_ws(chr(31),
                coalesce(prev_hash, ''), tenant_id, event_id, actor_id, event_type, resource_id,
                action, outcome, coalesce(trace_id, ''), details::text,
                extract(epoch FROM occurred_at)::text
            ), 'UTF8')), 'hex')
        $$;
        """
    )

    # --- one-time backfill with 0004's append-only trigger paused (same transaction) ---
    op.execute(f"ALTER TABLE audit_events DISABLE TRIGGER {APPEND_ONLY_TRIGGER}")
    op.execute(
        f"""
        DO $$
        DECLARE
            r record;
            current_tenant text := NULL;
            last_hash text;
            seq bigint;
        BEGIN
            FOR r IN SELECT * FROM audit_events ORDER BY tenant_id, occurred_at, id LOOP
                IF current_tenant IS DISTINCT FROM r.tenant_id THEN
                    current_tenant := r.tenant_id;
                    last_hash := NULL;
                    seq := 0;
                END IF;
                seq := seq + 1;
                UPDATE audit_events
                SET chain_seq = seq,
                    prev_hash = last_hash,
                    event_hash = {HASH_FUNCTION}(last_hash, r.tenant_id, r.id, r.actor_id, r.event_type,
                                                r.resource_id, r.action, r.outcome, r.trace_id,
                                                r.details_json, r.occurred_at)
                WHERE id = r.id
                RETURNING event_hash INTO last_hash;
            END LOOP;
        END;
        $$;
        """
    )
    op.execute(f"ALTER TABLE audit_events ENABLE TRIGGER {APPEND_ONLY_TRIGGER}")

    op.alter_column("audit_events", "chain_seq", nullable=False)
    op.alter_column("audit_events", "event_hash", nullable=False)
    op.create_unique_constraint(op.f(CHAIN_UNIQUE), "audit_events", ["tenant_id", "chain_seq"])
    op.create_check_constraint(
        op.f(CHAIN_CHECK),
        "audit_events",
        "(chain_seq = 1 AND prev_hash IS NULL) OR (chain_seq > 1 AND prev_hash IS NOT NULL)",
    )

    op.execute(
        f"""
        CREATE FUNCTION {CHAIN_FUNCTION}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
            last_seq bigint;
            last_hash text;
        BEGIN
            -- One writer per tenant chain at a time (released at commit/rollback).
            PERFORM pg_advisory_xact_lock(hashtextextended('amsc_audit_chain:' || NEW.tenant_id, 0));
            SELECT chain_seq, event_hash INTO last_seq, last_hash
            FROM audit_events WHERE tenant_id = NEW.tenant_id
            ORDER BY chain_seq DESC LIMIT 1;
            NEW.chain_seq := coalesce(last_seq, 0) + 1;
            NEW.prev_hash := last_hash;
            NEW.event_hash := {HASH_FUNCTION}(NEW.prev_hash, NEW.tenant_id, NEW.id, NEW.actor_id, NEW.event_type,
                                             NEW.resource_id, NEW.action, NEW.outcome, NEW.trace_id,
                                             NEW.details_json, NEW.occurred_at);
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        f"CREATE TRIGGER {CHAIN_TRIGGER} BEFORE INSERT ON audit_events "
        f"FOR EACH ROW EXECUTE FUNCTION {CHAIN_FUNCTION}()"
    )

    op.execute(
        f"""
        CREATE FUNCTION {BREAK_FUNCTION}(p_tenant_id text) RETURNS bigint
        LANGUAGE plpgsql STABLE AS $$
        DECLARE
            r record;
            expected_seq bigint := 1;
            last_hash text := NULL;
        BEGIN
            FOR r IN SELECT * FROM audit_events WHERE tenant_id = p_tenant_id ORDER BY chain_seq LOOP
                IF r.chain_seq <> expected_seq
                   OR r.prev_hash IS DISTINCT FROM last_hash
                   OR r.event_hash IS DISTINCT FROM {HASH_FUNCTION}(
                        r.prev_hash, r.tenant_id, r.id, r.actor_id, r.event_type, r.resource_id,
                        r.action, r.outcome, r.trace_id, r.details_json, r.occurred_at) THEN
                    RETURN expected_seq;
                END IF;
                last_hash := r.event_hash;
                expected_seq := expected_seq + 1;
            END LOOP;
            RETURN NULL;
        END;
        $$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION {REPORT_FUNCTION}() RETURNS TABLE(check_name text, ok boolean, detail text)
        LANGUAGE plpgsql STABLE AS $$
        DECLARE
            trigger_name text;
            enabled text;
            broken text[];
        BEGIN
            FOREACH trigger_name IN ARRAY ARRAY['trg_audit_events_no_update_delete', 'trg_audit_events_no_truncate',
                                        '{CHAIN_TRIGGER}', 'trg_forbid_tenant_id_change'] LOOP
                SELECT t.tgenabled::text INTO enabled FROM pg_trigger t
                WHERE t.tgrelid = 'audit_events'::regclass AND t.tgname = trigger_name AND NOT t.tgisinternal;
                check_name := 'trigger ' || trigger_name;
                ok := enabled IS NOT NULL AND enabled <> 'D';
                detail := coalesce('tgenabled=' || enabled, 'missing');
                RETURN NEXT;
            END LOOP;
            SELECT array_agg(tenant_id ORDER BY tenant_id) INTO broken
            FROM (SELECT DISTINCT tenant_id FROM audit_events) t
            WHERE {BREAK_FUNCTION}(t.tenant_id) IS NOT NULL;
            check_name := 'hash chains intact';
            ok := broken IS NULL;
            detail := CASE WHEN broken IS NULL THEN 'all tenants' ELSE 'broken: ' || array_to_string(broken, ', ') END;
            RETURN NEXT;
        END;
        $$;
        """
    )

    op.execute(
        f"""
        CREATE FUNCTION {DECISION_FUNCTION}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'policy_decisions are permanent; DELETE is forbidden (decision %)', OLD.id
                    USING ERRCODE = '55000';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.proposal_id IS DISTINCT FROM OLD.proposal_id
               OR NEW.decision IS DISTINCT FROM OLD.decision
               OR NEW.memory_trust IS DISTINCT FROM OLD.memory_trust
               OR NEW.policy_result IS DISTINCT FROM OLD.policy_result
               OR NEW.reasons_json IS DISTINCT FROM OLD.reasons_json
               OR NEW.incident_id IS DISTINCT FROM OLD.incident_id
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'policy_decisions are permanent; only execution_status may change (decision %)', OLD.id
                    USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        f"CREATE TRIGGER {DECISION_TRIGGER} BEFORE UPDATE OR DELETE ON policy_decisions "
        f"FOR EACH ROW EXECUTE FUNCTION {DECISION_FUNCTION}()"
    )


def downgrade() -> None:
    op.execute(f"DROP TRIGGER {DECISION_TRIGGER} ON policy_decisions")
    op.execute(f"DROP FUNCTION {DECISION_FUNCTION}()")
    op.execute(f"DROP FUNCTION {REPORT_FUNCTION}()")
    op.execute(f"DROP FUNCTION {BREAK_FUNCTION}(text)")
    op.execute(f"DROP TRIGGER {CHAIN_TRIGGER} ON audit_events")
    op.execute(f"DROP FUNCTION {CHAIN_FUNCTION}()")
    op.drop_constraint(op.f(CHAIN_CHECK), "audit_events", type_="check")
    op.drop_constraint(op.f(CHAIN_UNIQUE), "audit_events", type_="unique")
    op.drop_column("audit_events", "event_hash")
    op.drop_column("audit_events", "prev_hash")
    op.drop_column("audit_events", "chain_seq")
    op.execute(f"DROP FUNCTION {HASH_FUNCTION}({HASH_ARG_TYPES})")
