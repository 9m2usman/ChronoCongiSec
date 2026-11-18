# M6 Database Integration Guide

**Audience:** the team (M1–M7) integrating with the PostgreSQL layer.
**Owner:** M6, Database Architect & Governance.
**State:** `main` with migrations `0001`–`0009` (head `0009`).

Work history, the decisions behind each rule, and every open question are recorded in [M6-PROGRESS-LOG.md](M6-PROGRESS-LOG.md). Open questions are collected in its **OPEN-DEPENDENCIES** list (OD-1 … OD-28). This guide covers *how to use* the database layer.

---

## 1. Setup

```powershell
docker compose up -d postgres                       # PostgreSQL 16 (docker-compose.yml)
py -3.12 -m venv .venv                              # Python 3.12 (asyncpg 0.29.0 has no 3.13/3.14 wheel)
.venv\Scripts\python.exe -m pip install -r backend/requirements.txt

# Apply the schema to the database named by DATABASE_URL (.env / environment):
.venv\Scripts\alembic.exe -c backend/alembic.ini upgrade head
```

Run the database tests. They create and drop their own `amsc_test_*` databases and `amsc_test_role_*` roles, and never touch the database in `DATABASE_URL`:

```powershell
$env:TEST_DATABASE_URL = "postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/postgres"
.venv\Scripts\python.exe -m pytest backend/tests/database -q
```

- `TEST_DATABASE_URL` is required. There is no fallback to `DATABASE_URL`.
- The host must be local, or be listed in `TEST_DATABASE_ALLOWED_HOSTS` (for example `postgres` for a CI service).
- The test login needs `CREATEDB` and `CREATEROLE`.

---

## 2. Connecting

```python
from backend.app.database.session import create_engine, create_session_factory

engine = create_engine()                    # DATABASE_URL; only postgresql+asyncpg is accepted
session_factory = create_session_factory(engine)
```

The layer is async (SQLAlchemy 2.x AsyncIO + asyncpg), as required by the TRD. Synchronous callers need an async boundary (OD-13).

---

## 3. Which tool for which job

| Job | Use | Notes |
|---|---|---|
| Several writes that must succeed or fail together | `UnitOfWork` (`backend/app/database/unit_of_work.py`) | One session and one transaction per `async with`. Commits on success, rolls back on any exception. |
| Generic tenant-scoped CRUD for any tenant-owned model | `TenantScopedRepository(session, tenant_id, model=X)` | `get`, `list(limit, offset, **filters)`, `add`, `update`, `delete`. Always filtered by tenant. Never commits. |
| Login: a user's membership in a tenant | `MembershipRepository.get_for_user(user_id)` | Returns the row including `status`. Only `ACTIVE` should grant access (M1 decides). |
| Gateway: proposal by idempotency key | `tx.proposals.get_by_idempotency_key(key)` | `UNIQUE (tenant_id, idempotency_key)` |
| Gateway: decision / execution of a proposal | `tx.decisions.get_for_proposal(id)`, `tx.executions.get_for_proposal(id)` | |
| Approvals of a decision | `tx.approvals.list_for_decision(decision_id, limit, offset)` | |
| Audit trail | `tx.audit.append(event)`, `tx.audit.list_recent()`, `tx.audit.chain_break()` | Append-only and hash-chained. Never set `chain_seq` / `prev_hash` / `event_hash`. |
| Provenance edges touching a record | `ProvenanceEdgeRepository.edges_for_record(record_id, limit, offset)` | Both directions, ordered by id, returns `has_more`. |
| Version that `current_version` points to / highest version | `MemoryVersionRepository.current_version_for_record` / `.highest_version_for_record` | They can differ after a rollback (OD-17). |
| Agent rewind with pre-recovery snapshot | `RewindCoordinator` (`backend/app/database/rewind.py`) | Two transactions: the snapshot is committed before any rollback. |
| Least-privilege database role (for M7) | `backend/app/database/roles.py` | Generates SQL only; see section 8. |

**Pagination:** every list defaults to 50 rows, with a maximum of 100. `limit` and `offset` must be integers; anything else raises `ValueError`.

---

## 4. Examples

### Gateway action: proposal, decision, execution and audit in one transaction

```python
from backend.app.database.unit_of_work import UnitOfWork
from backend.app.database.models import ToolProposal, PolicyDecision, ToolExecution, AuditEvent

uow = UnitOfWork(session_factory)            # optional: statement_timeout_ms=..., lock_timeout_ms=...
async with uow(tenant_id) as tx:             # tenant_id from the verified request context, never from a header
    proposal = await tx.proposals.add(ToolProposal(id=..., agent_id=..., action_id=..., tool_name=...,
                                                    operation=..., idempotency_key=..., trace_id=...))
    decision = await tx.decisions.add(PolicyDecision(id=..., proposal_id=proposal.id, decision=...,
                                                      memory_trust=..., policy_result=...))
    await tx.executions.add(ToolExecution(id=..., proposal_id=proposal.id, decision_id=decision.id))
    await tx.audit.append(AuditEvent(id=..., actor_id=..., event_type=..., resource_id=proposal.id,
                                     action=..., outcome=...))
# Leaving the block commits. Any exception rolls everything back.
```

- Do not call `tx.session.commit()` yourself.
- The transaction sets `app.tenant_id` transaction-locally, which prepares for RLS (OD-11/OD-18).
- The allowed values for `decision`, `execution_status` and the status columns are not fixed yet (OD-1 … OD-9). The database stores what you send.

### Agent rewind

```python
from backend.app.database.rewind import RewindCoordinator

coordinator = RewindCoordinator(session_factory)
receipt = await coordinator.capture_snapshot(tenant_id, plan_id, {"records": [...]})   # tx 1: COMMITTED

async def restore(rtx):
    item = await rtx.checkpoint_item_for(record_id)
    # Choose new-version vs pointer move (OD-17), then for example:
    await rtx.compare_and_set_current_version(record_id, expected=3, new=1)
    await rtx.record_action(record_id, "RESTORED_TO_CHECKPOINT")

await coordinator.execute_rollback(tenant_id, plan_id,
                                   expected_snapshot_sha256=receipt.sha256, restore=restore)      # tx 2
```

If the restore fails, only transaction 2 is rolled back. The committed snapshot stays, and the rewind can be retried.

---

## 5. What the database rejects

Raw asyncpg raises the classes below. Through SQLAlchemy the same errors arrive as `IntegrityError` (class 23) or `DBAPIError` (other classes), with the original error in `.orig`.

| SQLSTATE | asyncpg class | Typical cause | What to do |
|---|---|---|---|
| 23503 | `ForeignKeyViolationError` | A reference to another tenant's row, a missing parent, or deleting a parent protected by RESTRICT | Treat as "not found / not allowed". Do not retry. |
| 23505 | `UniqueViolationError` | Duplicate idempotency key (`uq_tenant_idemp_key`), duplicate provenance edge, a record twice in one checkpoint | Idempotency: load the stored proposal and return its result. |
| 23514 | `CheckViolationError` | Unknown membership/source status, unknown relation type, self-loop, inconsistent snapshot hash, `executed_at` without a snapshot | Fix the input. |
| 23502 | `NotNullViolationError` | A required value is missing (for example `tenant_id`, `decision_id`) | Fix the input. |
| 23000 | `IntegrityConstraintViolationError` | `tenant_id is immutable` | Never move rows between tenants. |
| 55000 | `ObjectNotInPrerequisiteStateError` | Changing/deleting audit events; deleting or changing a policy decision (only `execution_status` may change); changing or deleting a captured recovery snapshot; a recovery action without a snapshot | These are permanent records. Write new rows instead. |
| 42501 | `InsufficientPrivilegeError` | The least-privilege app role tried something it may never do (section 8) | A bug in the caller. |

Python-side refusals (nothing reaches the database):
- `TenantScopeError`: empty tenant, or another tenant's entity.
- `ValueError`: bad pagination or arguments.
- `AppendOnlyError`: audit `update`/`delete`.
- `RewindError` subclasses: `PlanNotFound`, `RecordNotFound`, `SnapshotAlreadyCaptured`, `SnapshotMissing`, `SnapshotMismatch`, `PlanAlreadyExecuted`, `ConcurrencyConflict`.

### Rules that follow from this
- **Revoke access with status, not delete:** `memberships.status = 'REVOKED'`. A membership that approved something cannot be deleted.
- **Isolate, do not delete, agents** that have tool proposals: `agents.status = 'ISOLATED'`.
- Tenants, proposals, decisions, approvals, executions, incidents with evidence, checkpoints in use, captured recovery plans and audit events are **never physically deleted**. Deactivate them instead.
- Pre-existing memberships and sources became `INACTIVE` when their status columns were introduced. Activate them explicitly.

---

## 6. Migration history and what a downgrade loses

| Rev | Adds | A downgrade loses |
|---|---|---|
| 0001 | 36 tables (DOC-005) | **0001 → base drops every table and all data** |
| 0002 | Composite tenant FKs, `tenant_id` immutability | Only the rules (no data) |
| 0003 | `memberships.status`, approver must be a member, forensic RESTRICT | **`memberships.status` values** (a re-upgrade sets every existing membership to INACTIVE) |
| 0004 | Append-only `audit_events` triggers | Only the rules |
| 0005 | A checkpoint item's version belongs to its record | Only the rule |
| 0006 | `sources.status`, provenance edge rules | **`sources.status` values** (a re-upgrade sets INACTIVE) |
| 0007 | An execution's decision belongs to its proposal; RESTRICT on the gateway chain | Only the rules (CASCADE comes back) |
| 0008 | Snapshot hash, snapshot immutability, RESTRICT on the recovery chain | **`pre_recovery_snapshot_sha256`** (rebuilt from the kept snapshot on re-upgrade) |
| 0009 | Audit hash chain and verification functions, permanent decisions | **The audit chain columns** (rebuilt on re-upgrade) |

Every upgrade with a data rule first checks existing rows. If a row would break the rule, the upgrade **stops, lists the offending ids and changes nothing**. It never deletes or invents data.

`test_migration_lifecycle.py` proves the following on a fully seeded database:
- every downgrade is the exact inverse of its upgrade (schema fingerprint);
- the seeded database goes from head down to 0001 and back up without losing a row.

---

## 7. Changing the schema

`ownership.md` (section 6): "Other members must submit database schema requirements to M6 rather than directly editing migrations."

1. Open an issue or message for M6 with: the table/column, the reason (doc or GAP reference), the allowed values, who reads and writes it, and the expected volume.
2. M6 writes a **new** migration with the next number (`00NN_<short_name>.py`, `down_revision` = the previous number), the matching model change, and tests: cross-tenant, FK, up/down on fresh and seeded databases, and a break-it proof.
3. Review and merge through a PR. M6 must approve every migration (`ownership.md` rule 6).

**Never edit a merged migration.** `test_migration_governance.py` compares every merged file with `backend/tests/database/migration_manifest.py` and fails on any change.

### Adding a new migration's hash to the manifest (after it is merged)

```powershell
# On a checkout that contains the merged migration:
.venv\Scripts\python.exe -m backend.tests.database.migration_manifest
```

1. The command prints one line per migration file, for example `"0010_example.py": "<sha256>",`.
2. Copy the line of the newly merged migration into `MERGED_MIGRATIONS` in `migration_manifest.py`, in revision order, in the same PR or a follow-up PR.
3. Run `pytest backend/tests/database/test_migration_governance.py`. It must pass.
4. Hashes are taken over the text with normalised line endings, so Windows (CRLF) and Linux checkouts produce the same value.

The governance test also requires a gap-free numbered chain (`0001`, `0002`, …) whose file names match their revisions, and a docstring in every migration.

---

## 8. Least-privilege application role (for M7)

Today the application connects as `amsc`, which is the superuser and owns every table. Such a role can switch triggers off. The intended split, prepared in `backend/app/database/roles.py` and tested with temporary roles:

- **Owner role:** owns the schema and runs `alembic upgrade`.
- **`amsc_app`:** LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS. Grants:
  - DML on application tables;
  - `audit_events`: SELECT and INSERT only;
  - `policy_decisions`: SELECT, INSERT and `UPDATE (execution_status)` only;
  - no `alembic_version`, no TRUNCATE, no ownership.

```python
from backend.app.database.roles import app_role_script
print(app_role_script("amsc_app", owner_role="amsc_owner"))   # review, then run as the owner; set the password separately
```

After provisioning, run `SELECT * FROM amsc_audit_protection_report();`. Every row should be `ok = true`. Applying this to docker-compose, `.env.example` and CI is M7's task (OD-18).

---

## 9. Open questions for other members (summary)

The full list, with what each item blocks, is in the progress log under OPEN-DEPENDENCIES.

- **M1, RBAC (OD-19):** is `memberships.role` the source of truth, and how does it map to `roles` / `role_permissions`? Also: tenant context and the login path for RLS (OD-11), the gateway persistence owner and the idempotency source (OD-10, OD-12), and `MembershipRecord.status` defaulting to `"ACTIVE"` (OD-16).
- **M1 + M4:** decision and status vocabularies and the execution rule (OD-1 … OD-9); should `execution_status` leave `policy_decisions` (OD-25)?
- **M3:** async callers and transaction-scoped memory writes (OD-13); rollback semantics and the checkpoint hash (OD-17); memory-side cascades (OD-24).
- **M7, CI:** there is no CI workflow yet. CI needs PostgreSQL 15+, `TEST_DATABASE_URL`, a test login with `CREATEDB` and `CREATEROLE`, and the role split (OD-18).
- **M7, seed:** the product seed `core/seed.py` does not exist (OD-27). Until it does, `backend/tests/database/seed_fixture.py` (illustrative test data, not decisions) stands in for the lifecycle test.
- **Project owner + M7, branches vs tenants:** TRD section 12.1 seeds ONE company with branches; DOC-006 gate G2 says "3 tenants" (OD-28). Branch-level relationships are designed but waiting (P2 / OD-19).
- **Project owner:** DOC-005 does not describe migrations 0003–0009 yet (OD-20). External anchoring of the audit chain is "Phase 2" (OD-26).
