# ChronoCongiSec — Phase 5 Recovery & Forensic Verification Blueprint

**Implementation branch:** `feat/phase-5-recovery-forensic-verification`  
**Base:** `main` @ `c18d20ee8d94ba35f4dd383c177a98391985c95e`  
**Authoritative scope:** `docs/10-COORDINATED-IMPLEMENTATION-ROADMAP.md`, Phase 5  
**Status:** Source audit and implementation blueprint; application implementation not yet claimed.

> This document follows the current coordinated roadmap. Older Phase 5 readiness notes on `feature/phase-5-enterprise-integration` describe a different phase sequence and must not override the current roadmap.

## 1. Objective and boundaries

Restore reversible company state safely after containment and prove the exact result. Preserve the original incident, contaminated history, and all recovery actions.

Phase 5 owns:
- Recovery planning, snapshots, execution, compensation classification, post-condition verification, and forensic recovery timeline.
- Recovery of file content/version, file ownership and transfers, task assignment/status, supported message state, and memory.
- Stopping related agent runs and queued work before recovery, through the Phase 3 runtime contract.
- Durable, tenant/branch-scoped recovery evidence.

Phase 5 does not own:
- Phase 4 detection, source quarantine, incident creation, or containment implementation.
- Replacing the existing gateway, policy engine, trust evaluator, event store, or worker.
- Frontend work (Phase 6).
- Real payments, external email, or other real-world side effects.
- Deleting or rewriting original business history or forensic evidence.

## 2. Repository baseline and source findings

### 2.1 Current base

- Current `main` is `c18d20ee8d94ba35f4dd383c177a98391985c95e`.
- PR #53 (`feat/phase-2-company-application`) is open and not merged. Its changed files are the company schema migration, company ORM models, model registry, relationship/seed fixtures, and database schema tests. It does not yet provide company application service APIs or restore operations.
- The current Phase 4 branch `feat/phase-4-security-observation-containment` contains the Phase 4 plan. Phase 4 implementation is owned by another contributor; Phase 5 must consume its verified contracts and must not edit its implementation.
- An older branch `feature/phase-5-enterprise-integration` contains a readiness note that predates the current coordinated roadmap. It is not the implementation branch and will not be reused.

### 2.2 Existing recovery foundation on main

Verified source paths:
- `backend/app/recovery/orchestrator.py`: `RecoveryService` supports preview/execute for memory checkpoint recovery, role checks, blast-radius calculation, fingerprint/stale-plan detection, snapshot-first execution, trust quarantine, append-new-version restore, UNVERIFIED trust reset, and post-condition checks.
- `backend/app/recovery/store.py`: SQL adapters exist for memory checkpoints, recovery plans, external tool actions, and a factory for a database-backed memory recovery service.
- `backend/app/database/rewind.py`: `RewindCoordinator` commits a pre-recovery snapshot in one transaction, then performs rollback operations in a second transaction with row locking, append-version, compare-and-set current-version, and action recording.
- `backend/app/database/models/recovery.py`: current checkpoint items reference memory records/versions; recovery plans reference the current memory checkpoint model.
- `backend/app/api/recovery.py`: preview, execute, and plan-read routes exist. The API's current response vocabulary is memory-recovery oriented.
- `backend/app/main.py`: the recovery router is registered and a SQL/in-memory recovery service is constructed in the application lifespan according to configured persistence.

Important limitation: these components do not yet implement the roadmap's company-resource recovery. The checkpoint reader joins `CheckpointItem` to `MemoryVersion`; `RecoveryTransaction` exposes memory-specific checkpoint/version operations. The current `RecoveryPlan` schema is also tied to the memory checkpoint table. Existing memory recovery must be preserved, not replaced.

### 2.3 Company application dependency

PR #53 currently proposes these company records:
- `CompanyFile` and `CompanyFileVersion`: current owner/status/version and immutable content versions with checksums.
- `CompanyFileTransfer`: sender, recipient, and PENDING/ACCEPTED/REJECTED/CANCELLED state.
- `CompanyTask` and `CompanyTaskEvent`: current status/assignee plus task history.
- `CompanyMessage`: sender, recipient, body, SENT/READ status and read timestamp.
- `CompanyWorkspace`, `CompanyNotification`, and `CompanyActivity`.

The PR currently provides schema only. No company application service contract is present in its changed-file list. Do not implement a second company application or bypass the eventual service layer. Company recovery adapters must integrate with the merged Phase 2 service/repository contract.

### 2.4 Runtime dependency

Phase 5 must cancel related active runs and queued actions before restoring state. The current main-branch Phase 3 cancellation contract and durable job semantics must be inspected and verified before wiring. Never infer cancellation success from a request being sent.

## 3. Required recovery model

Use one recovery lifecycle and one forensic correlation chain. Preserve the existing memory recovery API and its security semantics. Extend through typed resource adapters rather than arbitrary ORM mutation.

Proposed logical records (final physical schema must be coordinated with the database owner and current migration head):
- **Recovery plan:** tenant, incident, creator, reason, requested scope, preview fingerprint, state, idempotency key, and timestamps.
- **Recovery snapshot/bundle:** immutable pre-recovery state and integrity digest, captured before the first mutation.
- **Snapshot item:** resource type, resource ID, branch, prior version/state, content/state checksum, typed snapshot payload or immutable version reference, and source checkpoint reference.
- **Recovery action:** append-only action record with before/after references, action type, outcome, actor, idempotency key, and error classification.
- **Verification result:** checks performed, expected/actual version and checksum, outcome, and evidence references.

Do not create a parallel incident or audit store. Prefer extending the existing recovery-plan/action and audit/event infrastructure. The database migration owner must approve the exact schema and revision parent before any migration is created.

## 4. Recovery lifecycle

1. **Authorize:** accept only a verified `TenantContext`; `SECURITY_ANALYST` or `TENANT_ADMIN` may preview/execute. Derive tenant, branch and actor from authenticated server context. Cross-tenant IDs must be indistinguishable from missing resources.
2. **Resolve scope:** derive affected resources from the incident, its evidence, Phase 4 checkpoints and correlated action receipts. Validate every resource belongs to the same tenant and permitted branch. Do not trust a client-supplied arbitrary restore list.
3. **Stop execution:** request cancellation of related active runs, queued jobs and pending protected actions. Require durable acknowledgement/completion according to the runtime contract. If the runtime cannot prove work has stopped, do not begin restore.
4. **Preview:** verify checkpoint/snapshot integrity, current versions, current hashes, resource ownership and authorization. Compute blast radius and immutable preview fingerprint. Refuse incomplete or oversized scope; never silently truncate.
5. **Capture pre-recovery state:** persist the immutable snapshot and its digest in a committed transaction before any restore mutation. A retry must reuse the same committed snapshot.
6. **Contain:** confirm affected memory/source and agents remain restricted through Phase 4's authoritative trust/containment services. Do not weaken quarantine or agent isolation during recovery.
7. **Execute:** acquire durable plan/resource locks; revalidate the preview fingerprint and expected resource versions; execute supported restore/compensation operations in bounded transactions. Use compare-and-set/version checks to prevent overwriting concurrent legitimate changes.
8. **Record:** append each recovery action and evidence reference. Preserve all original versions, transfer records, task events, messages, incident evidence, and prior action receipts.
9. **Verify:** read the resulting state back from persistence and compare it with the intended recovery target. Verify checksums, versions, ownership, task state, trust state, cancellation status and evidence continuity.
10. **Finalize:** mark recovery complete only after all required post-conditions and audit persistence succeed. A committed restore with failed verification/audit becomes `RECONCILIATION_REQUIRED`, never success.

## 5. Domain recovery semantics

### 5.1 Files and file versions
- Restore content by appending a new `CompanyFileVersion`; never delete or overwrite prior versions and never decrement the version number.
- Update `CompanyFile.current_version` using a row lock or compare-and-set against the previewed version.
- Verify the new version checksum and the file's tenant/workspace/branch authorization.
- Preserve the contaminated version and link the new version to the recovery plan and original checkpoint in recovery evidence.
- Restore a deleted file only through the authorized company service, with a new activity/history record.

### 5.2 Ownership and transfers
- Preserve the original transfer record and its status.
- If ownership must return to a prior owner, use an explicit compensating transfer/ownership operation through the company service. Do not rewrite the original sender/recipient or accepted timestamp.
- Record previous owner, current owner, compensating operation, actor, incident, and verification result.
- If the service cannot prove the previous owner was authorized and belongs to the tenant, refuse the restore.

### 5.3 Tasks
- Restore supported assignment/status fields to the checkpointed values using the company service and optimistic concurrency.
- Append a new `CompanyTaskEvent` describing the recovery; never delete or edit earlier task events.
- Preserve task creator, branch, workspace and unrelated fields.
- Verify the persisted assignee/status after the transaction.

### 5.4 Messages and notifications
- Message bodies and sent-message history are not reversible. Never delete, edit, unsend, or fabricate a prior read state.
- A sent message is classified as an irreversible internal action; record it in the forensic timeline and require an explicit human response where policy demands it.
- Do not reset `READ` to `SENT` to make recovery appear complete. Any reversible notification metadata must be separately justified by the final Phase 2 contract and must retain an audit record.

### 5.5 Memory and knowledge
- Reuse the existing `RecoveryService`, `TrustEvaluator`, checkpoint integrity rules and `RewindCoordinator`.
- Restore by appending a new memory version; never move version counters backwards or delete contaminated versions.
- A restored memory record must become `UNVERIFIED`, never `TRUSTED`. Intermediary/tainted derived records remain quarantined.
- Verify content checksum, new version pointer, effective trust state, and preserved provenance.
- Do not weaken the existing memory recovery path to accommodate company recovery.

### 5.6 Agent runs and tool actions
- Stop related active runs, queued jobs and pending protected actions before state restoration.
- Prevent cancelled jobs from being restarted by automatic retry.
- Preserve run IDs, trace/span IDs, proposals, gateway decisions, execution receipts and cancellation outcomes.
- Classify actions as reversible, compensatable, or irreversible. Only invoke registered simulated/internal compensation adapters. No real external side effects.
- If an action is irreversible or its history is unavailable, record that fact; do not claim it was undone.

## 6. Forensic timeline and evidence

The final timeline must correlate:
`Incident → Source/Memory → Checkpoint → Resource Version/State → Agent Run → Proposal/Decision → Execution Receipt → Containment/Cancellation → Recovery Plan → Snapshot → Recovery Action → Verification`.

Every record must be tenant-scoped and include, where applicable:
- authenticated actor and role;
- tenant and branch;
- incident, plan, checkpoint and resource identifiers;
- resource type and before/after version;
- integrity hashes and verification result;
- run/job/trace/action/proposal/decision/receipt identifiers;
- timestamps and idempotency key;
- compensation/irreversibility classification;
- failure/reconciliation reason.

Do not persist secrets, credentials, private prompts, hidden chain-of-thought, or unrestricted message/file contents in telemetry. Snapshot payloads must be access-controlled, bounded, encrypted at rest by the platform's supported storage, and excluded from ordinary user-facing logs.

Original incident evidence is immutable. Recovery evidence is appended and linked; it never replaces the original.

## 7. Failure, concurrency and retry rules

- At-least-once outbox delivery; recovery handlers must be idempotent.
- One active recovery per plan and no overlapping restores for the same resource without explicit safe serialization.
- Use database locks and optimistic version checks; process-local locks alone are insufficient.
- Duplicate request with same idempotency key and same body returns the recorded outcome; same key with changed body is rejected.
- Snapshot failure means no mutation.
- Cancellation failure/timeout means no mutation.
- Checkpoint corruption or cross-tenant references mean no mutation.
- Any restore transaction failure rolls back that transaction; the committed pre-recovery snapshot remains.
- A failure after a committed restore must preserve restrictive state and report reconciliation required.
- Retry must not append duplicate versions, duplicate transfer actions, or duplicate task events.
- Audit/evidence persistence failure must never be swallowed or reported as success.

## 8. Implementation sequence and ownership gates

1. **P5-A — Contract audit:** verify merged Phase 2 services, Phase 3 cancellation/action receipts, Phase 4 checkpoints/containment, and existing SQL recovery wiring.
2. **P5-B — Recovery data contract:** agree typed snapshot/item/action schema and migration parent with database owner. Preserve existing memory tables/API.
3. **P5-C — Recovery orchestration:** implement preview, fingerprint, durable locks, cancellation gate, idempotency and state transitions.
4. **P5-D — Domain adapters:** file version/content; ownership/transfer compensation; task assignment/status; message irreversibility; memory integration.
5. **P5-E — Forensic verification:** append-only evidence and timeline; actual persisted post-condition checks.
6. **P5-F — Reliability:** retries, crash recovery, partial failure, concurrency and transaction boundaries.
7. **P5-G — Acceptance:** PostgreSQL-backed end-to-end malicious mutation → containment → cancellation → recovery → verification, plus benign regression.

Ownership boundaries:
- Phase 4 contributor owns Phase 4 detection/containment files. Do not edit them.
- Phase 2 contributor owns company application service contracts. Consume them; do not duplicate them.
- Phase 3 contributor owns agent runtime/cancellation contracts. Integrate through the agreed interface.
- Database owner controls Alembic revision sequencing and shared schema.
- Phase 5 owns recovery orchestration/adapters/evidence integration and Phase 5 tests.

If a dependency is absent, implement only independent work and record a precise integration blocker. Never fabricate an adapter or mark a live integration complete because a mock passed.

## 9. Required verification

### Unit and contract
- role/tenant/branch authorization and cross-tenant indistinguishability;
- checkpoint integrity, stale fingerprint and blast-radius completeness;
- resource adapter contract and state transition validation;
- idempotency, retry and duplicate delivery;
- cancellation acknowledgement and retry suppression;
- reversible/compensatable/irreversible classification;
- no TRUSTED state after memory restore;
- append-only evidence and honest reconciliation outcomes.

### PostgreSQL integration
- migration upgrade/downgrade and constraints;
- real snapshot commit before mutation;
- real row locking and concurrent update conflict;
- append-only version/history behavior;
- rollback on injected failure;
- recovery retry after worker/process interruption;
- tenant/branch composite scoping;
- durable action/evidence/timeline persistence.

### End-to-end acceptance
1. Create a company file/task and a memory record with known trusted baseline.
2. Capture a checkpoint and record hashes.
3. Perform a protected mutation through the gateway and persist its receipt.
4. Trigger the Phase 4 incident/containment path.
5. Cancel related active and queued agent work and prove it cannot restart.
6. Preview and execute recovery with an authorized analyst.
7. Restore file content as a new version, restore ownership/transfer or task state through service operations, restore memory as a new UNVERIFIED version, and classify sent messages honestly.
8. Read all state back from PostgreSQL and verify hashes, tenant/branch scope, event history, action receipts and incident evidence.
9. Repeat the same recovery request and prove there are no duplicate side effects.
10. Run a benign company/agent workflow and prove recovery did not break normal authorized work.

Mocks may support unit tests but cannot be the only proof of database or runtime integration.

## 10. Exit criteria

Phase 5 is complete only when:
- all roadmap resource types are either recovered or explicitly classified as irreversible with a recorded human-response requirement;
- related agent work is demonstrably stopped before restore;
- all restore operations are authorized, tenant/branch scoped, version-safe and idempotent;
- snapshots are committed before mutation and integrity-verified;
- original history and evidence remain intact;
- post-recovery verification reads actual persisted state;
- failure and reconciliation outcomes are honest and retry-safe;
- PostgreSQL integration and adversarial tests pass;
- latest PR-head CI is green and GitHub reports mergeable;
- unresolved dependencies are clearly identified.

No frontend Phase 6 work is included. Do not merge the Phase 5 PR.
