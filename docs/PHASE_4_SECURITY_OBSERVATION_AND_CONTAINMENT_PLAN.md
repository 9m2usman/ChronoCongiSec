# Phase 4 — Security Observation and Containment

**Status:** Active implementation baseline and gap assessment  
**Authoritative roadmap:** `docs/10-COORDINATED-IMPLEMENTATION-ROADMAP.md`, §4, Phase 4  
**Branch baseline:** `main` at `c18d20ee8d94ba35f4dd383c177a98391985c95e`  
**Implementation owner:** D — Security & Recovery (Phase 4 scope only)  
**Coordination:** A (identity/persistence), B (company services), C (agent runtime), E (frontend/QA)

> This is the current coordinated roadmap's Phase 4: **Security observation and containment**. Older `PHASE_4_*` documents describe a historical ML-intelligence phase. The ML advisory layer is an existing capability to reuse, not the scope to repeat. Full restoration and compensation belong to Phase 5.

## 1. Objective

Detect compromised knowledge and contain harmful activity before it causes further damage. The system must observe the real company and agent workflow, correlate evidence from source to action, quarantine malicious knowledge, revalidate trust and policy before protected mutations, stop active/queued harmful work, and preserve durable forensic evidence.

## 2. Non-negotiable invariants

1. Authenticated server-side identity supplies tenant, branch and actor scope. Never trust caller-supplied tenant/branch/actor/agent ownership fields.
2. Every protected mutation is mediated before side effects. Required identity, trust, policy, persistence, audit and pre-action checkpoint dependencies must be available; otherwise fail closed.
3. Deterministic policy is authoritative. ML outputs are advisory evidence only and can never grant ALLOW or override BLOCK.
4. Quarantine is restrictive and idempotent. Quarantined/untrusted content must not be available through normal retrieval, summaries, agent context or tool execution.
5. Containment must change the real enforcement state. A response object that merely says SUSPENDED/BLOCKED/ISOLATED is not containment.
6. Preserve original events and evidence append-only. Do not delete or rewrite incident history to hide compromised activity.
7. Record enough correlation to follow source → ingestion/version → retrieval → agent/run/span → proposal → decision → execution receipt or block → containment.
8. Do not expose secrets, raw credentials, hidden prompts, private chain-of-thought or unrestricted source contents in telemetry/evidence.
9. Do not implement Phase 5 restoration/compensation in this phase. Phase 4 may create and reference pre-action checkpoints required by the global mutation invariant; Phase 5 owns rewind and compensation.

## 3. Existing capabilities — reuse, do not recreate

Verified on the current `main` source baseline:

- Observation API/repository: `backend/app/api/observation.py`, `backend/app/database/repositories/observation.py`, `ObservationEvent` in `backend/app/database/models/baseline.py`. Existing event fields include tenant/branch, agent/runtime, execution, trace/span, component, memory/version, tool/action, policy decision, receipt, baseline version, outcome, idempotency, payload and timestamp.
- Gateway emits observation events from `backend/app/api/gateway.py`; Phase 1 also documents CrewAI `ExecutionTracer` hooks.
- Detection engine: `backend/app/security/detection.py` supports memory integrity, semantic integrity, behavioral deviation and tool-threat analysis. Detection results have tenant/branch, agent/run/trace/action, evidence, severity, uncertainty and recommended outcome.
- Durable detection model/repository and API: `backend/app/database/models/detection.py`, `backend/app/database/repositories/detection.py`, `backend/app/api/detection.py`.
- ML advisory layer: `backend/app/security/ml_intelligence.py` and `ml/`; preserve `advisory_only` and deterministic PolicyEngine authority.
- Trust/quarantine primitives: `backend/app/security/trust.py`, `backend/app/security/quarantine.py`; normal memory retrieval is intended to remain TRUSTED-only.
- Incident and evidence lifecycle: `backend/app/api/incident_management.py`, `backend/app/security/investigation.py`.
- Containment entry points: `backend/app/security/containment.py`, `backend/app/api/containment.py`.
- Persistent outbox foundation: `backend/app/workers/outbox.py`.

## 4. Confirmed gaps requiring implementation or proof

These are source-level findings, not assumptions:

| Area | Existing evidence | Gap / required work |
|---|---|---|
| Real company event coverage | Generic observation contract exists | Verify and instrument source ingestion/retrieval, file/workspace mutations, transfers, tasks/handoffs, messages and notifications when Phase 2 services land. |
| Real agent event coverage | Gateway hook and CrewAI tracer exist | Coordinate with Phase 3; cover run start/step/completion/failure, memory retrieval, tool proposal, decision, receipt, cancellation and queued job lifecycle. |
| Event authenticity | Observation route derives tenant/branch from TenantContext | Agent/runtime/source fields in request are caller payload. Bind them to authenticated service identity and persisted registry records; reject spoofed or cross-branch references. |
| Provenance | Memory refs, versions, trace IDs and JSON payload exist | Ensure source ID/version, cryptographic content hash, ingestion/retrieval timestamps, actor, run/span and derivation lineage are present and consistently correlated. |
| Detection | Detection engine covers key categories | Prove each ingestion/retrieval/action path invokes the correct checks and stores structured evidence; add missing unsupported-claim/source-grounding coverage without duplicating existing detectors. |
| Incident correlation | Incident/evidence APIs exist | Ensure high-confidence findings create/link incidents idempotently and evidence joins source, memory, run, action, policy decision and receipt. |
| Memory quarantine | QuarantineWorkflow exists | Prove source-level quarantine and all derived/related retrieval paths are immediately excluded; quarantine must use TrustEvaluator, never direct trust writes. |
| Agent suspension | `ContainmentService._suspend_agent` currently constructs a SUSPENDED outcome and persists evidence; it does not update the agent/profile repository. | Implement actual persisted isolation and ensure Gateway/runtime refuses new work for the isolated agent. Use canonical status values and governance APIs. |
| Action blocking | `_block_actions` currently constructs a BLOCKED outcome and persists evidence; no permission/policy enforcement state is changed. | Implement durable enforcement (e.g. revoke or deny the scoped tool/operation through authoritative security profile/permission contracts), with no broad unintended revocation. |
| Resource isolation | `_isolate_resource` currently constructs an ISOLATED outcome and persists evidence; it does not isolate a real resource. | Coordinate with Phase 2 service/resource contracts; implement server-enforced read/write exclusion, not UI-only flags. |
| Active/queued cancellation | Current roadmap requires cancellation; runtime ownership belongs to Phase 3 | Integrate with Phase 3's real run/job cancellation API. Persist requested, acknowledged, completed/failed outcomes; cancellation timeout or unavailable runtime must not be reported as success. |
| Multi-action containment | `apply_containment` processes actions but returns only the first outcome | Define and test complete per-action outcomes and safe partial-failure/reconciliation semantics. Never report the whole batch successful if any action failed. |
| Evidence durability | Some containment paths log audit sink failures and still return an applied outcome | Require durable evidence/audit before reporting success; preserve restrictive state and report reconciliation-required when secondary evidence fails. |
| Pre-mutation checkpoint | Global roadmap invariant requires checkpoint before protected side effects | Integrate a checkpoint reference in the pre-mutation contract. Phase 4 does not implement rewind; Phase 5 consumes these checkpoints. |

## 5. Required implementation work packages

### WP4.1 — Trusted observation and provenance contract
- Publish one versioned event contract for company, source, memory, agent, gateway and containment events.
- Tenant/branch/actor/agent identity must be resolved server-side and verified against persisted membership/agent registry.
- Carry source/resource IDs, source version, SHA-256 content digest, memory IDs/versions, actor principal, agent/runtime, execution/run ID, trace/span, action/proposal ID, policy decision, checkpoint reference, execution receipt, event time and idempotency key as applicable.
- Redact credentials and sensitive values before persistence. Enforce payload size/depth bounds.
- Use existing observation columns and structured payload where appropriate. Coordinate any schema/migration change with A/M6; do not create competing Alembic revisions.

### WP4.2 — Detection orchestration
- Connect source ingestion, retrieval, run steps, tool proposals, messages, tasks, file mutations and gateway outcomes to the existing DetectionEngine.
- Evaluate prompt injection, memory poisoning, provenance/hash integrity, semantic drift, unsupported/ungrounded claims and behavioral anomalies.
- Persist detection result, evidence refs, uncertainty, severity, source/run/action correlation and deterministic policy linkage.
- ML contributes advisory signals only. Critical deterministic dependencies unavailable => protected mutation blocked.

### WP4.3 — Incident and evidence correlation
- Create or attach to incidents idempotently; avoid duplicate incidents for repeated delivery of the same finding.
- Preserve source-to-action lineage and evidence references across the entire lifecycle.
- Evidence records must be append-only, tenant/branch scoped, sanitized and independently auditable.

### WP4.4 — Effective containment
- Memory/source quarantine through TrustEvaluator and trusted-only retrieval enforcement.
- Real agent isolation using persisted agent status/profile and Gateway/runtime enforcement.
- Real action/tool/operation blocking scoped to the affected principal/resource.
- Real resource isolation through Phase 2 service contracts.
- Active run and queued job cancellation through Phase 3 runtime contracts.
- Each action must return an explicit outcome and evidence; partial failures must be visible and retry-safe.
- No fake success, in-memory-only production state or UI-only enforcement.

### WP4.5 — Pre-mutation enforcement and checkpoints
- Revalidate authenticated principal, agent status/profile, source trust, branch/resource authorization and deterministic policy immediately before each protected mutation.
- Create/commit the pre-action checkpoint before the side effect and link it to the action, run, decision and receipt.
- A missing checkpoint or failed persistence prevents execution.
- Do not implement restore/rewind/compensation here.

### WP4.6 — Adversarial integration verification
- Prove malicious source → ingestion detection → retrieval exclusion/quarantine → attempted harmful proposal → deterministic BLOCK → active/queued cancellation → persisted correlated evidence.
- Prove benign workflow remains functional.
- Prove tenant/branch spoofing, forged actor/agent, replay, duplicate events, missing audit/checkpoint, unavailable detector/runtime and partial containment all fail safely.

## 6. Ownership and dependency rules

- D/Phase 4 owns detection orchestration, incident correlation, quarantine/containment semantics and security acceptance.
- A owns identity, database models/migrations, durable audit/outbox and worker infrastructure.
- B owns company APIs/services and their event/checkpoint hooks.
- C owns agent runtime, proposal adapters and active/queued run cancellation.
- E owns security/incident/containment UI and integrated adversarial E2E coverage.
- Do not edit another owner's implementation paths to work around a missing interface. Publish a precise contract request and use an adapter/contract test until the owner supplies it.
- Phase 1/2/3 work may be on separate open branches. Inspect actual branches/PRs and coordinate contracts. Do not assume a branch is merged or a service exists because a plan says it should.
- One shared subsystem = one implementation branch/PR. Do not create competing migrations from the same parent.

## 7. Explicit exclusions

- No reimplementation of the old ML Phase 4; reuse and verify it.
- No full Phase 5 restore/rewind, semantic rollback, external compensation or recovery UI.
- No new parallel policy engine, gateway, incident system, observation store or agent runtime.
- No framework rewrite, second company/tenant demo, real financial side effects, real email sending or external integrations not already approved.
- No direct agent database/filesystem access, trust-state mutation outside TrustEvaluator, caller-selected tenant/branch/actor identity, fabricated telemetry, or tests that pass only because of mocks while production wiring is absent.

## 8. Definition of done / exit gate

Phase 4 is complete only when all are evidenced:

1. All real company and agent workflow stages required by the roadmap emit authenticated, sanitized, idempotent, durable and correlated events.
2. Provenance preserves source identity/version/hash, timestamps, actor, tenant/branch, agent/run/span, memory and action linkage.
3. Prompt injection, poisoning, provenance/hash tampering, semantic drift, unsupported claims and behavior anomalies are evaluated on the appropriate real paths.
4. ML remains advisory; deterministic policy is the only authority for ALLOW/BLOCK/approval.
5. Quarantined sources and their inadmissible derivatives cannot re-enter normal retrieval or justify protected actions.
6. Agent isolation, action blocking and resource isolation change real persisted enforcement state.
7. Active harmful runs and queued work are cancelled through the real runtime; acknowledgement and failure are persisted.
8. Every protected mutation revalidates trust/policy and has a committed pre-action checkpoint before side effects.
9. Incident evidence links source → retrieval → run → proposal → decision → block/receipt → containment without losing original records.
10. Benign workflows still work; tenant/branch isolation and fail-closed behavior are tested.
11. Backend lint, unit, database/migration, security, runtime, frontend contract/build and relevant E2E suites pass.
12. Documentation accurately reports live integrations vs test doubles, changed files, tests, known risks and remaining Phase 5 work.

**Merge readiness:** open PR, clean diff, no unresolved review blockers, GitHub reports mergeable, and every required CI check is green for the exact latest head SHA. Do not merge.
