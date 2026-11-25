# ChronoCongiSec — Coordinated Implementation Roadmap

**Status:** Proposed execution baseline  
**Repository baseline:** `feat/enterprise-connectivity-and-db-fixes`  
**Baseline commit:** `de8b1e7a28a72834e4efdea4985d26bf9a8e3fb6`  
**Roadmap branch:** `docs/implementation-roadmap-team-workstreams`  
**Product scope:** One simulated company with Head Office, Lahore, Karachi and Islamabad branches; tenant isolation remains in the architecture for future customers and automated isolation tests.

> This roadmap is based on the source-level audit of the baseline commit and the product requirements confirmed by the project owner. Source code and executable tests take precedence over older audit/progress documents. Several existing documents describe different historical commits or contain findings that no longer match the audited source; those documents must not be treated as current implementation truth without re-verification.

---

## 1. Product boundary and non-negotiable requirements

ChronoCongiSec is the security/governance control plane. The Simulated Company Application is where employees and agents perform actual company work. They are connected through authorized, scoped service interfaces; they are not one UI with fake dashboard cards.

### Simulated Company Application

- One demo company, with four branches: Head Office, Lahore, Karachi and Islamabad.
- Employee accounts are persisted. Registration requires Tenant Admin approval and assignment of an approved role and branch.
- Roles: `TENANT_ADMIN`, `SECURITY_ANALYST`, `AI_DEVELOPER`, `AUDITOR`.
- Separate employee accounts, workspaces and visibility boundaries.
- Persisted file create/read/edit/organize/transfer/delete operations, ownership and version history.
- Persisted tasks, assignments, handoffs and status changes.
- Internal company inbox and messaging, including delivery/seen state where appropriate.
- Real-time or near-real-time notifications and activity updates.
- Multiple simultaneous employee sessions must be able to observe transfers and state changes.
- Agents use company application services; they do not get arbitrary filesystem or direct database mutation access.

### ChronoCongiSec Security Center

- Authorized discovery and observation of company agents, tools, policies, permissions, workflows, knowledge and relevant events.
- Observe runs, memory retrieval, tool calls, messages, tasks, file/workspace changes and protected mutations.
- Detect malicious/poisoned instructions, indirect prompt injection, unsupported claims, stale or drifting knowledge and anomalous behavior.
- Deterministic gateway decisions: `ALLOW`, `BLOCK`, `QUARANTINE`, or `REVIEW/APPROVAL`. ML is advisory; deterministic policy is authoritative.
- Every protected mutation is mediated before side effects and produces a pre-action checkpoint, decision record and action receipt.
- Quarantine affected sources, block future harmful operations, cancel active harmful runs and queued work, and preserve forensic evidence.
- Restore reversible file versions, ownership/transfers, task assignments and memory. Irreversible external actions require explicit compensating workflows.
- Financial operations are simulated only. Never move real funds.
- ML lifecycle must use real datasets, training/evaluation evidence, model versions, approval, promotion and rollback. Never represent synthetic fixtures or unexecuted training as production results.
- Gmail/Google OAuth is optional future integration. Implement internal company messaging first.

### Engineering invariants

1. Tenant and branch context comes from authenticated, persisted membership—not a caller-controlled tenant selector.
2. Fail closed when identity, authorization, trust, policy, profile, checkpoint or required persistence is unavailable.
3. No protected side effect occurs before gateway approval and checkpoint creation.
4. No fixture, test double or synthetic response is presented as live company activity.
5. Every state-changing action is attributable to a human or scoped agent identity and is auditable.
6. Keep the existing security platform capabilities; extend and integrate them rather than replacing them with a new parallel implementation.
7. Do not merge a phase solely because code exists. It must pass its stated tests and review.

---

## 2. Repository baseline and audit caveats

The working baseline is commit `de8b1e7a28a72834e4efdea4985d26bf9a8e3fb6` on `feat/enterprise-connectivity-and-db-fixes`. The local working tree was reported clean.

The source audit found useful existing foundations: authentication and membership models, migrations, branch abstractions, agent registry, deterministic gateway/policy checks, memory trust/provenance, incident/quarantine primitives, checkpoint/recovery primitives, enterprise discovery connectors, frontend security workstation pages and classical ML implementations.

The repository is not yet the complete connected-company product. Important gaps include:

- No complete persisted employee company application for workspaces, files, file versions/transfers, inbox/messages, tasks and live activity.
- Agent runtime is primarily a CLI/test-double demonstration and is not connected to persisted company workflows.
- Agent security profiles, branch scoping and agent identity wiring are incomplete/inconsistent.
- Production trust-decision persistence and runtime wiring require correction and restart verification.
- Redis rate limiting and background/outbox worker startup/handlers are not reliably wired.
- The gateway currently has a limited adapter set and does not mediate all future company mutations.
- Recovery is mainly memory-oriented; company file/task/workspace recovery is not implemented.
- Frontend fixtures can mask unavailable or failing live APIs.
- Existing ML code is real, but evaluation data is small/synthetic and the full dataset/retraining/approval/promotion lifecycle is incomplete.

**Audit caution:** Historical documents in `docs/` include reports from different commits. For example, `docs/PHASE_0_REPOSITORY_REALITY_AUDIT.md` records a different branch/commit and makes claims that conflict with current source (including historical ML and persistence statements). It must be labelled historical or superseded after the current audit is added to the main documentation baseline. Do not copy its findings into implementation tickets without checking current code.

Local runtime, live PostgreSQL/Redis behavior and the full browser experience still require verification on a developer machine/CI. GitHub source access does not grant access to the project owner's localhost or local filesystem.

---

## 3. Team workstreams and ownership

Use these as role slots until the project owner supplies actual teammate names, GitHub usernames and strengths.

| Workstream | Suggested owner | Owns | Must coordinate with |
|---|---|---|---|
| A — Identity & infrastructure | Teammate A | PostgreSQL persistence, IAM, tenant/branch scoping, agent profiles, Redis, durable trust store, outbox/worker runtime | Project owner, B, C |
| B — Company application | Teammate B | Employee workspace, files/versions/transfers, tasks/handoffs, internal inbox/messages, activity/notifications | A for identity/schema; C for agent-facing service contracts; D for audit/checkpoints |
| C — Agent integration | Teammate C | Scoped agent/service identities, persistent agent runtime, company service clients, gateway-mediated agent actions, run lifecycle/cancellation | A for identity; B for service APIs; D for security events |
| D — Security & recovery | Teammate D | Observation contracts, detection, quarantine, active/queued cancellation, checkpoints, restore/compensation and forensic evidence | A for durable records; B/C for event and mutation contracts |
| E — Frontend & integration QA | Teammate E | Employee/security UI integration, live status, contract tests, end-to-end test harness and release evidence | All workstreams |
| Integration owner | Project owner (Usman) | Architecture decisions, API/schema contracts, branch protection/review, integration sequencing, acceptance and release | All |

If the team is smaller, combine E with the integration owner and combine D's implementation with C only after the contracts are agreed. Do not combine independent security review with implementation approval: a different teammate should review high-risk gateway, authorization and recovery changes.

### Parallel-work rules

- One workstream = one feature branch and one PR at a time per shared subsystem.
- Before coding, each owner posts: objective, exact owned paths, API/schema contract, migration impact, dependencies, tests and expected evidence.
- Never create competing Alembic revisions from the same parent. A owns migration sequencing; other owners submit schema requirements before migration creation.
- Shared contracts are reviewed and frozen before B/C/D implement against them.
- No direct commits to the integration branch by parallel contributors. Use PRs.
- No force pushes, resets or history rewrites on shared branches.
- PRs must include tests, migration notes, screenshots/logs where relevant, and a clear live-vs-test-double statement.
- If a PR changes a shared contract, update its consumer tests and notify affected workstreams before merge.
- The integration owner merges only after CI, review and acceptance checks pass.

---

## 4. Phase roadmap and acceptance gates

### Phase 0 — Repository reality baseline

**Status:** Source-level audit complete for the baseline commit; local runtime verification remains outstanding.

Deliverables:
- Confirmed branch, commit and clean working tree.
- Source audit distinguishing implemented, partial, missing and not runtime-verified behavior.
- Historical documentation caveats recorded.
- Agreed product scope and workstream ownership.

Exit gate:
- Team agrees on this roadmap and current baseline.
- No implementation begins from stale audit assumptions.

### Phase 1 — Persistent identity and runtime foundation

**Objective:** Make PostgreSQL and authenticated identity the dependable source of truth before adding employee workflows.

Scope:
1. Trace the actual startup/dependency wiring and repository selection in development, test and production. Document which services are DB-backed vs in-memory before changing them.
2. Make the one demo company and four branches the product-facing seed/onboarding experience. Preserve tenant isolation and test-only tenant fixtures without exposing a multi-company demo switcher.
3. Ensure registration approval persists the employee, approved role, tenant and branch. Enforce the four canonical roles.
4. Derive tenant and branch authorization exclusively from authenticated membership. Fix branch discovery/listing and tenant alias/context mismatches.
5. Persist agent security profiles, branch assignments and tool grants. Ensure agent repository filtering actually enforces branch scope.
6. Reconcile seeded agent tenant identifiers with runtime configuration; remove shared human credentials from machine-agent execution and define scoped service principals.
7. Make trust-decision history durable, awaited, queryable after process restart and shared by the gateway/evaluator. Persistence errors must not be swallowed.
8. Wire Redis rate limiting into supported runtime modes with explicit health/failure behavior.
9. Start a persistent worker process for the transactional outbox; register real handlers, retries and dead-letter/error behavior. An event without a handler must not be marked successfully published.
10. Remove any production path where fixtures or test doubles masquerade as live employee/company state.

Workstream allocation:
- A leads IAM, persistence, trust, Redis and worker wiring.
- C contributes agent principal/profile requirements and validates agent registration/runtime.
- D reviews fail-closed security, trust durability and audit behavior.
- E adds API contract and regression tests for auth/tenant/branch behavior.
- B supplies the minimal identity/branch contract it needs but does not start company-domain schema until A's contracts are agreed.

Exit gate:
- Employee registration and Tenant Admin approval persist to PostgreSQL.
- Approval assigns a valid role and branch; login works after backend restart.
- Two employee accounts cannot read or mutate each other's protected data.
- Branch-scoped authorization is enforced by backend queries, not just UI filtering.
- Agents have persisted profiles, branch scope, least-privilege grants and dedicated identity.
- Trust history survives restart and gateway uses the same durable source.
- Redis behavior is explicit and tested.
- Worker consumes registered events with retry/failure semantics; unhandled events are not silently discarded.
- Tests prove live mode cannot fall back to synthetic company activity.

### Phase 2 — Simulated company application

**Objective:** Build the real persisted business environment employees and agents operate in.

Scope:
1. Employee profile and workspace boundaries.
2. File records and safe storage abstraction; metadata, ownership, branch scope and version history.
3. File create/read/edit/organize/delete/restore operations.
4. File transfer with sender/receiver permissions, transfer state, ownership history, notification and audit receipt.
5. Internal inbox and employee-to-employee messaging; delivery/read state as appropriate.
6. Tasks, assignments, handoffs, status transitions and history.
7. Activity feed and notification delivery; use the worker/outbox and a supported real-time transport (SSE/WebSocket) where it materially improves live collaboration.
8. Simultaneous-session tests using two separate employee identities.
9. All mutations exposed through application services with authorization hooks that Phase 3/4 can mediate. Do not expose arbitrary filesystem paths or direct DB writes to agents.

Workstream allocation:
- B leads company domain, service layer and APIs.
- A reviews schema, tenant/branch composite constraints and migration order.
- D defines event/checkpoint/audit hooks before mutation APIs are finalized.
- C reviews agent-consumable service contracts.
- E leads employee workspace UI and two-user integration tests.

Exit gate:
- Two employees can sign in separately, create and edit files, transfer a file, receive a message/notification, hand off a task and see the persisted result from separate sessions.
- Ownership, versions, assignment and message state survive restart.
- Cross-tenant and cross-branch unauthorized operations are rejected.
- Every mutation has an actor, authorization result and auditable receipt.

### Phase 3 — Connected AI agent execution

**Objective:** Replace synthetic CLI-only business demonstrations with persistent agents performing real work through approved company services.

Scope:
1. Persistent agent runtime/job lifecycle with run IDs, status, heartbeat, timeout and cancellation.
2. Dedicated scoped service principal per agent (or equivalent least-privilege identity).
3. Agent registration, branch assignment, security profile and tool grants are persisted and validated.
4. Agents read and mutate company resources only through application service contracts.
5. Every protected mutation is submitted to the gateway before side effects.
6. Record run context, memory retrieval, tool call, gateway decision, checkpoint reference and action receipt.
7. Queue-based execution and safe retry/idempotency.
8. Explicit distinction between live execution, test double and simulated external integrations.
9. No hardcoded policy fallback presented as retrieved company knowledge.

Workstream allocation:
- C leads runtime, agent identities and tool integration.
- B supplies stable company service interfaces.
- A supports durable job/agent records and worker infrastructure.
- D specifies gateway, observation and checkpoint integration.
- E adds run lifecycle views and integration tests.

Exit gate:
- An agent completes a real persisted company task and file operation through authorized services.
- A denied action causes no side effect.
- Run state and receipts survive service restart.
- Active runs can be cancelled and queued work can be stopped.
- Agent access is branch/tenant scoped and least privilege.

### Phase 4 — Security observation and containment

**Objective:** Detect compromised knowledge and contain harmful activity before it causes additional damage.

Scope:
1. Instrument company and agent services for source ingestion, retrieval, run steps, tool proposals, messages, tasks, file mutations and gateway outcomes.
2. Preserve provenance, source identity, content hashes, timestamps and actor/run correlation.
3. Evaluate prompt injection, poisoning, semantic drift, unsupported claims and behavior anomalies.
4. Keep ML advisory; deterministic policy remains authoritative.
5. Quarantine a malicious source and prevent future retrieval/use according to policy.
6. Revalidate trust/policy immediately before each protected mutation.
7. Cancel active harmful runs and queued jobs when an incident requires it.
8. Preserve immutable/append-only incident evidence and complete correlation across source, memory, run, tool call and action.

Workstream allocation:
- D leads detection, quarantine and containment.
- C adds agent runtime instrumentation and cancellation.
- B adds company event hooks and mutation correlation.
- A ensures durable event, trust and audit persistence.
- E builds incident/containment views and adversarial tests.

Exit gate:
- A poisoned source is detected/quarantined.
- The agent cannot perform the prohibited operation.
- Active harmful execution and queued work are stopped.
- Evidence identifies source, run, decision and blocked action.
- Benign workflows continue and no synthetic result is shown as live.

### Phase 5 — Recovery and forensic verification

**Objective:** Restore reversible company state safely and prove the exact outcome.

Scope:
1. Create pre-action snapshots/checkpoints before protected mutations.
2. Link snapshots to file versions, ownership, transfers, tasks, messages, memory, agent run and action receipts as applicable.
3. Implement recovery for file version/content, ownership/transfer state, task assignment/status and memory.
4. Verify integrity and authorization before restore; restore by creating new history, never silently erasing forensic evidence.
5. Stop/cancel related runs and queued actions before recovery.
6. Define compensating workflows for irreversible actions; explicitly record what cannot be undone.
7. Produce a correlated forensic timeline with before/after state and verification results.
8. Test partial failure, duplicate request, concurrent update and recovery interruption.

Workstream allocation:
- D leads recovery orchestration and forensic evidence.
- B supplies domain restore operations for files/tasks/messages.
- C supplies run cancellation and action receipts.
- A ensures transactionality, durable checkpoints and worker safety.
- E leads recovery UI and end-to-end proof.

Exit gate:
- A completed reversible malicious mutation is restored to the verified prior business state.
- New recovery history and original incident evidence remain intact.
- Irreversible actions are described accurately with compensating action status.
- Recovery failure is safe, visible and retryable without duplicate side effects.

### Phase 6 — Frontend, integration and final demonstration

**Objective:** Deliver a coherent employee application and security center, then prove the full scenario.

Scope:
1. Separate employee and security workspaces with role-based navigation and backend-enforced authorization.
2. One company/four branches in product-facing UI; no three-demo-tenant switcher.
3. Clear live, simulated, test-double and unavailable states.
4. Remove misleading fixture fallback in live mode; fixtures are permitted only in explicit demo/test mode.
5. Employee file/task/inbox experiences and live notifications.
6. Security dashboards for agents, memory, gateway, incidents, audit, containment and recovery.
7. End-to-end scenario automation with seeded, reproducible test data.
8. Accessibility, error states, loading states, responsive behavior and security review.
9. CI, deployment/runbook, migration/seed procedure, backup/recovery guidance and demo script.

Workstream allocation:
- E leads UI integration and E2E QA.
- B owns employee application experience.
- D owns security workflow acceptance.
- C owns agent run experience.
- A owns deployment, runtime and migration reliability.
- Project owner coordinates release and final acceptance.

Exit gate:
- The full poisoning → detection → quarantine → block/cancel → restore → forensic verification scenario passes against persisted services.
- Two employee sessions visibly demonstrate company workflow changes.
- Security roles can investigate without exceeding their permissions.
- CI and documented clean-start deployment pass.
- Demo contains no false claims about live integrations, ML training or irreversible recovery.

---

## 5. Phase 1 implementation blueprint (first execution batch)

Phase 1 is the next implementation phase. Do not start Phase 2 domain features until Phase 1 exits.

### Work packages

**P1-A — Runtime and persistence map**
- Trace application startup, environment modes, dependency injection and repository selection.
- Map each critical service to its actual repository/store.
- Identify current migrations, ORM models, seed code and tests affected.
- Output a short verified wiring map and exact change list before coding.

**P1-B — Employee identity and branch authorization**
- Registration request → Tenant Admin approval → persisted membership/role/branch → login/session.
- Canonical tenant context from authenticated membership.
- Branch list and all protected queries must be tenant/branch scoped.
- Keep registration discovery narrowly scoped and avoid exposing arbitrary tenant data.

**P1-C — Agent identity and security profiles**
- Dedicated service principal/credentials, persisted profile, branch scope and tool grants.
- Correct ORM/repository branch filtering.
- Ensure registration/seed flows create valid profiles.
- Reconcile tenant slug and runtime configuration.

**P1-D — Durable trust and gateway wiring**
- Make trust-decision append awaitable and durable.
- Query persisted decisions after restart.
- Share one correctly wired evaluator/store with gateway and retrieval.
- Fail closed on persistence failure; no swallowed errors or process-local-only reads in production.

**P1-E — Redis and worker lifecycle**
- Add/verify Redis client dependency and lifecycle management.
- Attach rate limiter in the intended runtime modes.
- Start a persistent worker process and register handlers.
- Retry transient failures, retain terminal failures/dead letters, and never mark an event published without successful handler execution.
- Graceful shutdown and health checks.

**P1-F — Regression and acceptance**
- PostgreSQL integration tests and migration upgrade tests.
- Two-user tenant/branch isolation tests.
- Agent profile/branch/tool permission tests.
- Trust persistence restart test.
- Redis startup/health/rate-limit tests.
- Outbox handler/retry/unhandled-event tests.
- Live-mode fixture/test-double guard tests.

### Phase 1 file ownership

Exact paths must be confirmed from the current source before work begins. Likely ownership boundaries:

- A owns `backend/app/database/**`, `backend/alembic/**`, `backend/app/core/**` runtime wiring, `backend/app/workers/**`, seed/runtime configuration and relevant database tests.
- B does not modify company domain models in Phase 1; it submits requirements and reviews identity contracts.
- C owns agent service identity/runtime integration paths and agent-specific tests, coordinated with A before shared ORM/migration edits.
- D owns security review and tests for trust/gateway fail-closed semantics; changes to shared trust persistence are coordinated with A.
- E owns frontend contract tests/status behavior and does not create new employee product screens until Phase 2.

Do not treat the path suggestions as permission to modify every listed file. First inspect the current dependency graph and agree the smallest coherent file set.

### Phase 1 completion report

The phase is complete only when the exit criteria in Section 4 pass. Produce:
- merged PR links and commit SHAs,
- migration revision and upgrade evidence,
- test commands and exact results,
- runtime restart evidence,
- isolation and fail-closed test evidence,
- unresolved risks and explicit next-phase prerequisites.

Then conduct a phase review before Phase 2: architecture reasoning, authorization boundaries, failure handling, persistence semantics, worker behavior and security trade-offs.

---

## 6. Prompt protocol for teammates and implementation agents

Every phase prompt must be generated from this roadmap and the latest merged code—not copied blindly from an older prompt.

Each prompt must include:
1. Product invariants and relevant current phase objective.
2. Exact branch/base commit and instruction to inspect current source first.
3. Owned workstream and allowed file paths.
4. Explicit paths/files that must not be changed.
5. API, schema, migration and event contracts.
6. Required implementation and prohibited shortcuts.
7. Tests to add/run and acceptance criteria.
8. Required PR description, evidence and handoff notes.
9. Instruction to stop and report blockers rather than invent missing contracts.

**Efficiency rule:** Issue only the current phase's prompts when that phase is ready. Later-phase prompts are derived after earlier contracts are merged, preventing wasted work against unstable APIs.

### Reusable teammate prompt

You are implementing one assigned ChronoCongiSec workstream. Read the current roadmap and inspect the actual repository at the supplied base commit before changing anything. Treat source code and executable tests as truth; identify stale documentation rather than following it blindly. Work only in the assigned paths. Do not reset, force-push, rewrite shared history, create a competing Alembic migration, invent an API contract, or replace existing subsystems without evidence. Coordinate shared contracts before coding. Implement complete, integrated changes with tests. Never use fixtures/test doubles as live data, bypass the gateway, permit direct arbitrary filesystem/database access by agents, or claim unexecuted tests passed. Open a focused PR with changed paths, design decisions, migrations, test commands/results, security impact, known limitations and handoff notes. If a dependency or shared contract is missing, stop and report the exact blocker and proposed contract instead of building an incompatible workaround.

---

## 7. Integration and release workflow

1. Project owner confirms the team roster and workstream owners.
2. Phase lead posts a short contract proposal and exact file ownership.
3. Integration owner approves the contract and branch base.
4. Contributors work independently and open focused PRs.
5. CI runs; a different teammate reviews security-sensitive changes.
6. Integration owner verifies compatibility and merges.
7. Update the phase ledger with commit, tests, evidence and remaining risks.
8. Run the phase acceptance gate.
9. Conduct the phase review before authorizing the next phase.

Use a single integration branch as the merge target. Feature branches should be short-lived and based on the latest approved integration commit. Avoid parallel changes to shared migration history and shared API contracts.

---

## 8. Current decision and immediate next action

- Phase 0 source audit: complete for the recorded baseline.
- Current execution phase: **Phase 1 — Persistent identity and runtime foundation**.
- First action: verify team roster and assign A–E; then run P1-A runtime/persistence mapping against the current source and lock Phase 1 file/API/migration ownership.
- No Phase 1 implementation has been claimed by this roadmap document.
- Do not begin Phase 2 until Phase 1 acceptance is demonstrated.
