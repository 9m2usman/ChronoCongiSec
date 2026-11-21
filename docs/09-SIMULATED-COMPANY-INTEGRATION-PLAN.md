# AMSC Document 09 — Simulated Enterprise Integration & Member Execution Briefs

**Document ID:** AMSC-DOC-009  
**Version:** 1.0.0  
**Status:** Proposed implementation addendum; subordinate to DOC-001 through DOC-008  
**Target:** Existing ChronoCongiSec / AMSC repository  
**Scope:** Company simulation and coordinated work for M1, M3, M4, M5, M6 and M7. M2 is explicitly excluded from new assignments in this document.

---

## 1. Purpose and authoritative decisions

This document turns the existing single-company, multi-branch product design into an integrated, runnable demonstration environment. It does not create a second product, a parallel backend, or a replacement for the existing AMSC control plane.

### 1.1 Company model

The simulated environment represents **one fictional enterprise organization** with:
- Head Office — central governance, security oversight and company-wide knowledge.
- Lahore Branch — operational teams and branch-scoped knowledge.
- Karachi Branch — operational teams and branch-scoped knowledge.
- Islamabad Branch — operational teams and branch-scoped knowledge.

Use the existing company/tenant and branch abstractions as implemented and documented. Do not introduce three independent demo companies to represent these branches. Multi-tenant fixtures remain appropriate for negative isolation tests, but are not the primary company-demo storyline.

Company name, branch identifiers, roles, agents, documents and scenario content must be deterministic, fictional, clearly marked as demo data, and safe to reset. Never seed real personal, customer, banking or production secrets.

### 1.2 What the simulation is

The demo is a small, functioning business environment whose business agents perform bounded tasks using a configured model provider, authorized AMSC knowledge/memory retrieval, and approved tools. AMSC observes and governs their real execution through the existing Agent Registry, proposal/Gateway, M4 policy/trust checks, M3 memory/knowledge, M6 persistence and audit, trace/incident/recovery APIs, and M5 workstation.

Example workflow:
1. A simulated customer request enters the Customer Support workflow.
2. The agent retrieves only knowledge it is authorized to access through existing M3 interfaces.
3. It produces a business response or a typed action proposal with explicit evidence/memory references.
4. Every protected action is submitted through the existing M2-owned AMSC proposal/Gateway contract.
5. Existing M4 authorization and memory-trust decisions govern allow, block or approval.
6. An approved action is executed only by the existing server-side adapter path; no agent receives adapter credentials.
7. Execution, memory access, decisions and outcomes are correlated and persisted for the existing AMSC observability surfaces.
8. M5 presents actual backend state, not invented activity.

The company simulation is a **demo and development integration**, not a claim that a new enterprise customer can be automatically onboarded or that every external runtime is supported.

### 1.3 Runtime/framework rule

The product remains framework-neutral. CrewAI may be used as the initial simulated business-agent runtime if it is compatible with the current Python/runtime constraints and can be isolated cleanly. It must be an optional integration/adapter, not a mandatory dependency of the AMSC security core. Do not add LangChain, AutoGen, a second orchestration framework, or a new microservice unless a measured requirement and approved architecture decision justify it.

The agent runtime may expose safe lifecycle events, task status, tool proposals, tool outcomes and user-facing outputs. It must not expose hidden chain-of-thought, internal prompts, credentials, unrestricted memory dumps or sensitive provider payloads.

If model-provider configuration is absent, the demo must report a clear unavailable/configuration state. Do not fabricate model output, execution events or successful tool activity. A deterministic test double may be used in automated tests and must be visibly identified as a test double, not a live LLM agent.

---

## 2. Existing architecture and ownership boundaries

| Member | Owns this work in the company simulation | Must not take over |
|---|---|---|
| **M1 — Platform Backend & API Integration** | Company/branch request context, agent registration/API integration contracts, shared event/API contracts, app wiring, auth and authorization integration | M2 runtime internals; M3 memory logic; M4 policy decisions; M6 schema/migrations; M5 UI |
| **M2 — Agent Runtime & Gateway Adapters** | Existing owner of runtime, proposal protocol, adapter execution and credential containment. No new assignment in this document. | Must continue to be the sole owner of its runtime/gateway implementation |
| **M3 — Knowledge & Memory** | Fictional company knowledge ingestion, source metadata, authorized retrieval, memory/version/provenance/lineage, knowledge graph integration | M4 trust state/policy; M6 models/migrations |
| **M4 — Security Engine & Incident Response** | Policy and trust enforcement for company/branch/agent context, poisoning/taint scenarios, quarantine, incident and recovery integration | M2 proposal/runtime; M3 memory implementation; M6 schema |
| **M5 — Frontend & UX** | Integrate real company, branch, agent, memory, tool, trace, decision and incident data into the existing 11-screen workstation | New design system, parallel frontend, fake policy decisions, invented routes |
| **M6 — Database & Governance** | Persist company/branch/agent relationships and any approved simulation metadata; tenant-safe constraints, migrations and audit persistence | API/business logic, UI, agent runtime, policy engine |
| **M7 — DevOps, Testing & QA** | Deterministic seed/reset, local orchestration, model configuration documentation, demo runner, integration/E2E/security tests and evidence | Core domain logic owned by M1–M6 |

**M1–M7 work must use the existing repository and interfaces.** A member may request a contract change from another owner but must not silently edit that owner's files. The relevant owner implements the change, or the project lead explicitly approves a coordinated cross-owner patch.

---

## 3. End-to-end target workflow

```text
Demo User / Scenario
       |
       v
Existing AMSC API + authenticated company/branch context (M1)
       |
       v
Registered business agent / selected runtime (existing M2 contract)
       |
       +----> Authorized company knowledge retrieval (M3)
       |               |
       |               v
       |        Provenance, versions, trust metadata
       |
       v
Typed action proposal + evidence references (M2 contract)
       |
       v
Existing AMSC Gateway and M4 policy/trust decision
       |                         |
       | ALLOW / APPROVED         | BLOCK / REVIEW
       v                         v
Existing protected adapter     No protected side effect;
execution (M2)                  incident/audit as required
       |                         |
       +------------+------------+
                    v
        Persisted trace, decision, memory
        and execution evidence (M1/M3/M6)
                    |
                    v
       Existing M5 AMSC workstation
                    |
                    v
     M7 reproducible demo + regression suite
```

A direct agent-to-adapter path, direct database access from agents, or agent-side credential storage is prohibited.

---

## 4. Shared implementation rules for all assigned members

1. **Inspect before editing.** Read DOC-001 through DOC-009, `ownership.md`, `backend/owner.md`, `frontend/owner.md`, current `main`, active branches and merged PRs. Identify what already exists and what is genuinely missing. Do not reimplement completed work.
2. **Use existing technology.** Backend: current FastAPI/Pydantic/Python architecture. Frontend: current React 19, TypeScript, Vite, Tailwind CSS, TanStack Query, Zustand, React Router, React Flow and Recharts already declared by the repository. Persistence: existing PostgreSQL/SQLAlchemy/Alembic and configured cache/worker infrastructure. Verify actual installed versions and usage before adding dependencies.
3. **No speculative dependencies.** Prefer existing libraries and built-in capabilities. Add a package only when necessary, justified, version-compatible, maintained and isolated. CrewAI is optional runtime integration, not a core AMSC dependency.
4. **Contracts before parallel implementation.** M1 publishes API/event contracts; M6 publishes schema contracts; M2's existing proposal/Gateway contract remains authoritative; M3 and M4 publish memory/trust semantics. M5 consumes only published contracts. M7 coordinates the integrated test harness.
5. **Company and branch authorization is server-side.** A user/agent cannot select an arbitrary company, branch or tenant by trusting request-body/header values. Resolve identity and grants from authenticated server-side context. Company-wide knowledge and branch knowledge must have explicit visibility rules.
6. **Real data states only.** Distinguish live provider-backed execution, deterministic test-double execution, seeded static records and unavailable integrations. Do not present fixtures as real agent activity.
7. **Fail closed.** If identity, branch scope, memory trust, policy, proposal validation, persistence or audit prerequisites fail, protected action execution must not proceed.
8. **Bound execution.** Apply per-agent task/time/iteration/token limits where supported, typed input/output schemas, timeouts, cancellation, bounded retries and idempotency. No arbitrary shell, unrestricted filesystem, arbitrary network/browser access or general-purpose code execution.
9. **Security and privacy.** Keep secrets server-side; redact sensitive fields; treat retrieved documents and tool outputs as untrusted data; protect against prompt injection, SSRF, cross-branch and cross-tenant disclosure, replay and duplicate side effects. Require approval for high-impact actions according to existing policy.
10. **Evidence-based delivery.** Report exact files, tests and commands. Do not claim tests passed unless run. Record failures and limitations. Never silently suppress failing tests.
11. **Safe integration.** Each member uses a dedicated branch and small, focused PRs. Rebase/merge current main before final validation. No force-push to shared branches, no direct main commits, no automatic merge, and no overwrite of another owner's files.
12. **No production effects.** All company data and tool adapters in this demo are synthetic/sandboxed. No real customer data, real payments, real outbound messages or production infrastructure operations.

---

## 5. Member execution briefs

The prompts below are intended to be copied to the named member. Each prompt is self-contained enough to execute while remaining concise. All members must first perform a read-only gap audit and then implement only the approved scope.

### M1 — Platform Backend, Company/Branch Context & Integration

**Mission:** Make the existing AMSC API capable of serving the single simulated company and its branches safely, and publish the integration contracts used by the other members.

**Actions**
1. Audit existing auth, TenantContext, company/branch fields, agent registry, routers, dependencies, OpenAPI and current gateway integration. Reuse working code.
2. Verify the PRD's one-company/multi-branch model against current DB and API implementation. Identify any mismatch; do not invent a new tenant model.
3. Define/publish typed API contracts for company/branch context, agent metadata/configuration status, demo scenario selection/status where needed, and the read surfaces M5 needs. Keep routes under the canonical `/api/v1` conventions and align with existing route inventory.
4. Ensure authenticated user and service-agent identity, tenant/company, branch grants and roles are resolved server-side. Enforce branch scoping on list, detail, retrieval and mutation paths. Define explicit company-wide knowledge visibility.
5. Define a safe, authenticated event contract for lifecycle/proposal/decision/execution status consumption. Reuse existing traces/audit mechanisms; do not create a competing event store. Include event ID, event type/version, occurred-at timestamp, company/tenant and branch scope, agent ID, task/run ID, trace ID, status, and redacted safe metadata as appropriate. Define ordering/reconnect semantics only if supported by the chosen transport.
6. Wire existing routers/dependencies and OpenAPI without taking over M2 gateway internals, M3 memory services, M4 decisions or M6 migrations.
7. Add API/auth/branch authorization tests, including forged branch/company context, missing membership, unauthorized branch access and role restrictions.
8. Publish contract examples and integration notes for M3–M7.

**Deliverables:** contract update; minimal M1-owned API/context wiring; OpenAPI evidence; tests proving server-side branch authorization; documented event/API semantics.

**Acceptance:** a user sees only authorized company/branch data; agents are registered through existing contracts; no spoofed header/body can widen scope; M5 can build against actual OpenAPI; protected action authorization remains delegated to M4/M2.

**Do not:** create agent orchestration logic, duplicate the Gateway, add a second event broker without evidence, edit M6 migrations, or implement frontend features.

### M3 — Company Knowledge, Memory & Provenance

**Mission:** Give the simulated company realistic, safe, branch-aware knowledge that business agents retrieve through AMSC's existing memory/knowledge services.

**Actions**
1. Audit current source/document ingestion, chunking, embeddings/indexing, retrieval, memory trust filtering, provenance/versioning, ChroniMem and knowledge graph. Reuse existing services.
2. Define a small, coherent fictional company knowledge pack with Head Office policies and branch-scoped documents (for example: support policy, product/service catalogue, escalation procedure, HR leave policy, finance approval policy). Keep documents short, versioned, source-attributed, synthetic and clearly demo-labelled.
3. Coordinate any new source/branch metadata requirements with M6 and any endpoint/contract requirements with M1 before coding. Do not add ORM models or migrations yourself.
4. Ingest documents through existing pipeline; preserve source ID, owner, branch/company scope, classification/sensitivity, version, checksum and provenance according to current schema. Avoid bespoke demo-only retrieval logic.
5. Ensure agent retrieval uses existing trusted-only, tenant/branch-authorized retrieval path. No direct SQL/DB access by agent runtime. Company-wide vs branch-only document rules must be explicit.
6. Preserve provenance from source document to chunks, derived memories and agent-use evidence. Ensure retrieved references can be attached to an action proposal using the existing M2/M4 contract.
7. Add tests for valid branch access, denied cross-branch access, company-wide policy access, untrusted/quarantined exclusion, source/version lineage and deterministic reseeding behavior.
8. Provide M7 with seed content and expected retrieval assertions; provide M5 with actual data fields and API examples.

**Deliverables:** reusable fictional knowledge pack; ingestion/retrieval integration; provenance evidence; tests and seed specification.

**Acceptance:** agents retrieve only currently eligible trusted knowledge within authorized scope; every retrieved item has traceable source/version; quarantined or non-trusted content cannot justify a protected action.

**Do not:** implement a parallel vector/memory store, alter trust state independently of M4, change DB schema, create demo-specific fake retrieval endpoints, or fabricate citations/provenance.

### M4 — Security Policy, Trust & Incident Scenarios

**Mission:** Ensure simulated company agents are governed by the same AMSC security controls as any connected enterprise agents, including demonstrable allow, review and block outcomes.

**Actions**
1. Audit current PolicyEngine, TrustEvaluator, proposal validation hooks, agent isolation, incident, quarantine, drift and recovery paths. Treat existing policy engine as the authority.
2. Define a compact policy set for demo roles, branches, agents and tool impact levels. Policies must use the current rule model and M6 permission data; do not hardcode demo-only allow decisions in routes or UI.
3. Define deterministic demo scenarios: (a) normal support lookup/response with trusted knowledge; (b) attempted restricted action requiring review or being blocked by permission/parameter ceiling; (c) poisoned or suspicious knowledge reference causing a fail-closed block; (d) quarantine followed by retrieval exclusion and recovery/revalidation flow where supported.
4. Coordinate with M3 on trust/provenance states, M2 on proposal fields and enforcement hooks, M1 on authenticated company/branch context, and M6 on persisted policy/approval/audit fields. Do not edit their owned implementations.
5. Verify every protected proposal is evaluated against authenticated agent identity, branch/company scope, explicit tool permission, operation/parameter ceilings, current memory trust and required approval. Fail closed on missing/unknown/error states.
6. Ensure incidents and policy decisions include trace/run correlation and redacted evidence. Avoid storing full prompts, secrets or unnecessary sensitive payloads.
7. Add positive and negative tests for trusted/untrusted memory, branch violations, unapproved tools, threshold violations, isolated agents, policy engine outage, stale/replayed proposals and approval rules.
8. Provide M7 with scenario preconditions, expected decision, expected incident/audit state and a deterministic test oracle.

**Deliverables:** policy configuration/rules using existing engine; scenario definitions; regression tests; security acceptance evidence.

**Acceptance:** normal workflow can pass only when authorized; prohibited/tainted actions are blocked before adapter execution; review-required actions cannot execute without valid approval; incident and audit evidence are correlated.

**Do not:** create a second policy engine, let the frontend decide security, change M2 adapters, change M3 trust data directly, or weaken fail-closed behavior for demo convenience.

### M5 — Existing AMSC Workstation Integration (High Priority)

**Mission:** Make the current AMSC frontend display and operate the simulated company using the existing visual language, architecture and 11-screen workstation. This is an integration and refinement task, not a redesign.

**Actions**
1. Audit the current frontend branch and main: package manifest, AppShell, routes, design tokens, shared components, page implementations, API client, hooks, TanStack Query usage, Zustand stores, types and tests. Identify the existing screen structure and preserve it.
2. Keep the exact established stack and installed compatible versions: React 19, TypeScript, Vite, Tailwind CSS, React Router, TanStack Query, Zustand, React Flow and Recharts. Reuse current components, typography, spacing, color tokens, table patterns, drawers, status indicators and responsive behavior. Do not replace the design system or introduce another UI framework.
3. Integrate the single company and authorized branch context into the existing top navigation/AppShell. Show Head Office/Lahore/Karachi/Islamabad only when allowed by the backend. Do not imply that branches are separate tenants.
4. Connect the Agent Registry to actual registered agent records and real runtime/provider status. Show framework, model, branch, permissions, health/last-seen and execution status only when returned by APIs. Distinguish configured, running, unavailable, simulated-test and isolated states accurately.
5. Connect existing Overview, Agent Registry, Memory Explorer, ChroniMem, Knowledge Graph, Security Center, Dual Trace, Drift Monitor, Rewind, Audit Center and Settings screens to the canonical APIs. Extend current screens/components instead of creating duplicate pages.
6. Present real workflow lifecycle and gateway decisions using the published API/event/trace contract. Prefer existing polling/query invalidation or the existing supported streaming transport. Do not invent WebSocket/SSE endpoints. Handle reconnect, stale data, loading, empty, error and permission-denied states.
7. Show memory evidence and provenance in existing Memory Explorer/Graph/ChroniMem; connect action decisions to relevant memory and execution spans in Dual Trace; show incident/quarantine/recovery status from backend.
8. Clearly label demo/synthetic records and deterministic test doubles. Remove or isolate fixture fallback from any UI state that could be mistaken for live backend data. If backend is unavailable, show an explicit offline/fallback banner and never represent fixture activity as live.
9. Preserve accessibility and responsive density of the current security workstation. Avoid unnecessary animation, repeated network calls, large client bundles and redundant state. Use TanStack Query for server state and Zustand only for genuine client/workspace state.
10. Add component/page tests for branch switching, permissions, live-vs-demo labeling, agent status, gateway allow/block, errors and loading. Verify no frontend control can bypass server-side authorization.

**Deliverables:** integrated existing 11 screens; contract-aligned API hooks/types; tests; screenshots or reproducible verification notes.

**Acceptance:** the UI looks and behaves like the existing AMSC workstation, not a new generic admin dashboard; every displayed status is backend-grounded; all branch changes are authorized; no fake live events or client-side policy decisions.

**Do not:** redesign the app, replace React/Vite/Tailwind, add a parallel frontend, hardcode agents/incidents/metrics as live, invent routes, move business logic into Zustand, or change backend contracts unilaterally.

### M6 — Database, Branch Scoping & Durable Evidence

**Mission:** Ensure the simulated company, branches, agents, knowledge metadata and execution evidence fit the existing PostgreSQL data model and tenant-isolation invariants.

**Actions**
1. Audit current SQLAlchemy models, Alembic migrations, repository methods, constraints, indexes, tenant/company/branch relations and audit persistence. Identify existing structures before proposing new ones.
2. Map the one-company/multi-branch model onto existing tenant and branch abstractions. Do not create one tenant per branch or a new parallel company schema if current tables already represent the required concepts.
3. Review requirements from M1, M3, M4 and M2's existing interfaces. Propose only the minimum missing columns/tables/constraints for branch ownership, runtime metadata, simulation labeling, run correlation or event persistence.
4. Publish a short schema decision before migration work. Preserve M6-only ownership of models, repositories and Alembic migrations. Coordinate model names and API field names with M1/M3/M4.
5. Enforce tenant/company consistency and branch-scoped foreign keys/authorization support using composite constraints where appropriate. Add indexes for actual query paths. Keep audit/decision evidence append-only according to current design.
6. Ensure demo seed/reset is deterministic and cannot delete or overwrite non-demo/customer data. Use explicit demo markers and a narrowly scoped reset strategy; never rely on broad truncate/delete commands.
7. Keep transient event delivery/cache data separate from durable system-of-record evidence. Persist only events required by the existing audit/trace design; do not create duplicate logs.
8. Add migration upgrade/downgrade tests, cross-branch and cross-tenant constraint tests, concurrent-write/idempotency tests where relevant, and clean-database seed tests.

**Deliverables:** minimal reviewed schema changes (only if necessary); migrations; indexes/constraints; repository support; migration/isolation evidence.

**Acceptance:** all simulated entities persist consistently; branch and tenant mismatch is rejected at database/service boundaries; audit evidence is durable and append-only; migrations work from clean and current databases.

**Do not:** implement API endpoints, agent workflows, policy decisions, frontend code or runtime execution; do not add tables merely to mirror in-memory objects without demonstrated persistence need.

### M7 — Demo Environment, Seed/Reset, Integration QA & Delivery

**Mission:** Make the simulated company reproducible with one documented local setup and repeatable tests, while preserving the separation between demo orchestration and product logic.

**Actions**
1. Audit existing Docker Compose, environment templates, dependency locks, pytest/Vitest/CI setup, seed scripts, demo folders and test fixtures. Reuse current infrastructure and scripts.
2. Coordinate with M1/M3/M4/M6 to define deterministic company, branch, user/role, agent registration, knowledge pack and policy fixtures. M7 owns seed orchestration and demo runner; subsystem owners own domain behavior.
3. Implement an idempotent seed and explicitly scoped reset for the fictional company and its branches. The script must refuse to run against production or an unrecognized database and must never delete non-demo records.
4. Provide a concise local run path: environment check, services startup, migrations, seed, backend/frontend startup, model-provider configuration check, health/readiness check and demo launch. Reuse current Compose/Make targets where possible.
5. Keep CrewAI/provider configuration optional and isolated. Document required environment variable names without values. Never commit API keys. If no provider is configured, the runner must stop with a clear message or use an explicitly selected deterministic test mode.
6. Build a small demo runner that triggers the defined business workflows through public/authenticated AMSC APIs, not by calling internal adapters or mutating DB state directly. Do not duplicate the agent runtime owned by M2.
7. Add E2E tests for normal retrieval and response, approved tool action, denied/review action, tainted-memory block, quarantine/retrieval exclusion, trace correlation, branch authorization and clean reset/reseed.
8. Add security tests for gateway bypass, direct adapter reachability, secret leakage, prompt-injection propagation, SSRF-safe tool boundaries where applicable, cross-branch/cross-tenant access, replay/duplicate side effects and provider outage behavior.
9. Verify frontend build and tests, backend tests, migrations and Compose health. Capture exact commands, pass/fail counts and known limitations. Do not state 100% pass unless all relevant suites ran.
10. Provide one operator README section or focused runbook; keep demo orchestration scripts small and maintainable.

**Deliverables:** safe seed/reset; Compose/runbook integration; demo runner; E2E/security tests; evidence report.

**Acceptance:** a clean checkout can reproduce the same fictional company and workflows; no production secrets or side effects; tests prove both allowed and blocked paths; demo output distinguishes live provider from test mode.

**Do not:** implement core runtime/adapters, duplicate memory or policy engines, add unnecessary orchestration infrastructure, or treat a passing mock-only test as proof of live provider execution.

---

## 6. Cross-member contracts and integration order

| Order | Owner(s) | Required handoff | Consumer |
|---|---|---|---|
| 1 | M1 + M6 | Confirm company/branch identity, authorization and schema mapping | All |
| 2 | M2 (existing owner) + M1 | Existing agent proposal/Gateway contract and authenticated identity requirements; no new M2 task here | M3/M4/M7 |
| 3 | M3 + M6 | Source/document/memory fields, branch scope, provenance and persistence | M4/M5/M7 |
| 4 | M4 + M2 + M1 | Policy decision/approval contract and traceable block/allow semantics | M5/M7 |
| 5 | M1 + M3 + M4 + M6 | Published OpenAPI fields and query semantics | M5 |
| 6 | M3 + M4 + M6 | Deterministic synthetic knowledge, trust and policy fixtures | M7 |
| 7 | M5 + M1/M3/M4 | Existing workstation connected to real API states | M7 |
| 8 | M7 + all owners | Clean-run E2E evidence, integration defects and owner-assigned fixes | Project lead |

### Conflict prevention
- Each member works on a separate feature branch from current `main`; no shared branch editing.
- Before touching a file, check `ownership.md`, `backend/owner.md`, `frontend/owner.md` and recent PRs.
- If a change crosses ownership, open a contract/change request and wait for the owner. Do not implement the same file concurrently.
- Keep API, schema and UI changes in separate owner PRs where possible; merge in dependency order above.
- Rebase on the latest main before final tests. Resolve conflicts with the file owner; never choose one side blindly.
- M1 validates API/OpenAPI integration; M6 validates schema/migrations; M4 validates security invariants; M5 validates UI consistency; M7 validates reproducibility and test evidence.
- No member merges their own PR without the repository's required review and CI checks. No auto-merge or direct main writes.

---

## 7. Required demo scenarios

| Scenario | Setup | Expected result | AMSC evidence |
|---|---|---|---|
| **A — Normal customer support** | Customer Support agent; trusted company-wide and permitted branch knowledge | Agent returns a grounded response; no protected action unless required | Agent/task status, retrieved memory/source refs, trace and audit evidence |
| **B — Authorized low-impact operation** | Agent has explicit permission; trusted evidence; parameters within ceilings | Gateway allows and sandbox adapter reports a real sandbox result | Proposal, policy decision, execution receipt, trace and audit |
| **C — Restricted action** | Missing permission, wrong branch scope or exceeded parameter ceiling | Block or approval-required according to existing M4 rules; no unauthorized side effect | Decision reason, denied execution, incident/audit where required |
| **D — Tainted knowledge** | Referenced memory is suspicious, quarantined, rejected or otherwise ineligible | Fail-closed block before adapter execution | Memory trust state, proposal, block decision and correlated trace |
| **E — Quarantine and recovery** | Analyst investigates a tainted source and starts supported quarantine/recovery flow | Retrieval excludes quarantined content; recovery remains governed and revalidated | Incident, lineage/blast-radius, snapshot, recovery and audit records |

No scenario may use a real financial transfer, real customer communication, real infrastructure deletion or real production credentials.

---

## 8. Acceptance gates

- **SG-1 — Architecture alignment:** one fictional company, multiple authorized branches; no parallel product or duplicate core service.
- **SG-2 — Data integrity:** deterministic source/document ingestion; version and provenance are inspectable; trusted-only retrieval is preserved.
- **SG-3 — Security mediation:** every protected action follows existing M2 Gateway and M4 decision path; no direct adapter path; fail-closed behavior verified.
- **SG-4 — Persistence:** company/branch/agent/knowledge/decision/trace data is tenant-consistent and durable where required.
- **SG-5 — Workstation:** current M5 design and all 11 screens remain coherent; live data is distinguished from fixtures and unavailable state.
- **SG-6 — Reproducibility:** safe seed/reset, local run instructions and automated scenario execution work from a clean environment.
- **SG-7 — Integration evidence:** backend, frontend, migration, E2E and security tests have recorded results; unresolved failures are listed with owners.

The simulation is not accepted merely because the dashboard contains agent cards or seeded incidents. Acceptance requires at least one actual configured business-agent run (or a clearly labelled deterministic test-double run), authorized memory retrieval, a proposal through the existing Gateway, an observed M4 decision, an execution or block outcome, and correlated persisted evidence.

---

## 9. Token-efficient execution and reporting format

All members must minimize unnecessary token usage:
- Read only relevant files first; use search for discovery and fetch focused line ranges. Do not paste entire documents or repositories into agent context.
- Start with a concise gap table: requirement, existing evidence/path, missing work, owner, dependency.
- Do not repeat DOC-001–DOC-008. Cite document section and file path instead.
- Do not produce long plans for already completed tasks. Mark them **EXISTS—VERIFY**, **MISSING**, **PARTIAL** or **BLOCKED**.
- Implement in small logical batches and report only changed files, behavior, tests, risks and blockers.
- Ask one concise clarification only when an architectural decision cannot be safely inferred. Otherwise follow the authoritative documents.
- Do not spend tokens narrating routine actions or repeating the prompt.

**Required final report per member**
1. Status: COMPLETE / PARTIAL / BLOCKED.
2. Changed files (path + purpose).
3. Existing work reused.
4. Contracts/dependencies coordinated.
5. Commands/tests run and exact results.
6. Security checks and known gaps.
7. PR/branch reference and merge readiness.
8. Remaining work assigned to its actual owner.

---

## 10. Implementation boundary and approval

This document authorizes planning and implementation work only within the member's assigned ownership after the project lead starts that member's task. It does not authorize production deployment, real external side effects, direct main commits, automatic PR merging, or modification of M2-owned runtime/Gateway code. Any M2 contract change must be proposed to M2 and implemented by M2 or explicitly approved as a coordinated ownership change.

**Definition of done:** the simulated company is a reproducible, clearly labelled integration environment inside the existing AMSC repository; real or explicitly test-double business-agent workflows pass through existing AMSC memory, Gateway, policy, persistence, observability and workstation paths; every member's changes are ownership-aligned, tested and conflict-checked.
