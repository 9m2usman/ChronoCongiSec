# Research-Backed Agent Memory Security & Engineering Standard

**Document ID:** AMSC-DOC-007  
**Version:** 1.0.0  
**Status:** Approved research-backed engineering standard — v1.0 (documentation baseline; implementation remains subject to existing team ownership and milestone gates)  
**Prepared:** 16 November 2026  
**Applies to:** All M1–M7 work, integrations, tests, demonstrations and future milestones  
**Repository:** https://github.com/9m2usman/ChronoCongiSec

---

## 1. Purpose and authority

This document establishes the shared research-to-engineering methodology for ChronoCongiSec (Agent Memory Security Center / AMSC).

ChronoCongiSec is the improved successor that consolidates two prior foundations:

1. **KnowledgeLine** — https://github.com/9m2usman/KnowledgeLine  
   Its evidence/evolution/impact control-plane approach: source and knowledge lineage, authority, versions, transformations, freshness, conflicts, propagation, explainable ALLOW/REVIEW/BLOCK decisions, simulation, selective quarantine and recovery.
2. **Agent Security Guard / AgentGuard** — https://github.com/HafizShamaz/agent-security  
   Its runtime tool interception, deterministic policy enforcement, risk and impact assessment, PII/secret/injection detection, scoped permissions, human review, hash-chained audit, static scanning and red-team evaluation.

This is not a request to copy either repository. It is a requirement to preserve their useful, evidence-backed strengths while deliberately avoiding known weaknesses, unsupported claims, insecure shortcuts and architectural regressions.

**ChronoCongiSec's existing approved architecture and security improvements remain authoritative.** This document extends their research basis; it does not weaken or replace them.

Read this document together with:
- `docs/01-PRD.md` — product outcomes and requirements.
- `docs/02-TRD-SRS.md` — technical architecture and security behavior.
- `docs/03-APPLICATION-FLOW.md` — workflows, Dual Trace and rewind.
- `docs/05-DATABASE-API-SCHEMA.md` — canonical data/API contract.
- `docs/06-TEAM-IMPLEMENTATION-PLAN.md` — team ownership and delivery plan.

If a research paper conflicts with an approved product requirement, do not silently change the requirement. Record the conflict, assess the evidence and obtain an architecture decision.

## 2. Non-regression rules: strengths that must be preserved

The following are binding design invariants. Research additions must strengthen them, never replace them with weaker alternatives.

1. **Server-side complete mediation:** every protected tool/action proposal passes through the AMSC gateway. Agents do not receive protected tool credentials or direct bypass routes.
2. **Fail closed for protected actions:** unavailable or indeterminate authorization, trust, integrity, tenant or replay checks must not result in execution. A narrowly scoped availability exception requires an explicit threat-model decision; it must never silently authorize an action.
3. **Tenant isolation by construction:** tenant identity comes from authenticated server-side context; tenant-scoped access is enforced at service and persistence boundaries. Client-supplied tenant IDs are not authoritative.
4. **Durable evidence:** PostgreSQL is the system of record for security-critical state, versions, provenance, decisions, checkpoints and audit evidence. Redis is for transient coordination/cache/rate limiting, not the only copy of critical evidence.
5. **Immutable history:** preserve prior memory versions and provenance evidence. Corrections create new versions or explicit supersession/revocation events; do not silently rewrite history.
6. **Trust is multidimensional:** source identity, authority, integrity, freshness, sensitivity, policy scope, contradiction and derivation lineage are separate attributes. A checksum, signature, high similarity score or trusted tenant does not prove that content is true.
7. **Deterministic authorization:** an LLM, classifier, embedding similarity score or risk model may provide evidence, but must not independently grant permission or override a hard policy rule.
8. **Explainable ALLOW / REVIEW / BLOCK:** decisions record the applicable policy, evidence, reason codes, relevant memory/action lineage and policy version.
9. **Recovery is scoped and auditable:** preserve a pre-recovery snapshot, compute impact, apply explicit invalidation/revocation, validate post-recovery state and retain the incident/audit history.
10. **Modular ownership:** M1–M7 boundaries remain in force. No parallel RBAC, policy, persistence or gateway subsystem may be introduced by a team outside its ownership.
11. **No fabricated assurance:** do not claim zero latency, zero attack success, complete hallucination elimination, universal rollback or production readiness without reproducible evidence.

## 3. What we carry forward from KnowledgeLine

KnowledgeLine's strongest contribution is its **evidence/evolution/impact control-plane boundary**. AMSC must retain the following concepts:

### 3.1 Evidence and knowledge lineage

Preserve the chain:

`source → knowledge object → version → transformation → memory → agent/context → workflow → proposed action → executed effect`

Each derivation must retain its upstream references, actor/process, timestamps, tenant, transformation identity/version and integrity evidence. Summaries, embeddings, extracted claims and agent memories must not lose the identity and policy constraints of their ancestors.

### 3.2 Separate dimensions instead of one misleading trust score

Track at least:

- **Origin/provenance:** where the information came from and how it was derived.
- **Authority:** whether that source is authoritative for this subject and tenant.
- **Integrity:** whether bytes/state match the recorded cryptographic evidence.
- **Freshness/validity:** whether the information is current, expired or superseded.
- **Trust state:** security disposition such as UNVERIFIED, TRUSTED, SUSPICIOUS, QUARANTINED or REJECTED.
- **Sensitivity:** whether data is confidential, personal, regulated or secret.
- **Policy scope:** who may use the information, for which purpose, agent, tenant and action.
- **Conflict:** whether credible records contradict one another.
- **Derivation lineage:** which inputs materially influenced a derived record.

Do not collapse these dimensions into a single confidence number. If a score is used for ranking or triage, retain the underlying evidence and do not use it as authorization.

### 3.3 Deterministic security decisions

Retain explainable decisions:

- **ALLOW:** all mandatory identity, policy, trust, integrity, freshness, scope and action checks pass.
- **REVIEW:** policy explicitly permits escalation and a qualified reviewer can resolve the uncertainty.
- **BLOCK:** a mandatory check fails, the request is prohibited, evidence is invalid, or a required security dependency is unavailable.

An LLM may summarize evidence or suggest a classification. The final authorization decision remains deterministic and server-side.

### 3.4 Propagation and impact

When a source, claim, memory, policy or agent state is found compromised or superseded, calculate its downstream dependency closure:

- derived claims and summaries;
- memory versions and snapshots;
- embeddings/vector entries and caches;
- agent contexts and delegated agents;
- pending decisions and workflows;
- proposed or completed actions.

Do not assume a memory record is isolated merely because it has a separate row or vector ID.

### 3.5 Simulation and what-if analysis

Retain deterministic impact simulation: show which memories, agents, workflows and actions would be affected by a proposed quarantine, policy change, revocation or rewind before applying it. Simulation must not mutate production state.

### 3.6 KnowledgeLine lessons and constraints

The KnowledgeLine phase documents are valuable implementation history, but their `VERIFIED` labels and benchmark numbers are claims made by that project's own documentation; they are not independent security certification or peer-reviewed validation. Its separate `KNOWLEDGELINE_RESEARCH_PAPER_DRAFT.md` is an internal research manuscript, not a peer-reviewed publication. Treat the TMA-NM / Trust-Mediated Architecture, Section 5 governance model, divergence equation, SBU and T-1 recovery as project-originated design patterns unless a separate external source is cited. They are useful hypotheses and engineering patterns, not established mathematical laws.

Specific non-regression and evidence rules:
- KnowledgeLine Phase 12 documents an in-memory, node-local login rate limiter and explicitly notes it is not distributed. ChronoCongiSec must retain its Redis-backed distributed rate-limiting direction; do not copy the node-local fallback into production.
- KnowledgeLine's own README configures Gemini and SMTP integrations. Do not claim zero cloud egress or sovereign-only processing when external LLM, email, webhook or telemetry providers are enabled. Data-flow and egress controls must reflect the actual deployment configuration.
- A `SHA-256` digest is a content checksum, not a digital signature, source-authentication proof or non-repudiation mechanism. A party able to replace both content and digest can recompute the digest. Protect expected digests with separately controlled signatures/HMACs, KMS-backed keys or tamper-evident checkpoints where the threat model requires authenticity.
- KnowledgeLine's reported 100% accuracy over 1,000 synthetic claims, 0.908 ms divergence latency, and 10,000-turn drift simulations are project-specific reported results. They do not establish general real-world detection accuracy or a universal drift law. Rebuild representative, held-out, independently labelled evaluation before making AMSC performance claims.
- Treat the KnowledgeLine divergence equation as a domain-specific heuristic/decision-support feature until its variables, normalization, weights, thresholds and calibration are justified on representative data. Semantic distance is not equivalent to factual contradiction; a weighted score can hide a severe single constraint violation or overreact to irrelevant wording changes. Preserve deterministic hard constraints separately from statistical drift scores.
- Do not describe ordinary hashing, provenance metadata or tenant isolation as “zero-knowledge cryptography” unless a specific zero-knowledge proof protocol is implemented and verified. The KnowledgeLine research draft uses “zero-knowledge” language, but the described SHA-256 and in-tenant processing do not by themselves constitute a zero-knowledge proof.
- Its email status `ACCEPTED_BY_PROVIDER` does not prove recipient inbox delivery; retain the same distinction for every external tool result.
- Do not promote a source or memory to TRUSTED merely because a hash verifies, a divergence score is low, a model judge agrees, or a source is in a tenant's database. Trust requires an explicit policy-governed validation decision and preserved evidence.

Carry forward the strengths above, but avoid these failure patterns:

- **Shared-base or vector-store isolation shortcuts:** tenant isolation must not depend on a caller-supplied filter alone. Enforce tenant boundaries in authenticated context, repository queries, database constraints/RLS where appropriate, and adversarial cross-tenant tests.
- **Magic thresholds presented as truth:** thresholds such as divergence or contradiction cutoffs are heuristics until calibrated on representative data. Store rationale, calibration set, version, false-positive/negative results and uncertainty. Never let an unvalidated numeric threshold independently authorize a high-impact action.
- **Overclaiming hallucination detection:** no divergence metric, LLM judge or memory filter can prove that all hallucinations are detected. Use source-grounded verification, contradiction checks, abstention and measured evaluation; state limits clearly.
- **Claiming rewind undoes the outside world:** database/memory rollback cannot undo an email already sent, a payment, a cloud change or an external API side effect. Use compensating actions, provider idempotency/reversal APIs, containment and incident response; label irreversible effects explicitly.
- **Unbounded agent orchestration or external automation:** every delegated agent, webhook, workflow and integration must have identity, scoped authority, signed/replay-protected messages, bounded retries/timeouts and audit evidence.
- **Provider/model dependence:** LLM providers may assist extraction or analysis but must not be a mandatory authorization dependency. Keep deterministic policy enforcement available independently.

## 4. What we carry forward from Agent Security Guard

Preserve these useful patterns:

- Runtime interception at the tool-call boundary, before the tool function executes.
- Shared detection logic between runtime enforcement and static/CI scanning where practical.
- Deterministic hard rules that cannot be lowered by an ML score.
- Risk/impact assessment with human-readable reason codes.
- PII and secret detection/redaction.
- Prompt-injection and unsafe-execution signals treated as evidence, not proof.
- Agent and requesting-principal permissions both checked.
- Versioned policy-as-data with schema validation; never evaluate arbitrary policy text with `eval`.
- Human approval for selected high-impact actions, with expiry defaulting to denial.
- Append-only/hash-chained audit evidence.
- Red-team cases, benign hard negatives, held-out attack families and latency measurement.
- Static scanning with machine-readable CI output (for example SARIF).

### 4.1 AgentGuard limitations that must not be inherited

The AgentGuard repository's own `docs/EVALUATION.md` is unusually transparent and must be read before borrowing its scoring approach. It reports 27 synthetic scenario families, a 7,000-scenario training pool and a 2,500-scenario test pool; the default rules-plus-model blend is 93.4% accuracy versus 93.3% for rules alone on that synthetic test pool. On held-out scenario families, the model-only accuracy drops to 76.4% and review-class recall to 5.5%. Its prompt-injection classifier is weak on unseen phrasing and the report explicitly calls out Roman Urdu and reworded styles. Its 0% end-to-end attack success demonstration uses a deterministic `NaiveAgentModel`, and the tested harmful outcomes were already blocked by action-level rules even when injection detection was disabled. The evaluation also reports a single-node setup, no application TLS termination or rate limiting, and development API keys that must be changed. These are project-reported synthetic/demo results, not evidence of real-world generalization.

Therefore:

1. Do not treat synthetic accuracy or a small demonstration attack set as proof of real-world security. Report AgentGuard's sample sizes and limitations whenever citing its evaluation.
2. Do not allow an XGBoost model, classifier, SHAP explanation or LLM analyst to authorize a tool call.
3. Do not assume prompt-injection text detection catches semantic, multilingual, encoded, compositional or delayed attacks.
4. Do not rely on keyword/pattern detection as the only memory-poisoning defense.
5. Do not confuse detecting an injection with preventing its downstream effect. AgentGuard's own end-to-end result shows why action-boundary policy can be the actual blocking control even when the injection detector is disabled.
6. Do not claim an action was blocked merely because a model labelled it risky; verify the tool was not invoked and no external side effect occurred.
7. Keep hard permission, tenant, destination, data-flow and action constraints deterministic.
8. Evaluate on unseen attack families, realistic tools, real state changes and independent ground-truth oracles.

## 5. Research selection and evidence policy

Research is selected for direct relevance to AMSC's actual capabilities: persistent memory, provenance, trust, poisoning, drift, retrieval, rollback, traces, multi-tenancy and tool execution.

Research status must be recorded honestly:
- **Peer-reviewed:** published in a named peer-reviewed venue.
- **Preprint:** arXiv or other preprint; useful but not peer-reviewed unless separately confirmed.
- **Benchmark/tool:** useful evaluation artifact; its dataset, license, implementation and protocol still require inspection.
- **Design guidance:** standards or security guidance, not an experimental paper.
- **Emerging/unverified:** insufficient independent evidence; research lead only.

Paper-reported results are not AMSC results. Reproduce relevant experiments before using any result as a project performance claim. Check paper version, authors, venue, code, data, license, threat model, baselines, sample size, variance, evaluator and limitations before adopting a method.

## 6. Selected research and engineering implications

### 6.1 Memory versioning, temporal state and rewind

**ChronoMem: Version Control and Semantic Rollback for Large Language Model Agent Memory** — Yongye Su, Wujiang Xu, Chaoji Zuo, Elisa Bertino, arXiv:2607.27773 (2026), preprint.

Source: https://arxiv.org/abs/2607.27773

Relevance:
- Whole-memory snapshots and structured version histories.
- Semantic selection of a historical version from a natural-language undo request using hybrid lexical/semantic retrieval and reranking.
- Post-exposure evaluation: after rollback, test whether future information still leaks into answers or summaries.

AMSC application:
- Treat snapshots and immutable versions as first-class records.
- A rollback request must resolve to an explicit version/checkpoint; do not let an LLM directly choose and mutate arbitrary history.
- Preserve a pre-rollback snapshot and audit the selected checkpoint, reason, operator and impact.
- Test counterfactual consistency after rollback: queries and summaries must not reveal information that belongs only to the invalidated future state.

Limitations to respect:
- Memory rollback is not external-world rollback.
- Whole snapshots have storage costs.
- The paper's reported implementation/evaluation scope does not establish universal enterprise readiness or arbitrary multi-tenant concurrency.
- AMSC must test branching, concurrent writes, retention and selective recovery rather than assume linear history is sufficient.

**AgentRewind: Recoverable Execution for Long-Horizon LLM Agents** — arXiv:2608.14380 (2026), preprint.

Source: https://arxiv.org/abs/2608.14380

Relevance:
- Aligned checkpoints of agent context and controlled environment state.
- Recovery that preserves a useful account of the failed attempt.
- Evidence that restoring only conversation context or only workspace state can be insufficient.

AMSC application:
- Dual checkpoint model: memory/context checkpoint plus controlled environment/workspace checkpoint.
- Record a rewind explanation so the agent does not repeat the same failed path.
- Restore only controlled state with explicit ownership and recovery boundaries.
- Verify the restored context, memory, environment and caches before resuming.

Limitations:
- External network requests and third-party side effects cannot be undone by filesystem or memory restoration alone.
- Do not promise universal rewind. Use compensating transactions, cancellation, provider reversal APIs or human incident response for external effects.
- Treat benchmark results as paper-reported, not AMSC-validated.

**Rollback the World, Keep the Reflection: Rollback-Induced Reflection for Long-Horizon LLM Agents** — arXiv:2609.18304 (2026), preprint.

Source: https://arxiv.org/abs/2609.18304

Relevance:
- Recovery should decide when to intervene, where to resume and what information from the failed attempt should survive.

AMSC application:
- Keep a structured, untrusted recovery note that records the failed action, evidence, reason for rewind and prohibited repetition.
- Do not reintroduce tainted instructions through the recovery note.
- Separate preserved learning from active authoritative memory.

**Temporal Multimodal Memory Banks for Agentic Reasoning (ChronoMem)** — Prasanth Yadla, ICCV 2025 Workshop.

Source: https://openaccess.thecvf.com/content/ICCV2025W/MMRAgI/html/Yadla_Temporal_Multimodal_Memory_Banks_for_Agentic_Reasoning_ICCVW_2025_paper.html

Relevance:
- Hierarchical episodic memory and temporal association across modalities.

AMSC application:
- Research lead for future multimodal evidence and temporal indexing.
- Not a requirement to introduce multimodal storage in the current milestone.
- Distinguish this paper's multimodal memory architecture from the separate 2026 ChronoMem semantic version-control paper.

### 6.2 Memory poisoning and trust propagation
**Important dual-trace distinction:** KnowledgeLine's Phase 03/07 uses `FACT` and `SCENE` as two memory representations; the separate paper *Drawing on Memory* pairs a factual trace with a generated contextual scene trace. These are distinct from AMSC's UI/observability **Dual Trace**, which correlates execution and memory/evidence spans. A generated SCENE is a mnemonic reconstruction, not primary source evidence. Label it as model-generated/derived, retain its source-event references, and never use the narrative itself to establish factual truth, authority or action permission. Evaluate privacy leakage and injection carryover before adopting scene traces.

**Drawing on Memory: Dual-Trace Encoding Improves Cross-Session Recall in LLM Agents** — arXiv:2604.12948 (2026), preprint.

Source: https://arxiv.org/abs/2604.12948

Relevance:
- Pairs a factual memory with a contextual/scene trace describing when and how the fact was learned.
- Reports gains on cross-session recall and temporal reasoning in its evaluated LongMemEval-S setting.

AMSC application:
- Consider storing a compact contextual evidence trace alongside selected facts: source event, time, interaction/session, observed evidence and derivation.
- Use this as an optional memory-quality and explainability enhancement, not as proof of truth or authority.
- Preserve a strict separation between the paper's **dual-trace memory encoding** (fact + contextual scene) and AMSC's **Dual Trace observability feature** (execution trace + memory/evidence trace). They are related research ideas but are not the same architecture.
- Evaluate whether contextual traces improve recall and temporal reasoning without increasing privacy exposure, prompt-injection carryover, storage cost or retrieval noise.

Caution:
- The work is a preprint, not a validated security mechanism. Contextual scene traces can themselves contain untrusted or sensitive material and must inherit provenance, trust, sensitivity and retention controls.


**Memory Injection Attacks on LLM Agents via Query-Only Interaction (MINJA)** — NeurIPS 2025.

Source: https://papers.neurips.cc/paper_files/paper/2025/hash/42a97bbd9844d2bf68596730af80bcdf-Abstract-Conference.html

Finding:
- An attacker may influence persistent memory through ordinary query interactions without direct database write access.

AMSC application:
- Treat conversational write channels as untrusted.
- Record the principal, session, source and derivation path for every memory write.
- Test delayed activation, bridging context and malicious content that becomes relevant only to later victim queries.
- Do not equate authenticated user interaction with trustworthy memory content.

**From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents** — arXiv:2606.04329 (2026), preprint.

Source: https://arxiv.org/abs/2606.04329

Finding:
- Multiple write channels and structural vulnerabilities create persistent poisoning risk.
- Aggressive memory write/retrieval can increase exposure.
- Existing prompt-injection defenses do not cover all memory poisoning paths.
- Introduces MPBench as an evaluation direction.

AMSC application:
- Build a write → persist → retrieve → influence → consequence attack lifecycle test.
- Test every memory write channel, not only direct upload.
- Separate write-time checks from retrieval-time and action-time controls.
- Measure benign memory utility alongside attack prevention.

**MemPoison: Uncovering Persistent Memory Threats and Structural Blind Spots in LLM Agents** — arXiv:2607.14651 (2026), preprint at time of review.

Source: https://arxiv.org/abs/2607.14651

Finding:
- Distinguishes direct single-record corruption, compositional multi-record corruption and context-triggered dormant corruption.
- Write-time filtering may suppress direct attacks while missing malicious effects created by joint retrieval or later triggers.

AMSC application:
- Add L1/L2/L3 poisoning test classes.
- Evaluate memory influence by controlled ablation: remove candidate record, remove its fragments, and compare matched retrieval contexts.
- Apply trust-aware retrieval and action-time lineage checks, not just ingestion filters.
- Test adversarial paraphrase, entity masquerading and embedding-neighborhood behavior.

**MemLineage: Lineage-Guided Enforcement for LLM Agent Memory** — arXiv:2605.14421 (2026), preprint.

Source: https://arxiv.org/abs/2605.14421

Finding:
- Combines cryptographic provenance with derivation lineage.
- Uses per-principal signatures, Merkle-log concepts, a weighted derivation DAG and propagation of untrusted ancestry to sensitive-action authorization.

AMSC application:
- Strong research basis for cryptographic memory provenance and source-to-derived-memory lineage.
- Preserve the principle that signing a derived record does not cleanse untrusted ancestry.
- Carry ancestry trust and policy restrictions into derived summaries and downstream action justification.
- Evaluate signed entries, lineage-only and combined defenses separately.

Caution:
- Paper-reported zero-ASR and latency figures belong to its stated harness and conditions. They are not universal guarantees and must not be copied into AMSC marketing or acceptance claims.
- Review its code, cryptographic construction, threat model and deployment assumptions before adopting exact algorithms or thresholds.

**MemSecBench: Tracking Agent Memory Poisoning from Persistence to Consequence and Repair** — arXiv:2607.27080 (2026), preprint/benchmark.

Source: https://arxiv.org/abs/2607.27080

Relevance:
- Evaluates poisoning across persistence, downstream consequence and selective repair, not merely whether a filter flags a record.

AMSC application:
- Use its lifecycle framing to design an internal benchmark.
- Map each test to memory write, later retrieval, agent decision, actual tool/environment effect and repair verification.
- Review dataset availability, license, case protocol and evaluator before integrating the benchmark.

**Your Agent's Memories Are Not Its Own: Forged Reasoning Attacks on LLM Agent Memory and Defenses** — arXiv:2607.05029 (2026), preprint.

Source: https://arxiv.org/abs/2607.05029

Relevance:
- Poisoning reasoning traces, not just factual memory.
- Self-referential reinforcement can make malicious remembered rationales appear corroborated.

AMSC application:
- Treat reasoning summaries and past tool-use explanations as untrusted derived data.
- Preserve the difference between observed facts, model-generated rationale, tool evidence and verified outcomes.
- Do not use repeated self-generated claims as independent corroboration.
- Require external evidence for sensitive action justifications.

**Important naming distinction:** the arXiv:2605.29960 paper also names its proposed attack *MemPoison*. It is a separate work from the arXiv:2607.14651 paper titled *MemPoison: Uncovering Persistent Memory Threats and Structural Blind Spots in LLM Agents*. Do not merge their threat taxonomies, datasets or findings.

**Hijacking Agent Memory: Stealthy Trojan Attacks Through Conversational Interaction** — arXiv:2605.29960 (2026), preprint.

Source: https://arxiv.org/abs/2605.29960

Relevance:
- Selective extraction, rewriting and embedding-space behavior can carry triggerable malicious content into memory.

AMSC application:
- Test the complete memory-consolidation pipeline, not just raw input filters.
- Include trigger-conditioned retrieval and semantically disguised poison in red-team tests.

### 6.3 Enterprise authorization continuity and provenance

**AkasicMEM: Governed Enterprise Memory for Agents** — arXiv:2609.25563 (2026), preprint.

Source: https://arxiv.org/abs/2609.25563

Relevance:
- Source restrictions can be lost when information is transformed and reused across agents.
- Proposes authorization continuity using transitive lineage, policy composition during memory formation and policy re-evaluation at retrieval.

AMSC application:
- A derived memory must not become more permissive than its source.
- Carry purpose, tenant, sensitivity and access restrictions across source → memory → derived memory → agent.
- Re-evaluate current authorization at retrieval and action time, because policy may change after ingestion.
- Test delegated-agent and cross-workflow reuse.

Caution:
- Do not assume the paper's unified graph/vector/relational database is required. AMSC's existing PostgreSQL + pgvector architecture remains the baseline unless measured evidence justifies a change.

### 6.4 RAG poisoning, hallucination and stale knowledge

**ToxicRAG: Compromising Retrieval-Augmented Generation Systems via Single-Shot Knowledge Poisoning Attacks** — arXiv:2609.11082 (2026), preprint.

Source: https://arxiv.org/abs/2609.11082

Relevance:
- A single coherent narrative can attempt to supersede a previously accepted fact by fabricating updates and authority.

AMSC application:
- Preserve source authority and effective time separately from document recency.
- Require evidence for claimed supersession or revocation.
- Detect contradictions and suspicious authority claims.
- Test narrative-form poisoning, not only obvious malicious strings.

**Reliable Post-Retrieval Assembly for Agent Memory: Separating Evidence Extraction from Policy Execution** — arXiv:2606.01435 (2026), preprint. The arXiv identifier's citation metadata has also circulated under the working/alternate title “Don't Ask the LLM to Track Freshness”; use the current paper title when citing the work.

Source: https://arxiv.org/abs/2606.01435

Relevance:
- Current-value conflict resolution should use explicit version/serial/time and authority metadata rather than relying entirely on model judgment.

AMSC application:
- Use deterministic ordering only when the domain defines a valid ordering and the source authority is comparable.
- Do not assume newest always means correct: authority, effective time, scope and revocation matter.
- Preserve unresolved conflicts and abstain/escalate when evidence is insufficient.

**When Memory Lies: An Empirical Study of Spatial Memory Staleness in VLM Agents** — arXiv:2608.04574 (2026), preprint.

Source: https://arxiv.org/abs/2608.04574

Relevance:
- Stale memory can be worse than no memory when the current environment contradicts it.

AMSC application:
- Include freshness, expiry and supersession in retrieval eligibility.
- Compare memory claims against current authoritative observations where available.
- Make uncertainty and stale status visible to the agent and policy engine.

**HaluMem: Evaluating Hallucinations in Memory Systems of Agents** — EMNLP 2026 main-conference paper and benchmark.

Source: https://aclanthology.org/2026.emnlp-main.220/

Relevance:
- Evaluate hallucination introduced during memory extraction, updating and question answering as separate failure stages. HaluMem provides Medium and Long datasets with roughly 15,000 memory points and 3,500 questions.

AMSC application:
- Add tests for fabricated memory, incorrect extraction, unsupported summaries, retrieval mismatch and confident answer without evidence.
- Measure factual support, attribution, abstention and task utility separately.

Important distinction:
- AMSC is a memory integrity and action-governance control plane. It cannot guarantee that an underlying LLM never hallucinates. It can preserve evidence, detect certain inconsistencies, require verification and block actions whose required evidence is missing.

### 6.6 Memory consolidation, evidence assembly and hallucination attribution

**TrustMem: Learning Trustworthy Memory Consolidation for LLM Agents with Long-Term Memory** — Findings of EMNLP 2026, peer-reviewed conference findings paper.

Source: https://aclanthology.org/2026.findings-emnlp.2419/

Relevance:
- Evaluates memory transitions using coverage, preservation and faithfulness, addressing omissions, corruption and unsupported additions during updates.
- A useful complement to AMSC's immutable versions and source lineage: evaluate the transition between old and proposed memory states, not only the final record.

AMSC application:
- Add transition-level evaluation for memory create/update/consolidate operations: what source facts were preserved, omitted, altered, contradicted or newly invented?
- Preserve before/after versions and evidence links for every proposed transition.
- Use a verifier as a diagnostic signal or review trigger; it must not independently promote memory to TRUSTED or authorize actions.
- Consider preference learning only as an offline model-improvement experiment with held-out evaluation. Do not add a trained verifier as a mandatory runtime dependency without measured benefit and a safe fallback.

**MemBook: A Hierarchical Reasoning-based Memory Framework for Hallucination-Resistant LLM Agents** — Findings of EMNLP 2026, peer-reviewed conference findings paper.

Source: https://aclanthology.org/2026.findings-emnlp.1847/

Relevance:
- Studies hierarchical memory organization and retrieval across evolving memory records, with evaluation on HaluMem and LongMemEval.
- Offers a research direction for organizing temporal, logical and evidentiary relationships rather than treating all memory as a flat vector collection.

AMSC application:
- Evaluate whether a hierarchical retrieval/assembly layer improves temporal and multi-hop evidence selection over the existing PostgreSQL + pgvector design.
- Preserve the canonical relational record and provenance graph as the authority; hierarchy is a retrieval/organization layer, not a replacement for tenant-scoped storage or policy enforcement.
- Benchmark memory utility, unsupported synthesis, latency and tenant isolation before adopting.

**AgentHallu: Benchmarking Automated Hallucination Attribution of LLM-based Agents** — EMNLP 2026, peer-reviewed main-conference paper.

Source: https://aclanthology.org/2026.emnlp-main.925/

Relevance:
- Studies attribution of hallucinations to intermediate planning, retrieval, reasoning, human-interaction and tool-use steps across multi-step agent trajectories.
- Its reported best step-localization accuracy is limited, demonstrating that automated attribution remains difficult.

AMSC application:
- Extend Dual Trace forensic analysis to identify candidate divergence points: source ingestion, memory extraction, retrieval, reasoning, policy evaluation, tool result interpretation or final reporting.
- Treat model-generated attribution as an investigative hypothesis. Correlate it with immutable spans, actual memory versions, policy decisions and independently observed tool effects.
- Do not use automated attribution as a standalone verdict or authorization input.

### 6.7 Tool execution and agent security

**AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents** — NeurIPS 2024.

Source: https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html

AMSC application:
- Benchmark tool use against malicious instructions embedded in untrusted tool outputs.
- Preserve benign task completion measurements alongside attack success.
- Use state-based assertions to verify whether the protected action actually occurred.

**Securing Tool-Using AI Agents Against Injection and Authority Misuse** — Computation, 2026.

Source: https://doi.org/10.3390/computation14050098

Relevance:
- Compares least privilege, retrieval allowlisting, execution verification, memory compartmentalization, rate limits and human approvals.
- Explicitly reports security/utility/latency trade-offs; layered defenses can create significant friction.

AMSC application:
- Prefer mechanism-specific controls rather than applying every expensive check to every request.
- Least-privilege tool scopes are a default.
- Retrieval allowlisting is useful for untrusted external sources.
- Execution receipts/read-after-write checks address false claims about tool state.
- Human approval is reserved for high-impact actions, not every routine action.
- Rate limits reduce burst impact and severity.

Caution:
- Its results are from an assumption-explicit simulation framework, not a field trial. Use the design insights, not its simulated percentages as production predictions.

**Runtime Protection Practice for LLM Agent Security: An On-Demand Behavioral Sandbox Approach** — IEEE conference paper, 2026.

Source: https://doi.org/10.1109/ISAEECE70502.2026.11635191

AMSC application:
- Evaluate on-demand sandbox execution for ambiguous or high-risk actions.
- Observe filesystem, process, network and privilege side effects before promotion to real execution.
- Keep routine low-risk operations on a faster deterministic path.
- Measure added latency and false rejection.

Caution:
- Paper-reported benchmark results are not universal. Sandbox isolation must be independently verified and cannot guarantee containment of every side effect.

**Runtime Policy Enforcement for MCP-Based LLM Agents** — Electronics, 2026.

Source: https://www.mdpi.com/2079-9292/15/13/2829

AMSC application:
- Enforce policy at the tool boundary.
- Propagate source-integrity and data-sensitivity labels across tool steps.
- Bind authorization to the actual tool arguments and current information-flow context.
- Record tamper-evident evidence for decisions.

Caution:
- Validate the paper's test environment, assumptions and external reproducibility before adopting reported ASR improvements.

## 7. Dual Trace: required AMSC interpretation

The KnowledgeLine FACT/SCENE memory encoding and AMSC execution/memory observability traces are complementary concepts, not interchangeable implementations. See Section 6.2 for the handling requirements for generated scene traces.

Dual Trace is an AMSC architectural capability, not a claim that one paper has already validated the complete AMSC design.

It must correlate two complementary evidence streams:

### Trace A — Execution trace
- user/request identity and tenant;
- agent identity and delegation chain;
- model invocation and tool-call spans;
- tool name, version and normalized argument digest;
- policy decision and reason codes;
- approval/rejection;
- actual tool result and independently observed side effect;
- latency, retries, errors and idempotency key.

### Trace B — Memory/evidence trace
- memory IDs and immutable versions read;
- source and derivation ancestors;
- trust, authority, freshness, sensitivity and policy state at read time;
- memory writes, transformations and version changes;
- contradictions, quarantine, revocation and rewind events;
- evidence used to justify the proposed action.

### Correlation requirements

- Use a stable request/trace ID and span/parent relationships to join the two traces.
- Record exactly which memory versions influenced a tool proposal, not merely which records were available.
- Preserve provenance across summaries, derived memories and delegated agents.
- Keep trace events tenant-scoped and access-controlled.
- Redact secrets, credentials, PII and sensitive content; prefer identifiers and digests over raw payloads.
- Store critical security decisions durably; telemetry systems are not the authoritative audit ledger.
- Do not allow an agent to forge, suppress or rewrite the trace evidence used to evaluate its own action.
- Ensure sampling never drops mandatory security/audit events. Sampling may apply to non-security diagnostic spans only.
- Use OpenTelemetry-compatible trace/span concepts and GenAI semantic conventions where applicable, while pinning the adopted convention version and documenting gaps.

Research reference: https://opentelemetry.io/docs/specs/semconv/gen-ai/

## 8. Rewind and recovery: required AMSC interpretation

AMSC recovery must be a controlled, multi-layer operation, not a generic "undo" button.

1. Detect and classify the incident.
2. Freeze or constrain affected agent/action paths where necessary.
3. Preserve pre-recovery memory, execution and environment checkpoints.
4. Compute dependency and authorization impact.
5. Identify contaminated descendants, embeddings, caches, summaries, contexts and pending actions.
6. Select a valid recovery point using deterministic version identity and authorized operator intent.
7. Apply scoped restore, tombstones/revocations and cache invalidation.
8. Handle external effects separately through compensating actions, provider cancellation/reversal or incident response.
9. Rebuild or invalidate derived state so future context cannot retain the abandoned branch.
10. Validate memory, context, environment and tool state.
11. Record an immutable recovery event and evidence of what was and was not reversed.

### Recovery acceptance tests

- A poisoned memory is removed from normal retrieval after quarantine.
- Derived summaries and embeddings no longer expose the invalidated content.
- The restored agent cannot answer using post-checkpoint facts that were structurally removed.
- The recovery note does not reintroduce malicious instructions.
- Unaffected memories and other tenants remain unchanged.
- An external action is never reported as reversed unless provider/environment evidence confirms the reversal.
- Repeated recovery requests are idempotent or safely rejected.
- Concurrent writes during recovery are detected and reconciled; no silent lost update.
- Every recovery step is attributable to an authorized principal and policy decision.

## 9. Security and efficiency architecture

The goal is not maximum checks per request. The goal is the minimum safe, evidence-based checks for each risk tier.

### 9.1 Mandatory fast path

For every protected action:
- authenticate principal and agent;
- resolve tenant and delegation context;
- validate request schema and idempotency/replay state;
- enforce deterministic tool and resource permissions;
- enforce hard policy constraints;
- verify required memory trust/lineage/freshness and data-flow constraints;
- write required decision evidence before execution;
- verify execution outcome.

No LLM call is required for deterministic authorization.

### 9.2 Risk-based additional controls

Apply expensive or interactive controls selectively:
- sandbox ambiguous/high-impact tool actions;
- human approval for irreversible, financial, external communication, privilege-changing or sensitive export actions;
- deeper lineage traversal for high-risk actions or suspicious ancestry;
- additional semantic/contradiction analysis when deterministic evidence is insufficient;
- rate limits and circuit breakers based on tool, tenant and principal risk.

Risk tier may add controls; it must never disable mandatory baseline controls.

### 9.3 Safe performance practices

- Index tenant ID, record ID, version, trust state, timestamps and graph traversal keys according to measured query plans.
- Bound graph depth, nodes, edges, fan-out, payload size, retries and queue length.
- Use batched database operations and transactions for logically atomic memory updates.
- Cache only decisions whose invalidation and freshness rules are explicit.
- Invalidate authorization/trust caches on membership, policy, quarantine, revocation and key changes.
- Use Redis atomic scripts/operations for distributed rate limits and locks.
- Keep slow LLM analysis and human review off the routine deterministic authorization path.
- Use asynchronous processing for non-blocking enrichment, but never execute a protected action before mandatory synchronous gates pass.
- Maintain separate SLOs for authorization latency, memory retrieval, deep forensics and recovery.
- Benchmark p50/p95/p99 latency, throughput, benign task success, false blocks, attack success and severity-weighted harm.

## 10. Evaluation methodology: how AMSC proves its claims

Every security feature must have a testable threat model and an independent outcome oracle.

### 10.1 Memory poisoning lifecycle matrix

Test:
- direct memory write;
- query-only injection (MINJA-style);
- rewritten/extracted memory;
- multi-record compositional poisoning;
- dormant trigger-based poisoning;
- forged reasoning/rationale memory;
- narrative authority spoofing;
- stale/superseded memory;
- cross-tenant and cross-agent propagation;
- poisoning of derived summaries and embeddings.

Track:
- injection/persistence rate;
- retrieval rate;
- harmful influence rate;
- unauthorized action rate;
- severity-weighted impact;
- time to detection;
- selective repair success;
- benign task success and false-positive rate.

### 10.2 Tool execution matrix

Test:
- direct and indirect prompt injection;
- untrusted tool output;
- confused deputy and delegated authority escalation;
- unauthorized destination/resource;
- data exfiltration;
- replay/duplicate action;
- forged tool result;
- action hallucination (agent claims success without actual effect);
- partial failure and timeout;
- sandbox escape/side-effect boundary;
- approval expiry and reviewer denial.

Track:
- attack success rate;
- actual side-effect success;
- policy false allow/block;
- task completion on benign cases;
- approval latency and expiry;
- p50/p95/p99 decision latency;
- severity-weighted harm.

### 10.3 Reproducibility rules

- Keep attack families separated between development and held-out evaluation.
- Prevent test leakage from detector rules or training data.
- Include benign hard negatives and multilingual/obfuscated cases.
- Use deterministic seeds where possible and report variance/confidence intervals.
- Distinguish simulated agents from real model evaluations.
- Distinguish model output judgments from external state-based oracles.
- Record model/provider/version, prompts, policy version, dataset version, configuration and commit SHA.
- Never grade a detector using labels generated by that same detector.
- Report both security and utility. A system that blocks every request is not a successful secure agent platform.

## 11. Team ownership and mandatory integration points

| Team | Ownership | Research-derived responsibilities |
|---|---|---|
| M1 — Platform | Authentication, JWT, TenantContext, shared API | User/agent/service identity context, delegation context, secure request boundaries, session and token lifecycle |
| M2 — Runtime | Agent runtime, tool adapters, gateway | Tool interception, least privilege, execution receipts, sandbox boundary, delegation attenuation, context/execution trace |
| M3 — Memory | Memory models, versions, hashing, provenance, memory services | Immutable versions, source/derivation lineage, trust-aware retrieval, bounded graph traversal, integrity evidence |
| M4 — Security | Policy, RBAC, trust engine, threat detection, quarantine/recovery | Deterministic ALLOW/REVIEW/BLOCK, trust transitions, action authorization, incident/rewind approval, forensic access |
| M5 — Frontend | React UI and API integration | Explainable evidence, Dual Trace, impact preview, safe operator confirmations; frontend never enforces security by itself |
| M6 — Database | PostgreSQL models, sessions, repositories, migrations | Tenant constraints/RLS, transactions, uniqueness/concurrency, append-only evidence, indexes, encryption integration |
| M7 — Infrastructure | Redis, test harness, CI/CD, DevOps | Distributed limits, secrets/KMS integration, SBOM/scanning, reproducible security tests, observability pipeline |

No team may bypass another team's ownership by implementing a competing copy. Integration contracts must be agreed and tested.

## 12. Recommended research and implementation priorities

### P0 — Before external-company or production use
- Verify tenant isolation at API, service and database boundaries.
- Enforce complete mediation and deterministic action authorization.
- Ensure quarantined/rejected memory cannot reach normal agent retrieval or justify actions.
- Verify source/agent ownership and authorization continuity through derivations.
- Preserve immutable versions and reliable provenance.
- Prevent credentials from reaching agents or logs.
- Add idempotency/replay protection and actual execution verification.
- Establish durable audit evidence and tested recovery boundaries.
- Add cross-tenant, poisoning-lifecycle and tool-side-effect regression tests.

### P1 — Before advanced memory and autonomous action capabilities
- Add derivation-aware trust propagation.
- Add explicit freshness, authority and conflict resolution.
- Add signed memory evidence/checkpoints where the threat model warrants it.
- Add Dual Trace correlation between exact memory versions and action effects.
- Add selective recovery with downstream invalidation and counterfactual tests.
- Add AgentDojo-style tool injection and memory poisoning evaluation.
- Add least-privilege delegation and action-specific approval.

### P2 — Enterprise hardening
- KMS-backed key rotation and envelope encryption.
- PostgreSQL RLS and stronger tenant-scoped constraints after M6 review.
- On-demand sandboxing for selected high-risk actions.
- SBOM, dependency/container scanning, artifact signing and build provenance.
- Formal policy tests, fuzzing and continuous red-team regression.
- Advanced memory influence decomposition and benchmark harness.

### P3 — Research extensions
- Multimodal temporal memory.
- More advanced Merkle proofs and cross-system evidence exchange.
- Automated recovery-point recommendation with human-authorized commit.
- Adaptive verification budgets and risk-aware lineage expansion.
- Cross-company governed knowledge exchange.

These priorities are a proposed roadmap, not permission to change the current sprint or team assignments. Architecture review is required before introducing new infrastructure or dependencies.

## 13. Research register and source links

The following sources are the initial selected register. The team must update status, version, venue, code/data availability, license and limitations as research matures.

| ID | Work | Type/status | AMSC use |
|---|---|---|---|
| R-001 | ChronoMem — Version Control and Semantic Rollback, arXiv:2607.27773 | Preprint | Memory snapshots, semantic rollback, post-exposure evaluation |
| R-002 | AgentRewind, arXiv:2608.14380 | Preprint | Aligned context/environment recovery |
| R-003 | Rollback the World, Keep the Reflection, arXiv:2609.18304 | Preprint | Recovery boundary and retained reflection |
| R-004 | Temporal Multimodal Memory Banks, ICCV 2025 Workshop | Workshop paper | Temporal episodic memory research |
| R-005 | MINJA, NeurIPS 2025 | Peer-reviewed | Query-only memory poisoning |
| R-006 | From Untrusted Input to Trusted Memory, arXiv:2606.04329 | Preprint | Poisoning channels and MPBench |
| R-007 | MemPoison, arXiv:2607.14651 | Preprint | L1/L2/L3 poisoning and adaptive defense |
| R-008 | MemLineage, arXiv:2605.14421 | Preprint | Cryptographic provenance and derivation lineage |
| R-009 | MemSecBench, arXiv:2607.27080 | Preprint/benchmark | Persistence-to-consequence-to-repair evaluation |
| R-010 | Forged Reasoning Attacks, arXiv:2607.05029 | Preprint | Reasoning-trace memory poisoning |
| R-011 | Hijacking Agent Memory, arXiv:2605.29960 | Preprint | Conversational triggerable memory backdoors |
| R-012 | AkasicMEM, arXiv:2609.25563 | Preprint | Enterprise authorization continuity |
| R-013 | ToxicRAG, arXiv:2609.11082 | Preprint | Narrative single-document RAG poisoning |
| R-014 | Reliable Post-Retrieval Assembly for Agent Memory, arXiv:2606.01435 | Preprint | Separate evidence extraction from policy execution; current-value conflict handling when serial/version metadata exists |
| R-015 | When Memory Lies, arXiv:2608.04574 | Preprint | Stale memory vs current observation |
| R-016 | HaluMem: Evaluating Hallucinations in Memory Systems of Agents, EMNLP 2026 | Peer-reviewed benchmark paper | Memory extraction, updating and QA hallucination evaluation |
| R-017 | AgentDojo, NeurIPS 2024 | Peer-reviewed benchmark | Tool-output prompt injection |
| R-018 | Securing Tool-Using AI Agents Against Injection and Authority Misuse, Computation 2026 | Published research; simulation-based | Least privilege, allowlisting, verification, approvals, trade-offs |
| R-019 | Runtime Protection Practice, IEEE 2026 | Conference paper | On-demand behavioral sandbox |
| R-020 | Runtime Policy Enforcement for MCP-Based LLM Agents, Electronics 2026 | Published research | Tool-boundary PEP and information-flow labels |
| R-021 | Drawing on Memory: Dual-Trace Encoding Improves Cross-Session Recall, arXiv:2604.12948 | Preprint | Fact-plus-contextual-trace memory encoding; distinct from AMSC's execution/memory observability Dual Trace |
| R-022 | TrustMem: Learning Trustworthy Memory Consolidation, Findings of EMNLP 2026 | Peer-reviewed findings paper | Transition-level coverage, preservation and faithfulness checks |
| R-023 | MemBook: A Hierarchical Reasoning-based Memory Framework, Findings of EMNLP 2026 | Peer-reviewed findings paper | Hierarchical temporal/logical memory retrieval; evaluate as optional retrieval layer |
| R-024 | AgentHallu: Benchmarking Automated Hallucination Attribution, EMNLP 2026 | Peer-reviewed main-conference paper | Candidate attribution of hallucination origins across agent trajectories |

### Standards and implementation guidance

- OWASP Top 10 for Agentic Applications 2026: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP AI Agent Security Cheat Sheet: https://cheatsheetseries.owasp.org/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- IETF RFC 8725 (JWT Best Current Practices): https://www.rfc-editor.org/rfc/rfc8725
- NIST SP 800-207 (Zero Trust Architecture): https://csrc.nist.gov/pubs/sp/800/207/final
- OpenTelemetry GenAI semantic conventions: https://opentelemetry.io/docs/specs/semconv/gen-ai/

## 14. Research governance: how this document stays useful

For every new paper proposed by any team member, add a research entry containing:

1. Full title, authors, publication date, venue and persistent URL/DOI.
2. Publication status: peer-reviewed, preprint, benchmark, standard or vendor material.
3. Direct relevance to an AMSC requirement or threat.
4. Main method and what evidence supports it.
5. Threat model and assumptions.
6. Dataset/code availability and license.
7. Reported results with evaluation conditions.
8. Limitations, reproducibility concerns and possible conflicts of interest.
9. Proposed AMSC design implication.
10. Owner, milestone and acceptance test.

A paper does not become an implementation requirement merely because it is recent or has impressive results. The architecture owner must assess fit, threat model, cost, maintainability, compatibility and measurable benefit.

## 15. Mandatory instruction for all future implementation agents

Every Antigravity agent, subagent and human contributor must:

- Read this document and the relevant PRD/TRD/API/flow requirements before implementation.
- Preserve the non-regression rules in Section 2.
- Explain which research-backed design principle supports a significant security decision.
- Implement the principle in the correct team-owned component.
- Add tests that demonstrate the security property and a realistic bypass attempt.
- Measure benign utility and performance as well as attack resistance.
- Distinguish deterministic guarantees from heuristic/LLM-assisted signals.
- Avoid importing a paper's prototype limitations or copying paper-reported results as project claims.
- Document deviations and request an architecture decision before changing an invariant.
- Never claim a control is complete based only on a passing unit test; verify the end-to-end security boundary and actual side effect.

**Definition of done:** the feature meets the approved product/technical requirement, preserves all existing security invariants, has an explicit threat model, is tested against both attack and benign cases, has measurable performance impact, and is documented with its owner and evidence.

---

## Appendix A — Source repositories

- ChronoCongiSec / AMSC: https://github.com/9m2usman/ChronoCongiSec
- KnowledgeLine: https://github.com/9m2usman/KnowledgeLine
- Agent Security Guard / AgentGuard: https://github.com/HafizShamaz/agent-security

## Appendix B — Important naming distinction

AMSC's existing **ChroniMem** product feature and the research papers named **ChronoMem** are related by topic but are not the same implementation. The 2025 ICCV workshop paper is about temporal multimodal memory banks; the 2026 arXiv paper is about semantic version control and rollback. Cite and discuss them separately.
