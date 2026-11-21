# Known Limitations

## Integrated platform (status 2026-11-21)

1. Persistence in production depends on `app.state.db_session_factory`, which `create_app` does not create yet. Persistence-backed services therefore return 503 in production instead of silently using in-memory stores.
2. The M4 trust ledger has no durable store yet. Outside development/test, trust-dependent operations (gateway decisions with memory, quarantine, forensic access) refuse with 503.
3. Recovery is implemented as an M4 orchestrator over defined ports; the checkpoint reader, recovery-plan store and external-action reader are not implemented, so `/recovery/plans/*` returns 503 until they are wired.
4. The ChroniMem timeline contract differs between backend and frontend (see gap register OPEN-04).
5. The frontend falls back to clearly labelled fixtures ("CONTRACT FALLBACK") only when the API is unreachable; HTTP errors are shown as errors. Polling is not real-time streaming.
6. Forensic reads from the Security Center send a generated reason ("Security Center inspection of <id>"); a UI prompt for an analyst-entered justification is still to be added.
7. None of the 2026-11-21 changes were verified against PostgreSQL, Redis or Python 3.12 locally; CI is configured to run them.

## Initial gateway foundation

1. JSONL audit sink is local development and single-process only. It uses fsync and a hash chain, but has no multi-process coordination, external anchoring, trusted timestamps, WORM storage, or protection against an attacker rewriting the entire file and recomputing the chain.
2. Gateway receives an already authenticated AgentPrincipal. Authentication, token issuance, revocation, tenant membership, and agent identity resolution are not implemented.
3. Tool handlers are injected server-side. No HTTP endpoint, agent SDK, MCP transport, function-calling adapter, sandbox, or credential broker is included.
4. In-memory tool registry is not durable or tenant-aware.
5. MemoryEvidence is a typed input contract. Its trust state is not yet resolved from an authoritative database transaction; production code must load and validate the memory record in the same tenant-scoped transaction as authorization.
6. Tool output validation, output sensitivity labels, rate limits, human approval workflows, idempotency, and external side-effect compensation remain unimplemented.
7. If an adapter executes but the post-execution audit append fails, the outcome reports audit_complete=False; the external action may already have occurred and cannot be claimed to have been rolled back.
8. Unit tests have been authored but have not yet been executed.

## Donor repository risks

See INITIAL_REPOSITORY_AUDIT.md. Key issues include unsafe fallback secrets/configuration, wildcard CORS, startup schema mutation with warning-only failure handling, incomplete checkpoint hashing, and unverified cache/tenant boundaries.

## Research limitations

The bibliography is an initial verified source list, not a systematic review. Some sources are preprints. Benchmarks and reported metrics are source-specific and must not be represented as ChronoCongiSec results.
