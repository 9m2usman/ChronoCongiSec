# Known Limitations

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
