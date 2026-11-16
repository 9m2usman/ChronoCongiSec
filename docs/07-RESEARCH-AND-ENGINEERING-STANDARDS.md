# AMSC Document 07 — Research & Engineering Standards
### Authoritative Security, Cryptographic & Architecture Standards Baseline

**Document Identifier:** AMSC-DOC-007  
**Status:** Canonical Authority  
**Applies to:** All Modules (M1 through M7)  

---

## 1. Executive Summary & Purpose

This document serves as the binding research and non-regression authority for **ChronoCongiSec — Agent Memory Security Center (AMSC)**. It establishes authoritative principles, standards, and non-negotiable security invariants derived from peer-reviewed research, industry standards (OWASP, NIST, IETF), and enterprise security architectures.

No team member may weaken, bypass, or remove any security control defined in this document.

---

## 2. Foundational Security Frameworks

### 2.1 OWASP Top 10 for Agentic Applications (2026 Baseline)
AMSC provides architectural controls mitigating the primary threats to autonomous AI agent systems:

1. **ASI-01: Prompt Injection & Context Weaponization**
   - *Threat:* Malicious payloads embedded in retrieved documents manipulate agent goals.
   - *Control:* Complete mediation via Security Gateway (M2/M4); quarantined memories are strictly excluded from normal agent retrieval; heuristic and semantic pre-screening on ingestion.
2. **ASI-04: Broken Agent Authorization & Identity Spoofing**
   - *Threat:* Untrusted callers ingest or mutate memory pretending to be an authorized agent.
   - *Control:* Strict server-side verification that `agent_id` exists, belongs to the authenticated company, is `ACTIVE`, and matches caller permissions.
3. **ASI-06: Memory Poisoning & Knowledge Corruption**
   - *Threat:* Adversaries inject untrusted knowledge or alter historical records to steer future agent behavior.
   - *Control:* Canonical SHA-256 checksums, append-only immutable version histories, automatic trust invalidation on memory update (`UNVERIFIED`), and DAG provenance tracking.
4. **ASI-07: Insecure Tool Execution & Credential Exposure**
   - *Threat:* Agents execute high-impact tools with unconstrained parameters or leaked credentials.
   - *Control:* Server-side protected tool adapters; credentials never dispatched to agents; operational ceilings enforced.

### 2.2 NIST SP 800-207 Zero Trust Architecture
AMSC operates under strict Zero Trust tenets:
- **Complete Mediation:** All access requests to memory, tools, and configurations must be authenticated, authorized, and validated before granting access.
- **Fail-Safe Defaults (Fail-Closed):** All new memories default to `UNVERIFIED`. Normal agent retrieval returns ONLY `TRUSTED` memories. Any failure in rate limiting, authentication, or persistence halts processing rather than failing open.
- **No Implicit Trust:** Being within the enterprise network or part of the same company does not grant implicit access to restricted branch records.

### 2.3 IETF RFC 8725: JSON Web Token Best Current Practices
- **Algorithm Allowlisting:** Explicitly enforce `algorithm="HS256"`. Reject `none`, asymmetric substitution, or unexpected algorithm headers.
- **Claim Validation:** Mandate `iss` (`amsc-auth-service`), `aud` (`amsc-api-gateway`), `exp`, `iat`, `nbf`, `sub`, and `jti`.
- **Stateless Tokens with Stateful Revocation:** Access tokens have short lifetimes (<= 15 minutes in production); `jti` is checked against Redis denylist for logout and revocation.
- **No Blind Trust:** Token claims provide authenticated principal identity; current active status, company membership, and assigned roles must be verified against repository data on protected requests.

---

## 3. Cryptographic Provenance & Memory Integrity Standards

### 3.1 Canonical Content Hashing
To prevent subtle formatting variations from breaking content-addressable hash equality:
1. Normalize line endings: all `\r\n` must be converted to `\n`.
2. Strip trailing/leading whitespace deterministically before computing the digest, or hash the exact UTF-8 byte stream persisted to storage.
3. Use SHA-256 as the standard content checksum (`checksum = sha256_hex(content)`).

### 3.2 Immutability of Historical Versions
- Memory records are versioned entities. Version 1 is created on ingestion.
- Updating memory (`update_memory`) **NEVER** mutates or overwrites historical version content or checksums.
- Updates append a new `MemoryVersion` (`current_version + 1`) and transition `record.trust_state` to `UNVERIFIED`.
- Historical trust decisions, audit events, and checksums remain immutable for forensic non-repudiation.

### 3.3 Provenance DAG Integrity
- Lineage derivations are tracked via `ProvenanceEdge` records (`DERIVED_FROM`, `TRANSFORMED_INTO`, `SUPERSEDES`).
- Graphs must be strictly acyclic (DAG). Circular references must be rejected during ingestion.
- Traversal depth is hard-capped at 5 levels; total visited node budget is capped at 50 nodes globally per request to prevent algorithmic complexity DoS.
- Ingesting a record derived from a `QUARANTINED` or `REJECTED` parent is strictly prohibited (quarantine laundering prevention).

---

## 4. Single-Company Enterprise & Multi-Branch Architecture

### 4.1 Organizational Topology
AMSC is designed for an enterprise organization structured across operational branches:
```text
ONE ENTERPRISE (Company / Organization)
  ├── Head Office (Central Governance, Global Policies, Root Security Operations)
  ├── Branch Lahore (Operational Agents, Branch-Specific Knowledge)
  ├── Branch Karachi (Operational Agents, Branch-Specific Knowledge)
  ├── Branch Islamabad (Operational Agents, Branch-Specific Knowledge)
  └── Subordinate Regional Branches
```

### 4.2 Structural Architectural Invariants
1. **Branches are NOT Tenants:** Branches are subordinate operational units within the same legal entity. They share the enterprise's central governance, security policies, and incident response center.
2. **Internal Tenant Abstraction Preserved:** The root organization is mapped to `tenant_id` in database schemas and service protocols. This guarantees seamless future multi-organization SaaS capability without requiring database redesign.
3. **Single Active Organization Seeded:** The MVP environment seeds only ONE company. Multi-company demonstrations, external partner tenants, or global tenant switching are out of scope for the MVP.
4. **Explicit Branch Authorization:** While all branches belong to the company, records and agents can be branch-scoped. Access to branch-specific restricted memory requires explicit authorization.

---

## 5. Non-Negotiable Non-Regression Invariants

1. **Memory Retrieval Trust Invariant (GAP-001):** Normal agent retrieval returns ONLY eligible `TRUSTED` memories. `UNVERIFIED`, `SUSPICIOUS`, `QUARANTINED`, `REJECTED`, and `SUPERSEDED` states must never be returned to normal agents.
2. **Update Invalidation Invariant (GAP-002):** Updating a memory record invalidates its trust eligibility, setting `trust_state = UNVERIFIED` until M4 re-evaluates it.
3. **Identity Verification Invariant (GAP-003):** `agent_id` and `source_id` must be validated against the authenticated company and must be in `ACTIVE` status.
4. **Detail Trust Invariant (GAP-004):** Normal memory detail endpoints apply the exact same trust filter as list retrieval, returning HTTP 404 for non-TRUSTED records.
5. **Fail-Closed Production Boot:** In-memory authentication, in-memory rate limiting, and in-memory memory storage must abort production startup immediately with `RuntimeError`.
6. **Error Sanitization:** Stack traces, internal diagnostics, database credentials, and raw exception details must never be exposed to clients; public responses use strict allowlisted envelopes.
