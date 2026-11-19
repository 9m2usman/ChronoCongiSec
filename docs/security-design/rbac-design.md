# M4 Day 2 — Basic RBAC Evaluator: Design

**Document ID:** AMSC-SEC-002
**Owner:** M4 — Security Engine & Incident Response Lead
**Status:** Implemented and tested in M4-owned code. Integration into M1's `require_roles()` is **pending M1 approval** (§12).
**Date:** 2026-11-17
**Plan reference:** `docs/06-TEAM-IMPLEMENTATION-PLAN.md` §3 Day 2, M4 row — *"Implement basic RBAC check (`TENANT_ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`)"* → *RBAC evaluator*; dependency *M1 Auth context*; exit *Unauthorized roles rejected with 403*.
**Related:** [`policy-evaluation-matrix.md`](policy-evaluation-matrix.md) (Day 1) — RBAC implements stage S4 (POL-PRN-01) for human callers.

| Artifact | Path |
|---|---|
| Evaluator | `backend/app/security/authorization.py` |
| Unit tests | `backend/tests/security/test_rbac_evaluator.py` |
| HTTP integration tests | `backend/tests/security/test_rbac_integration.py` |

---

## 1. Purpose

RBAC answers one question: *may this authenticated member, in this tenant, perform this class of operation?* It is enforced on the backend for every protected request. Frontend role hiding is cosmetic and never a control (Doc 06 M5 constraint; OWASP Top 10 2025 A01).

RBAC is **one layer**. The following remain separate controls, and RBAC does not replace any of them:

- object-level ownership checks (OWASP API1:2023 BOLA)
- tenant isolation in queries and constraints (M1/M6)
- memory trust gating
- the deterministic policy engine
- protected-tool authorisation

---

## 2. Day 2 roles

| Role | Intended scope (Doc 02 §11, Doc 05 §5.1) |
|---|---|
| `TENANT_ADMIN` | Users, agents, tools and policies **within one tenant** |
| `SECURITY_ANALYST` | Triage, quarantine, trace correlation, recovery |
| `DEVELOPER` | Agent configuration, ingestion, proposal submission |

**No hierarchy is implemented.** `TENANT_ADMIN` does **not** implicitly satisfy a requirement for `SECURITY_ANALYST` or `DEVELOPER`. Each route must list every role it permits. No approved document defines a role hierarchy, and an implicit super-role contradicts least privilege (OWASP Authorization Cheat Sheet). `TENANT_ADMIN` never bypasses tenant isolation, memory trust or protected-action policy.

---

## 3. Role-name inconsistency (unresolved, needs owners' decision)

| Source | Role names used for the developer persona |
|---|---|
| Doc 06 Day 2 (M4 task) | `DEVELOPER` |
| Doc 01 PRD FR-003, Doc 02 TRD §11, Doc 04 UI, Doc 05 `memberships.role` comment and route catalogue | `AI_DEVELOPER` |
| M6 ORM / migration 0001 | `role` is free text (`VARCHAR(64)`, default `SECURITY_ANALYST`); no CHECK constraint or enum |
| M1 demo seed on `main` (`tenancy/context.py`) | Only `SECURITY_ANALYST` and `TENANT_ADMIN` |
| M1 branch `feat/m1-day4-protected-gateway` (unmerged) | Seeds `AI_DEVELOPER` memberships; `api/agents.py` uses `require_roles("AI_DEVELOPER")` |
| **Any source using `DEVELOPER`** | Only Doc 06 Day 2 |

Other roles in the documents: `AUDITOR` (Doc 01/02/04/05) and `PLATFORM_ADMIN` (Doc 02 only).

**What M1's context actually returns:** `TenantContext.role` is the `role` string from the membership repository row (`resolve_tenant_context_from_request` → `membership.role`), passed through unchanged. The JWT `role` claim is **not** used for authorisation. A test (`test_jwt_role_claim_cannot_escalate_privilege`) confirms this.

**Handling, as instructed for Day 2:**

- The evaluator recognises exactly `TENANT_ADMIN`, `SECURITY_ANALYST` and `DEVELOPER`.
- `AI_DEVELOPER`, `AUDITOR`, `PLATFORM_ADMIN` and every other value are **unrecognised and denied**.
- No alias was introduced and no schema was changed.

**Consequence:** under the vocabulary the PRD, TRD and DB documents call canonical, real developer accounts (`AI_DEVELOPER`) are denied by every route that uses this evaluator. This is fail-closed, but it blocks the developer persona.

**Decision needed (M1, M5, M6 per Doc 05 §8; Doc 06 owner):** choose one canonical value. If an alias is approved, it is a one-line change to the `Role` enum and `RECOGNIZED_ROLES`, plus a test. `AUDITOR` stays denied until its permissions are specified. It receives nothing simply because it appears in the schema.

---

## 4. Trusted context integration

```text
Request ──► M1 get_tenant_context()                      ──► M4 require_role_access(...)
            · Bearer JWT: signature, exp, iss, aud (M1)       · evaluate_role_access(ctx, policy)
            · user ACTIVE, tenant ACTIVE                      · ALLOW → handler receives ctx
            · membership ACTIVE in token's tenant             · DENY  → ForbiddenError (403)
            · X-Tenant-ID must equal token tenant
            · role := membership.role (repository)
            401 / 403 / 503 raised here, before RBAC
```

- **Input.** The only input is M1's immutable, request-scoped `TenantContext`. The evaluator makes no database queries; M1 has already re-verified the membership.
- **Ignored sources.** Role or tenant values in the request body, query string, arbitrary headers, JWT claims or agent metadata are never read. Tests send `X-Role`, `?role=`, `?tenant_id=` and JSON bodies, and all of them are ignored.
- **Not a parallel system.** `require_role_access` depends on M1's `get_tenant_context`. There is no second authentication or tenant mechanism. This "additional route dependency" integration is the one `backend/owner.md` §2.C describes.

---

## 5. Decision process

`evaluate_role_access(context, allowed_roles, *, expected_tenant_id=None)` is a **total function**: it never raises, and every path except the last returns DENY.

| # | Check | Deny reason |
|---|---|---|
| 1 | Policy present: a non-empty collection, not a bare string | `POLICY_MISSING` |
| 2 | Every policy entry is exactly a recognised role | `POLICY_INVALID` |
| 3 | Context present | `CONTEXT_MISSING` |
| 4 | Context is a real `TenantContext`; duck-typed objects are rejected | `CONTEXT_INVALID` |
| 5 | `is_active is True`; truthy values such as `1` or `"true"` are rejected | `CONTEXT_INACTIVE` |
| 6 | `tenant_id` is a non-blank `str` | `TENANT_MISSING` |
| 7 | `user_id` is a non-blank `str` | `USER_MISSING` |
| 8 | If `expected_tenant_id` is given, it equals `tenant_id` exactly | `TENANT_MISMATCH` |
| 9 | Role present | `ROLE_MISSING` |
| 10 | Role is exactly `str` or `Role` (`str` subclasses rejected), upper snake case, ≤ 64 characters, checked with `fullmatch` | `ROLE_MALFORMED` |
| 11 | Role is one of the 3 recognised roles; exact match only, with no case folding, trimming or aliasing | `ROLE_UNRECOGNIZED` |
| 12 | Role is in the allowed set | `ROLE_NOT_PERMITTED` |
| — | Any exception | `EVALUATION_ERROR` |
| ✓ | All checks pass | `ROLE_PERMITTED` (ALLOW) |

Further properties:

- **Enforcement wrapper.** `authorize()` raises M1's `ForbiddenError` on DENY. The reason code goes only to the server log, and the client receives M1's allowlisted `FORBIDDEN_ACTION` message with `details: null`.
- **Early configuration failure.** `require_role_access()` validates the policy **when the route is defined**. An empty or misspelled role list (for example `require_role_access()` or `require_role_access("AI_DEVELOPER")`) raises `AuthorizationPolicyError` at application start-up instead of failing at runtime.
- **No hidden state.** There is no mutable module state, and decisions are not cached.

---

## 6. Default deny

| Situation | Result |
|---|---|
| Absent or empty policy | DENY (never "everyone") |
| Unknown, unsupported, malformed or missing role | DENY |
| Missing, inactive or incomplete context | DENY |
| Evaluator exception | DENY |
| Dependency (auth repository) failure | M1 raises `SECURITY_DEPENDENCY_UNAVAILABLE` (503); the handler never runs |
| No wildcard, no implicit admin, no hierarchy | — |

This contrasts with M1's existing `require_roles()` in `core/dependencies.py:108-122`. That function:

- **allows every role when called with no arguments** (`if allowed_roles and context.role not in allowed_roles`);
- doesn't check `is_active`;
- accepts any string, so unknown roles pass if they are listed.

It is not used by any route on `main` today, but it is used on M1's unmerged Day 3/4 branches. The fix is in §12.

---

## 7. Tenant isolation

1. Tenant identity comes only from `TenantContext`, which M1 derives from the verified token plus active membership.
2. A client `X-Tenant-ID` that differs from the token's tenant is rejected with 403 `TENANT_ACCESS_FORBIDDEN` by M1, before RBAC runs. This behaviour is preserved and tested.
3. A role is per membership, so it is per tenant. A user who is `TENANT_ADMIN` in A and `SECURITY_ANALYST` in B gets admin access only in A (tested).
4. A token naming a tenant where the user has no membership is rejected by M1 (tested).
5. For tenant-addressed resources, the caller passes `expected_tenant_id` from **server-side resource state**. A mismatch is denied even for `TENANT_ADMIN` (tested).
6. There is no global tenant state and no decision cache. A test runs 30 concurrent mixed-tenant requests and finds no context leakage.

---

## 8. HTTP 401 vs 403 vs 503

| Condition | Raised by | Status / code |
|---|---|---|
| Missing, malformed or invalid bearer token; bad signature; expired | M1 | 401 `AUTHENTICATION_FAILED` |
| Token tenant ≠ `X-Tenant-ID`; no, revoked or inactive membership; tenant suspended | M1 | 403 `TENANT_ACCESS_FORBIDDEN` |
| Authenticated, active member whose role is not permitted, unknown or malformed; tenant/resource mismatch | **M4** | 403 `FORBIDDEN_ACTION` |
| Auth repository unavailable | M1 | 503 `SECURITY_DEPENDENCY_UNAVAILABLE` |

A `None` context reaching the evaluator (a wiring error that bypasses M1) is denied with 403 rather than 401, because the client did nothing wrong that re-authentication would fix. M1's global exception handling is unchanged.

---

## 9. Assumptions and limitations

- **Only human members are covered.** M1 has not implemented agent API-key principals yet (Day 1 D-04). Agent proposals will be authorised by the policy engine, not by this evaluator alone.
- **Role checks, not permissions.** Day 2 checks role membership against a per-route allow-list. The Doc 05 `permissions` / `role_permissions` catalogue isn't populated yet. Moving to permission keys (e.g. `memory:quarantine`) is future work.
- **No branch dimension.** `TenantContext` and the M6 schema carry no branch (Day 1 D-09).
- **No routes on `main` use this evaluator yet.** M4's own routes (`api/security.py`, `api/incidents.py`, `api/recovery.py`) arrive on later plan days, and wiring other members' routes is their decision.
- **Accuracy depends on the membership store.** RBAC is only as correct as M1's membership re-verification and M6's membership data. Membership revocation takes effect on the next request; there is no JWT revocation list yet (Doc 08 GAP-007).

---

## 10. Test coverage and verification

All results below were executed on 2026-11-17 with Python 3.14.5 and the pinned `requirements.txt` (`asyncpg` excluded; see §12), on branch `feat/m4-security-ml` merged with `origin/main` @ `b7d68d9`.

| Suite | Result |
|---|---|
| `backend/tests/security/test_rbac_evaluator.py` + `test_rbac_integration.py` | **113 passed** |
| Full suite excluding `backend/tests/database` | **287 passed** (174 pre-existing + 113 new); no existing test modified |
| `backend/tests/database` (M6) | **Not run.** Needs `asyncpg` (no Python 3.14 build) and a PostgreSQL server |
| Mutation check | Three injected regressions were each caught: empty policy → allow (4 failures), skipped `is_active` (5), case-insensitive role match (6) |

Coverage by required area:
- **A. Valid roles:** each Day 2 role allowed only when listed; no implicit admin.
- **B. Invalid roles:** `AI_DEVELOPER`, `AUDITOR`, `PLATFORM_ADMIN`, empty, `None`, lower or mixed case, padded, trailing newline, comma lists, `*`, overlong, Cyrillic homoglyph, int, list, dict, bytes, bool, and a `str` subclass whose `__eq__` always returns `True`.
- **C. Context:** missing, duck-typed, inactive or non-boolean active flag, blank or non-string tenant and user ids.
- **D. Tenant isolation:** per-tenant roles, no membership in the token's tenant, header override, cross-tenant resource, concurrent requests.
- **E. Authentication integration:** permitted → 200; unauthorised → 403 with no leakage of reason codes or secrets; missing or invalid token → 401; wrong signing secret → 401; revoked or inactive membership → 403; JWT role-claim escalation → 403.
- **F. Fail-closed:** repository outage or timeout → 503; evaluator fault → 403; missing policy → start-up error or deny.

The **Day 2 exit criterion** (*unauthorized roles rejected with HTTP 403*) is demonstrated end-to-end through M1's real authentication path on test routes. It is **not yet wired into production routes**.

---

## 11. Research basis

| Source | Version / status (checked 2026-11-17) | Applied as |
|---|---|---|
| NIST RBAC model, ANSI/INCITS 359-2004, revised 359-2012 | Standard. NIST's RBAC project page is marked archived, and ANSI listings disagree on the current status (reaffirmed R2022 vs "historical"). Cited for the model, not as current certification. | Users → roles → permissions separation; role assignment held by an authority (the membership store), not the user |
| NIST SP 800-207 Zero Trust Architecture (Aug 2020) | Final standard | Authorisation evaluated per request from verified identity; no implicit trust from network or session |
| OWASP Authorization Cheat Sheet | Living document (undated) | Deny by default, least privilege, validate on every request, prefer explicit configuration over framework defaults |
| OWASP ASVS 5.0.0 (released 30 May 2025) | Latest stable. 5.0 renumbered the requirements; I didn't verify individual V8 requirement ids from the official text. | Documented authorisation rules; function- and data-level checks |
| OWASP API Security Top 10 2023: API1 BOLA, API5 BFLA | Current edition | API5 → role check on every function. API1 → `expected_tenant_id` object guard; RBAC alone doesn't solve BOLA. |
| OWASP Top 10 2025 A01 Broken Access Control | Current edition | Server-side enforcement; deny except for public resources |
| CWE-862 Missing Authorization; CWE-863 Incorrect Authorization (MITRE) | Current entries (CWE-862 #4 in the 2025 CWE Top 25) | Start-up failure for empty policies (862); exact matching, no aliasing, no deny-lists (863) |

No LLM or ML output takes part in any authorisation decision. The evaluator is pure and deterministic (Doc 07 §2.7).

---

## 12. Remaining integration items and risks

| ID | Owner | Item |
|---|---|---|
| R-1 | M1, M5, M6, plan owner | **Role vocabulary.** `DEVELOPER` (Doc 06) vs `AI_DEVELOPER` (PRD, TRD, Doc 05, M1 branch). Until decided, `AI_DEVELOPER` members are denied by this evaluator. |
| R-2 | M1 | **Delegate `require_roles()` to the M4 evaluator** so there is one RBAC path. Proposed change below; **not applied** because `core/` is M1-owned. |
| R-3 | M1 | `feat/m1-day4-protected-gateway` authorises proposals with a **deny-list** (`UNAUTHORIZED_PROPOSAL_ROLES = {"AUDITOR","READ_ONLY","GUEST"}`), so unknown roles are allowed. This is CWE-863 default-allow. It also places proposal authorisation in `api/gateway.py`, which `ownership.md` assigns to M2, with policy decisions owned by M4. It should use an allow-list via this evaluator and the Day 1 policy engine. |
| R-4 | M1, M7 | `asyncpg==0.29.0` won't build on Python 3.14.5 (TRD approves 3.14.x), so M6's DB test suite can't run in this environment. |
| R-5 | M6 | Consider a CHECK constraint or reference table for `memberships.role` once the vocabulary is decided, so malformed roles can't be stored. Requirement only; no migration authored. |
| R-6 | M1 | Agent principals and the permission catalogue (Day 1 D-04) for moving beyond role checks |

**Proposed M1 change (R-2), for M1 to review and apply.** It uses a lazy import to avoid a circular import:

```python
# backend/app/core/dependencies.py
def require_roles(*allowed_roles: str) -> Callable[[TenantContext], TenantContext]:
    """Delegates to M4's default-deny RBAC evaluator (backend.app.security.authorization)."""
    from backend.app.security.authorization import require_role_access
    return require_role_access(*allowed_roles)
```

Effects:
- `require_roles()` with no roles now fails at start-up instead of allowing everyone.
- Unknown roles in a route definition fail at start-up. **`require_roles("AI_DEVELOPER")` on M1's branch would refuse to start until R-1 is resolved.** That is intentional, so the vocabulary conflict surfaces rather than silently denying developers.
- The existing `test_role_enforcement_boundary` (`TENANT_ADMIN` route) keeps passing unchanged.

**Verified without editing M1's file.** I applied the delegation in memory through a scratch pytest plugin:
- all 16 tests in `backend/tests/unit/test_tenancy.py` pass;
- `require_roles()` and `require_roles("AI_DEVELOPER")` both raise `AuthorizationPolicyError` at definition time.
