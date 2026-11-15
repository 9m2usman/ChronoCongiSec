
# Backend Ownership

**Platform coordinator:** M1

| Module | Owner |
|---|---|
| core/ | M1 |
| api/auth.py | M1 |
| api/tenants.py | M1 |
| api/agents.py | M1 |
| gateway/ | M2 |
| api/gateway.py | M2 |
| memory/ | M3 |
| knowledge/ | M3 |
| api/memory.py | M3 |
| api/chronimem.py | M3 |
| security/ | M4 |
| recovery/ | M4 |
| api/security.py | M4 |
| api/incidents.py | M4 |
| api/recovery.py | M4 |
| database/ | M6 |
| alembic/ | M6 |
| workers/ | M7 coordinates infrastructure |

## Rules

- M1 maintains API conventions and integration.
- Subsystem owners implement their own business logic.
- M4 owns mandatory security decisions.
- M6 exclusively edits database migrations.
- M7 coordinates backend test infrastructure.
- All members write tests for their own code.
