# ChronoCongiSec (Agent Memory Security Center) — Local Development & Verification Guide

This guide explains how to clone, configure, run, and test the current ChronoCongiSec repository on Windows using PowerShell. It describes the implementation that exists in the repository today; it does not claim that every service is production-wired.

## 1. Project overview

ChronoCongiSec is the repository name for the Agent Memory Security Center (AMSC), a research-driven platform for AI-agent memory security, governance, observability, and recovery.

The repository contains:
- **Backend:** FastAPI application, authentication and tenant context, protected gateway, memory and provenance services, security workflows, API routes, and database infrastructure.
- **Frontend:** React, TypeScript, Vite, TanStack Query, and Zustand workstation.
- **Database infrastructure:** PostgreSQL schema and Alembic migrations, with database integration tests.
- **Local infrastructure:** Docker Compose definitions for PostgreSQL 16 and Redis 7.

The current development application initializes in-memory demo repositories for several services. A configured PostgreSQL URL does not, by itself, switch every API service to database-backed persistence. See [Current implementation boundaries](#14-current-implementation-boundaries).

## 2. Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.12 recommended; 3.11 minimum | Backend and tests |
| Node.js | 20 LTS recommended | Frontend tooling |
| npm | Bundled with Node.js 20 | Frontend dependencies |
| Git | 2.30 or newer | Source control |
| Docker Desktop | Optional | PostgreSQL and Redis containers |

Verify the installations:

```powershell
python --version
node --version
npm --version
git --version
docker --version
docker compose version
```

Docker is only required for the PostgreSQL-backed migration and database-test steps. The local in-memory demo application does not require PostgreSQL or Redis.

## 3. Clone the repository

Run these commands from the directory where you keep your projects:

```powershell
git clone https://github.com/9m2usman/ChronoCongiSec.git
Set-Location .\ChronoCongiSec
```

If you already have the repository cloned, open PowerShell in that repository directory instead.

Confirm that you are at the repository root:

```powershell
git status --short --branch
Get-ChildItem
```

The root should contain `backend`, `frontend`, `docs`, `docker-compose.yml`, `pyproject.toml`, and `backend\requirements.txt`.

## 4. Create the local environment file

From the repository root:

```powershell
Copy-Item .env.example .env
```

The checked-in `.env.example` contains local-development settings only. The application generates a random JWT secret when `JWT_SECRET` is empty in development/test mode. Do not commit `.env`, and never use the example database password or development settings in production.

The principal local settings are:

| Variable | Local value | Purpose |
|---|---|---|
| `APP_ENV` | `development` | Enables local development behavior |
| `AUTH_BACKEND` | `in_memory_demo` | Uses the seeded in-memory demo authentication repository |
| `ALLOW_IN_MEMORY_AUTH` | `true` | Allows demo authentication outside production |
| `RATE_LIMITER_BACKEND` | `in_memory` | Uses the local in-memory rate limiter |
| `ALLOW_IN_MEMORY_RATE_LIMITER` | `true` | Allows the local rate limiter outside production |
| `JWT_SECRET` | Empty | Generates a random development/test secret at startup |
| `DATABASE_URL` | Local PostgreSQL URL | Used by database/migration tooling |
| `REDIS_URL` | Local Redis URL | Connection setting for components that are configured to use Redis |

Do not change `APP_ENV` to `production` to test the local demo. Production startup deliberately rejects in-memory repositories and requires persistent services to be explicitly wired.

## 5. Install backend dependencies

From the repository root, create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, allow scripts for the current terminal only and activate again:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1
```

Install the pinned backend dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The root `requirements.txt` delegates to `backend/requirements.txt`. Keep the backend dependency pins in that single authoritative file to avoid two manifests drifting apart.

## 6. Run the backend

From the repository root, with the virtual environment active:

```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend should start at:

- API base: `http://127.0.0.1:8000`
- Liveness: `http://127.0.0.1:8000/health`
- Readiness: `http://127.0.0.1:8000/ready`
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- OpenAPI JSON: `http://127.0.0.1:8000/openapi.json`

The readiness route is `/ready`; it is not `/api/v1/health/readiness`.

You can verify liveness from another PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/ready
```

A successful liveness response confirms that the process responds. Readiness also checks the development dependencies attached by the application factory.

## 7. Demo authentication

The current development authentication repository is seeded in `backend/app/tenancy/context.py`.

Use this local demo account with the login endpoint:

| Field | Value |
|---|---|
| Email | `analyst@company-a.com` |
| Password | `SecurePassword123!` |
| Tenant slug | `company-a` |

The login request is sent to `POST /api/v1/auth/login` with JSON fields `email`, `password`, and `tenant_slug`.

These are public demo credentials for local development only. Do not reuse them for a real deployment.

## 8. PostgreSQL migrations and database tests (optional)

The Docker Compose file defines a local PostgreSQL 16 service. Start it from the repository root:

```powershell
docker compose up -d postgres
docker compose ps
```

The development database URL in `.env.example` matches the Compose service credentials:

```text
postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/amsc
```

Apply the Alembic migrations from the repository root:

```powershell
alembic -c backend/alembic.ini upgrade head
```

The database integration tests use a separate, explicitly configured `TEST_DATABASE_URL`. They intentionally do not fall back to `DATABASE_URL`, because they create and drop temporary test databases. The local Docker Compose PostgreSQL user has the privileges required by the test harness.

Set the test connection to the maintenance database (not the application database):

```powershell
$env:TEST_DATABASE_URL = "postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/postgres"
```

Then run the database tests:

```powershell
python -m pytest backend/tests/database -v
```

The test harness creates uniquely named `amsc_test_*` databases and removes only those databases. Do not point `TEST_DATABASE_URL` at a production server or production database.

**Database seeding note:** `backend/app/database/seed.py` currently exposes an asynchronous `seed_database(session)` function; it does not provide a `python -m backend.app.database.seed` command-line entry point. Do not run that module as a CLI command.

## 9. Install and run the frontend

Open a second PowerShell terminal and navigate to the frontend directory:

```powershell
Set-Location .\frontend
npm ci
npm run dev
```

Vite serves the workstation at:

`http://localhost:5173`

The Vite configuration proxies `/api` and `/health` requests to the backend at `http://127.0.0.1:8000`. If you change the backend port, update the proxy target in `frontend/vite.config.ts`.

To create a production frontend bundle:

```powershell
npm run build
```

To run the frontend test suite:

```powershell
npm test
```

## 10. Run backend tests

From the repository root, with the virtual environment active, run the same primary backend test paths used by the repository CI workflow:

```powershell
python -m pytest backend/tests/security backend/tests/unit backend/app/memory/tests -v --durations=10
```

The knowledge tests are in a separate directory:

```powershell
python -m pytest backend/app/knowledge/tests -v
```

The PostgreSQL-specific tests are separate and require the `TEST_DATABASE_URL` setup in Section 8:

```powershell
python -m pytest backend/tests/database -v
```

Do not rely on a previously documented fixed test count. The number of collected tests can change as the project evolves; use the actual pytest summary from your run.

## 11. Run the full local verification sequence

After starting PostgreSQL and setting `TEST_DATABASE_URL` (if you intend to run database tests), the following sequence verifies the principal backend, frontend, and database paths:

```powershell
# Backend unit, security, and memory tests
python -m pytest backend/tests/security backend/tests/unit backend/app/memory/tests -v --durations=10

# Knowledge tests
python -m pytest backend/app/knowledge/tests -v

# PostgreSQL migration/integration tests (requires TEST_DATABASE_URL)
python -m pytest backend/tests/database -v

# Frontend tests and production build
Set-Location .\frontend
npm ci
npm test
npm run build
```

Record the actual command output and test summary. A test suite that was not run, or could not connect to its required database, must be reported as skipped or blocked—not as passed.

## 12. Docker services

Start PostgreSQL only when you need migrations or PostgreSQL-backed tests:

```powershell
docker compose up -d postgres
```

Redis is also defined in `docker-compose.yml`:

```powershell
docker compose up -d redis
```

Starting the Redis container alone does not switch the current development application to a Redis-backed rate limiter. The local application factory initializes its in-memory rate limiter in development/test mode. Do not describe Redis as active in the application unless a Redis-backed implementation has actually been configured and attached.

## 13. Common troubleshooting

### PowerShell cannot activate the virtual environment

Run this in the current terminal, then activate again:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1
```

### Port 8000 or 5173 is already in use

Inspect the process using the port:

```powershell
Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, OwningProcess

Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, OwningProcess
```

Stop a process only after confirming its PID and that it is safe to stop:

```powershell
Stop-Process -Id <PID>
```

### PostgreSQL connection fails

Check that the container is running and healthy:

```powershell
docker compose ps
docker compose logs postgres
```

Confirm that `DATABASE_URL` uses the local Compose credentials and that PostgreSQL is listening on port 5432.

### Database tests reject the connection string

Set `TEST_DATABASE_URL` to the local maintenance database named `postgres`, as shown in Section 8. Do not use the application database name `amsc` for the test harness.

### Frontend cannot reach the API

Confirm that the backend is running on port 8000 and that `frontend/vite.config.ts` points to the correct backend address.

## 14. Current implementation boundaries

These details describe the current repository implementation and prevent the local guide from overstating runtime capabilities:

- The development application factory initializes in-memory repositories for authentication fallback, memory, agents, gateway, incidents, traces, and rate limiting.
- PostgreSQL models, migrations, and database repositories exist, but setting `DATABASE_URL` alone does not attach every database-backed repository to the running application. Production startup requires persistent repositories and a Redis-backed rate limiter to be explicitly configured; it fails closed when those dependencies are absent.
- The database seed module is an asynchronous function, not a standalone CLI.
- Redis is available as a Compose service, but the development application factory currently selects the in-memory rate limiter.
- The frontend dev server proxies API and liveness requests to the local backend. It does not itself establish production deployment, event streaming, or persistent storage.

Treat the approved architecture and implementation gap register as authoritative for feature status. Do not present a placeholder, fixture, or unavailable integration as a completed production capability.

## 15. Shutdown

Stop the backend and frontend terminals with `Ctrl+C`.

Stop optional Docker services from the repository root:

```powershell
docker compose down
```

To also remove the local PostgreSQL data volume, use `docker compose down -v` only if you intentionally want to delete the local database contents.
