# ChronoCogniSec (Agent Memory Security Center) — Local Execution Guide

This document provides complete, step-by-step instructions for setting up, installing dependencies, configuring environments, and executing the **ChronoCogniSec** (Agent Memory Security Center / AMSC) platform locally on **Windows** using **PowerShell**.

---

## 1. Project Overview

### What the Application Does
ChronoCogniSec (AMSC) is a research-driven AI Agent Security, Memory Governance, Observability, and Recovery platform. It protects enterprise LLM/agent deployments against:
- **Indirect Prompt Injection & Memory Poisoning** (untrusted knowledge ingested into agent memories).
- **Tool-Call Hijacking & Malicious Action Proposals** (enforcing fail-closed gate evaluation before tool execution).
- **Memory Tampering & Provenance Drift** (cryptographically verified append-only memory version trees with SHA-256 checksums).
- **Cross-Tenant Data Leakage** (strict logical tenant boundary enforcement across all APIs, storage layers, and traces).

### Major Components & Architecture
- **Backend API (`backend/`)**: FastAPI application exposing versioned REST APIs (`/api/v1`) for:
  - **Authentication & RBAC (`/api/v1/auth`)**: JWT-based session tokens with Argon2id password verification and multi-tenant organization scoping.
  - **Protected Gateway (`/api/v1/gateway`)**: Action proposal evaluation, memory trust checks (Gate G4), and policy enforcement.
  - **Knowledge & Memory Engine (`/api/v1/memory`)**: Ingestion, cryptographic checksum verification, trust state transitions, and provenance DAG tracking.
  - **ChroniMem & Knowledge Graph (`/api/v1/chronimem`, `/api/v1/knowledge`)**: Memory version evolution timeline, diff inspection, and topological relationship visualizer.
  - **Incident Quarantine (`/api/v1/incidents`, `/api/v1/memory/{id}/quarantine`)**: Security incident investigation, containment, and analyst-audited forensic retrieval.
  - **Dual Trace (`/api/v1/traces`)**: Request correlation, span hierarchy, execution grant recording, and telemetry redaction.
- **Frontend Workstation (`frontend/`)**: React 19 single-page application built with TypeScript, Vite, Tailwind CSS, Zustand, and TanStack Query. Features security dashboards, visual memory DAG graphs, version diff viewers, and incident management workstations.
- **Persistence & Infrastructure (`docker-compose.yml`)**:
  - **Development Mode**: Can run completely standalone with zero external dependencies using high-performance in-memory repositories (`AUTH_BACKEND=in_memory_demo`).
  - **PostgreSQL Mode**: Uses PostgreSQL 16 via async SQLAlchemy (`asyncpg`) for durable relational storage.
  - **Redis Mode**: Ephemeral state, distributed locks, and token rate limiting.

### Service Communication Flow
```mermaid
flowchart LR
    Browser["Browser Client (React Workstation)"] -->|HTTP / Local Proxy :5173| ViteProxy["Vite Dev Server (:5173)"]
    ViteProxy -->|Proxy /api and /health| Backend["FastAPI Backend (:8000)"]
    Backend -->|Async SQLAlchemy (asyncpg)| Postgres[("PostgreSQL 16 (:5432)")]
    Backend -->|Cache & Rate Limit| Redis[("Redis 7 (:6379)")]
```

---

## 2. Prerequisites

Before running ChronoCogniSec, ensure the following tools are installed:

| Tool | Required Version | Verification Command | Purpose |
| :--- | :--- | :--- | :--- |
| **Python** | `>= 3.11` (3.12 or 3.14 recommended) | `python --version` | Backend API, security engine, and test suites |
| **Node.js** | `>= 18.0` (Node 20+ recommended) | `node -v` | Frontend runtime and tooling |
| **npm** | `>= 9.0` | `npm -v` | Frontend package management |
| **Git** | `>= 2.30` | `git --version` | Source control management |
| **Docker & Docker Compose** | Optional (for PostgreSQL & Redis) | `docker --version`<br>`docker compose version` | Running database and caching containers |

### Installation Guidance
- **Python**: Download from [python.org](https://www.python.org/downloads/). Check **"Add python.exe to PATH"** during installation.
- **Node.js**: Download the LTS release from [nodejs.org](https://nodejs.org/).
- **Docker Desktop**: If you plan to run PostgreSQL and Redis in containers, install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/).

---

## 3. Clone the Repository

If you already have this workspace open in your editor, proceed to **Section 4**.

To clone a fresh copy from GitHub:
```powershell
git clone https://github.com/9m2usman/ChronoCogniSec.git
cd ChronoCogniSec
```

---

## 4. Project Structure

```text
ChronoCogniSec/
├── backend/                       # Python Backend Service
│   ├── app/
│   │   ├── api/                   # REST API Routers (auth, memory, gateway, incidents, etc.)
│   │   ├── core/                  # Configuration, logging, exception handlers, middlewares
│   │   ├── database/              # DB schemas, models, and seed scripts
│   │   ├── gateway/               # Protected execution guard and policy evaluator
│   │   ├── knowledge/             # Topological knowledge graph builder
│   │   ├── memory/                # Memory models, ingestion, versioning, provenance DAG, adapters
│   │   ├── security/              # Trust evaluator, quarantine engine, security models
│   │   ├── traces/                # Dual trace persistence and span telemetry
│   │   └── main.py                # FastAPI application entry point
│   ├── tests/
│   │   ├── security/              # Exhaustive security test suites (1,100 tests)
│   │   └── unit/                  # Unit test suites (288 tests)
│   ├── Dockerfile                 # Backend container definition
│   └── requirements.txt           # Backend-specific Python requirements
├── frontend/                      # React / Vite Frontend Application
│   ├── src/
│   │   ├── components/            # Reusable UI components & layouts
│   │   ├── services/              # API clients and HTTP adapters
│   │   ├── stores/                # Zustand client state management
│   │   └── types/                 # TypeScript interfaces and schemas
│   ├── Dockerfile                 # Frontend container definition
│   ├── package.json               # Frontend dependencies & build scripts
│   ├── package-lock.json          # Pinned npm dependencies
│   └── vite.config.ts             # Vite server config & reverse proxy
├── docs/                          # Architecture & design specifications (read-only reference)
├── docker-compose.yml             # Local PostgreSQL 16 and Redis 7 definitions
├── pyproject.toml                 # Python package metadata
├── pytest.ini                     # Pytest test configuration
├── requirements.txt               # Pinned root-level Python dependencies
├── .env.example                   # Local environment variable template
└── RUN.md                         # This execution guide
```

---

## 5. Environment Configuration

The application reads configuration from a root `.env` file. A pre-configured template is provided at `.env.example`.

### Step 1: Create `.env`
In PowerShell, from the project root:
```powershell
Copy-Item .env.example .env
```

### Key Environment Variables Explained

| Variable | Default Value | Required? | Description |
| :--- | :--- | :--- | :--- |
| `APP_ENV` | `development` | Yes | Controls security constraints (`development`, `staging`, `production`, `test`). |
| `DEBUG` | `false` | Yes | Enable debug output. Must remain `false` in production. |
| `API_PREFIX` | `/api/v1` | Yes | Prefix for all versioned API routes. |
| `AUTH_BACKEND` | `in_memory_demo` | Yes | `in_memory_demo` for standalone zero-dependency mode; `database` for PostgreSQL mode. |
| `ALLOW_IN_MEMORY_AUTH` | `true` | Yes | Allows in-memory authentication. Must be `false` in production. |
| `JWT_SECRET` | Auto-generated in dev | No (Dev) | Secret key for JWT signing. In production, must be `>= 32` characters. |
| `JWT_ALGORITHM` | `HS256` | Yes | Cryptographic algorithm for JWT signing. |
| `DATABASE_URL` | `postgresql+asyncpg://...` | Optional | Async connection string for PostgreSQL. Only needed when using database persistence. |
| `REDIS_URL` | `redis://localhost:6379/0` | Optional | Redis connection URL for distributed locking and rate limiting. |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Yes | Allowed origins for cross-origin browser requests. |

---

## 6. Backend Installation

### Step 1: Open PowerShell at Project Root
Open PowerShell and navigate to the project directory:
```powershell
cd E:\ChronoCogniSec
```

### Step 2: Create a Python Virtual Environment
```powershell
python -m venv .venv
```

### Step 3: Activate the Virtual Environment
```powershell
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell displays an `ExecutionPolicy` restriction, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` in your current terminal session and re-run the activation script).*

### Step 4: Upgrade Pip & Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 7. Database Setup

ChronoCogniSec supports two modes of execution:

### Option A: Standalone Demo Mode (Recommended for Instant First Run)
In standalone mode, no database installation is required. The system boots using high-performance, in-memory reference repositories:
- Pre-seeded users:
  - `admin@companya.com` (Company A Administrator)
  - `analyst@companya.com` (Company A Security Analyst)
  - `dev@companya.com` (Company A AI Developer)
  - Password for all pre-seeded users: `Password123!`
- No Docker, PostgreSQL, or Redis installation needed.
- This is the default setting in `.env` (`AUTH_BACKEND=in_memory_demo`).

### Option B: PostgreSQL Mode (Production-Like Relational Storage)
To run with a real database:

1. **Start PostgreSQL via Docker Compose:**
   ```powershell
   docker compose up -d postgres
   ```
2. **Verify PostgreSQL is Ready:**
   ```powershell
   docker compose ps
   ```
3. **Update `.env`:**
   Ensure `.env` contains:
   ```ini
   DATABASE_URL=postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/amsc
   ```
4. **Seed Database:**
   ```powershell
   python -m backend.app.database.seed
   ```

---

## 8. Additional Services (Redis)

Redis is optional in development. It handles distributed rate limiting and token revocation caches.

To start Redis via Docker:
```powershell
docker compose up -d redis
```
To run without Redis:
Keep `RATE_LIMITER_BACKEND=in_memory` and `ALLOW_IN_MEMORY_RATE_LIMITER=true` in `.env`.

---

## 9. Frontend Installation

### Step 1: Navigate to Frontend Directory
From the project root:
```powershell
cd frontend
```

### Step 2: Install Node Dependencies
```powershell
npm install
```

### Step 3: Verify Frontend Build
To verify TypeScript compilation and production bundle creation:
```powershell
npm run build
```

---

## 10. Running the Complete Application

To run the complete platform, open **two PowerShell terminals** (or three if running Docker infrastructure).

### Terminal 1: Infrastructure (Optional — only if using PostgreSQL/Redis)
```powershell
cd E:\ChronoCogniSec
docker compose up
```

### Terminal 2: Backend API Server
```powershell
cd E:\ChronoCogniSec
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
**Expected Output:**
```text
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Starting Agent Memory Security Center v1.0.0 [development]
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Terminal 3: Frontend Workstation Server
```powershell
cd E:\ChronoCogniSec\frontend
npm run dev
```
**Expected Output:**
```text
  VITE v6.0.0  ready in 250 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
```

---

## 11. Verification

Once both servers are running, verify each tier:

### 1. Backend Health Check
Open a new terminal or browser tab:
```powershell
curl http://127.0.0.1:8000/health
```
**Expected Response:**
```json
{"status":"healthy","service":"amsc-api"}
```

### 2. Service Readiness Probe
```powershell
curl http://127.0.0.1:8000/api/v1/health/readiness
```

### 3. Interactive API Documentation (Swagger UI)
Visit [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) in your browser. All route catalogs (Auth, Memory, ChroniMem, Knowledge, Gateway, Incidents, Traces) are documented and interactive.

### 4. Frontend Application Access
Open [http://localhost:5173](http://localhost:5173) in your browser.
- **Login Credentials:**
  - Email: `analyst@companya.com`
  - Password: `Password123!`
  - Tenant ID: `tenant-company-a`

### 5. Running the Automated Test Suites
From the project root with the virtual environment activated:
```powershell
# Run Unit Tests (288 tests)
python -m pytest backend/tests/unit/ -v

# Run Security Regression Tests (1,100 tests)
python -m pytest backend/tests/security/ -q

# Run Memory & Knowledge Tests (164 tests)
python -m pytest backend/app/memory/tests/ backend/app/knowledge/tests/ -v
```

---

## 12. Common Errors and Troubleshooting

### Issue 1: PowerShell Script Execution Policy Restriction
* **Error:** `File .venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system.`
* **Solution:** Run the following command in PowerShell before activating:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
  ```

### Issue 2: Port 8000 or Port 5173 Already in Use
* **Error:** `[Errno 10048] error while attempting to bind on address ('127.0.0.1', 8000): address already in use`
* **Solution:** Identify and terminate the conflicting process:
  ```powershell
  # Find process using port 8000
  Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | Select-Object OwningProcess
  # Terminate process by PID (e.g., PID 1234)
  Stop-Process -Id 1234 -Force
  ```

### Issue 3: In-Memory Demo Authentication Rejected in Production
* **Error:** `Production startup failure: Real database authentication repository is not configured.`
* **Solution:** If running in production mode (`APP_ENV=production`), you must configure a PostgreSQL database (`AUTH_BACKEND=database`) and provide real secrets. For local development, ensure `APP_ENV=development` in your `.env` file.

### Issue 4: JWT Secret Invalidation Warning
* **Error:** `JWT_SECRET contains prohibited keyword 'replace', 'example', or 'dev'` in production mode.
* **Solution:** In `.env`, provide a high-entropy string of at least 32 characters generated via:
  ```powershell
  python -c "import secrets; print(secrets.token_hex(32))"
  ```

---

## 13. Shutdown Instructions

To gracefully stop running services:

1. **Backend Server:** Press `Ctrl + C` in Terminal 2.
2. **Frontend Server:** Press `Ctrl + C` in Terminal 3.
3. **Docker Containers (if running):**
   ```powershell
   cd E:\ChronoCogniSec
   docker compose down
   ```

---

## 14. Current Limitations

- **M2 Drift Detection & Security ML Models:** In accordance with project architecture specifications, external ML model training pipelines and raw datasets are deferred; the API provides deterministic statistical drift scoring and stubbed anomaly detection endpoints.
- **In-Memory vs. PostgreSQL Memory Repository:** In development, memory and knowledge records default to in-memory persistence. To persist memory records across restarts, configure PostgreSQL and set `DATABASE_URL`.
- **Browser Proxying:** Vite proxies API calls directly to `127.0.0.1:8000`. If you change the backend port, update the `target` address in `frontend/vite.config.ts`.
