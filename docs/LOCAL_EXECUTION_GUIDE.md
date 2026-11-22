# ChronoCogniSec — Beginner-Friendly Local Execution & Troubleshooting Guide

This guide walks you through running the entire ChronoCogniSec (Agent Memory Security Center) system on your local Windows PC in VS Code, explains what each component does, and provides immediate solutions for common socket and API key errors.

---

## 1. System Overview: What Are the Components?

The system consists of three main pieces designed to work seamlessly together:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VS Code (3 Terminals)                          │
├──────────────────────────┬───────────────────────┬─────────────────────┤
│   Terminal 1: Backend    │  Terminal 2: Frontend │  Terminal 3: CrewAI │
│      (Python/FastAPI)    │   (React 19 / Vite)   │   (5 Business Agts) │
│  http://127.0.0.1:8000   │ http://localhost:5173 │  Autonomous Flows   │
└────────────┬─────────────┴───────────┬───────────┴──────────┬──────────┘
             │                         │                      │
             │   REST API / Gateway    │                      │ Dual Trace API
             ▼                         ▼                      │ & Branch Context
     [In-Memory Demo Engine] ◄────────────────────────────────┘
               OR
     [Docker: PostgreSQL 16] (Optional for persistence)
```

1. **Backend (Python / FastAPI)**: The security gateway, audit logger, access control, and memory integrity engine.
2. **Frontend (React 19 / TypeScript / Vite)**: The interactive security dashboard with dual-mode badges, security policies, and trace visualizers.
3. **CrewAI Service (Multi-Agent System)**: 5 autonomous business agents (Customer Support, HR, Finance, Branch Operations, and Enterprise Workflow Coordinator) operating across enterprise branches (Head Office, Lahore, Karachi, Islamabad).

---

## 2. Resolving the Two Terminal Errors

### Error A: `[WinError 10013] Socket access forbidden` or `ECONNREFUSED 127.0.0.1:8000`

#### Why did this happen?
1. On Windows, binding explicitly to `127.0.0.1:8000` is blocked by Windows interface restrictions when WSL/Hyper-V is active.
2. When the backend is not running, Vite's proxy logs `connect ECONNREFUSED 127.0.0.1:8000` whenever the frontend tries to fetch API data.

#### The Permanent Fix: Bind to `0.0.0.0 --port 8000`
Binding to `0.0.0.0` bypasses the Windows single-interface restriction completely:
```powershell
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
Once this starts, `http://127.0.0.1:8000/health` responds immediately with `{"status":"healthy","service":"amsc-api"}` and Vite connects with 0 errors!

---

### Error B: `HTTP 400 Bad Request: API key not valid. Please pass a valid API key.` (Terminal 3)

#### Why did this happen?
You executed:
`$env:GEMINI_API_KEY = "your-actual-api-key"`
Because `"your-actual-api-key"` is a placeholder string, your machine sent that literal text to Google's AI Studio API. Google rejected the invalid key.

#### How to run it:

#### Path 1: 100% Free & Offline — Test Double Mode (Recommended for Local Testing)
No API key, credit card, or internet connection required! The built-in deterministic Test Double runs all 5 agents and generates full Dual Trace telemetry:
```powershell
python -m crewai_service.main --mode test_double
```
*Result: All 5 business agents execute immediately with 9 recorded dual-trace runs.*

#### Path 2: Live AI Execution with Google Gemini
1. Visit [Google AI Studio](https://aistudio.google.com/app/apikey) and click **Get API key** (it is free for developers).
2. Copy your key (starts with `AIzaSy...`).
3. Set your actual key in PowerShell:
```powershell
$env:GEMINI_API_KEY = "AIzaSyYourActualKeyHere..."
python -m crewai_service.main --mode live --provider gemini --model gemini-1.5-flash
```

---

## 3. What Does Docker Do & Do You Need It?

### What is Docker?
Docker runs software in isolated environments called "containers". In ChronoCogniSec, Docker is used to run **PostgreSQL** (the relational database) and **Redis** (the cache and rate limiter) without needing to install them directly onto Windows.

### Do you need Docker to run the project right now?
**NO.**
ChronoCogniSec is engineered with development defaults (`AUTH_BACKEND=in_memory_demo` and in-memory dual transactions). The backend and frontend run 100% locally out-of-the-box without Docker.

### When should you start Docker?
Only when you want data to be permanently saved to a real PostgreSQL database rather than kept in RAM.

#### To use PostgreSQL via Docker:
1. Ensure **Docker Desktop** is running (green icon in system tray).
2. Open a PowerShell terminal and run:
```powershell
# Start the PostgreSQL container in the background
docker compose up -d postgres

# Verify the container is running and healthy
docker compose ps
```
3. To run database migrations and seed enterprise branches:
```powershell
alembic upgrade head
python -m backend.app.database.seed
```

---

## 4. Complete Step-by-Step Execution (3 Terminals in VS Code)

Open VS Code with the `ChronoCogniSec` repository. Open 3 PowerShell terminals (`Ctrl + Shift + \``).

---

### Terminal 1: Start the Backend (API Gateway)

```powershell
# 1. Navigate to repository root
Set-Location E:\ChronoCogniSec

# 2. Start the FastAPI backend server on 0.0.0.0 (avoids Windows 10013 socket errors)
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
**Expected Output:**
```
INFO:     Started server process
INFO:     Waiting for application startup.
2026-11-22 14:31:39 [INFO] [amsc] Starting Agent Memory Security Center v1.0.0 [development]
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

---

### Terminal 2: Start the Frontend (Security Dashboard)

```powershell
# 1. Navigate to frontend directory
Set-Location E:\ChronoCogniSec\frontend

# 2. Start the Vite development server
npm run dev
```
**Expected Output:**
```
  VITE v5.4.14  ready in 450 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: http://10.x.x.x:5173/
  ➜  press h + enter to show help
```

---

### Terminal 3: Run the CrewAI Multi-Agent System

```powershell
# 1. Navigate to repository root
Set-Location E:\ChronoCogniSec

# 2. Run the 5 CrewAI Business Agents (Offline Test Double)
python -m crewai_service.main --mode test_double
```
**Expected Output:**
```
================================================================================
  ChronoCogniSec: Five Genuine CrewAI Business Agents in Simulated Enterprise
================================================================================
Execution Mode: TEST_DOUBLE
LLM Provider:   TEST_DOUBLE (Model: gemini-1.5-flash)
Tenant ID:      tenant-a-uuid-001 (ChronoCogniSec Enterprise)
Branches:       Head Office, Lahore, Karachi, Islamabad
--------------------------------------------------------------------------------
[AGENT 1] Customer Support Specialist: Processing Ticket...
[AGENT 2] HR Specialist: Processing Employee Inquiry...
[AGENT 3] Finance Specialist: Processing Discretionary Refund...
[AGENT 4] Branch Operations Specialist: Querying Inventory across Branches...
[AGENT 5] Enterprise Workflow Coordinator: Orchestrating Cross-Branch Transfer...
================================================================================
All 5 business agents executed cleanly.
Trace records generated and verified.
================================================================================
```

---

## 5. Verification: Opening in Your Browser

1. **Frontend Application**:
   Open [http://localhost:5173](http://localhost:5173) in your browser.
   - **Demo Login**:
     - Email: `analyst@amsc.local`
     - Password: `AnalystPass123!`
   - Verify the dashboard loads, the **Dual Mode Badge** displays connected status, and the agent memory and trace explorer widgets render correctly.

2. **Backend Interactive API Documentation**:
   Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) (or port `8001` if used).
   - Test the `/health` endpoint to verify system status:
     ```json
     {
       "status": "healthy",
       "service": "Agent Memory Security Center",
       "version": "1.0.0",
       "environment": "development"
     }
     ```

3. **Running the Full Test Suite**:
   You can verify all tests anytime across all layers:
   ```powershell
   # Run Backend Unit Tests (312 tests)
   pytest backend/tests/unit/ -v

   # Run CrewAI Agent Tests (36 tests)
   pytest crewai_service/tests/ -v

   # Run Frontend Component Tests (42 tests)
   cd frontend
   npm test -- --run
   ```
