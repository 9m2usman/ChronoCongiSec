# ChronoCogniSec CrewAI Business Agents: Local Developer Setup Guide

**Document Identifier:** AMSC-DOC-011  
**Target Audience:** AI Engineers, Backend Developers, DevSecOps  
**Applicability:** Windows, macOS, Linux local development workstations  

---

## 1. System Requirements

- **Operating System:** Windows 10/11, Ubuntu 22.04+, macOS Sonoma+
- **Python Version:** Python 3.12, 3.13, or 3.14 (Python 3.14 recommended and verified locally)
- **Memory:** Minimum 4 GB RAM
- **Disk Space:** 500 MB free space

---

## 2. Directory Structure

The CrewAI business agent application resides inside the `crewai_service/` directory of the ChronoCogniSec repository:

```
e:\ChronoCogniSec\
├── backend\                     # Existing ChronoCogniSec FastAPI Backend
│   ├── app\
│   └── tests\unit\test_crewai_business_agents.py
├── crewai_service\              # Five Genuine CrewAI Business Agents
│   ├── .env.example             # Template environment variables
│   ├── pyproject.toml           # Modern package declaration
│   ├── requirements.txt         # Pinned dependencies
│   ├── framework.py             # Dual-mode runtime (Official CrewAI + Native compliant engine)
│   ├── main.py                  # CLI demonstration entrypoint
│   ├── agents\                  # 5 Business Specialists
│   │   ├── customer_support.py
│   │   ├── hr_operations.py
│   │   ├── finance_operations.py
│   │   ├── branch_operations.py
│   │   └── workflow_coordinator.py
│   ├── config\                  # Settings and LLM Provider Layer
│   │   ├── settings.py
│   │   └── provider.py
│   ├── security\                # Boundary & Policy Enforcement
│   │   └── boundaries.py
│   ├── telemetry\               # Dual Trace Telemetry Accumulator
│   │   └── tracer.py
│   ├── tools\                   # Restricted Tools & REST Client
│   │   ├── amsc_client.py
│   │   ├── branch_tools.py
│   │   ├── escalation_tools.py
│   │   ├── gateway_tools.py
│   │   └── memory_tools.py
│   ├── workflows\               # CrewAI Flow Definitions
│   │   └── flows.py
│   └── tests\                   # Comprehensive Test Suite (34 tests)
│       ├── test_customer_support.py
│       ├── test_hr_operations.py
│       ├── test_finance_operations.py
│       ├── test_branch_operations.py
│       ├── test_workflow_coordinator.py
│       ├── test_provider_configuration.py
│       ├── test_security_boundaries.py
│       └── test_twelve_scenarios.py
└── docs\                        # Architecture & Engineering Standards
```

---

## 3. Environment Setup Steps

### Step 1: Clone Repository & Open Workspace
```bash
git clone https://github.com/9m2usman/ChronoCongiSec.git
cd ChronoCongiSec
```

### Step 2: Configure Environment Variables
Copy `crewai_service/.env.example` to `crewai_service/.env`:

```bash
# Windows PowerShell
Copy-Item crewai_service\.env.example crewai_service\.env

# Linux / macOS
cp crewai_service/.env.example crewai_service/.env
```

### Step 3: Configure LLM Provider in `.env`
Open `crewai_service/.env` in your editor. Select your preferred execution mode:

#### Option A: Offline Test Double Mode (Zero External Network Required)
Recommended for automated CI/CD and offline unit testing:
```ini
EXECUTION_MODE=test_double
LLM_PROVIDER=test_double
LLM_MODEL=test-double-deterministic
```

#### Option B: Live Google Gemini LLM
```ini
EXECUTION_MODE=live
LLM_PROVIDER=gemini
LLM_MODEL=gemini-1.5-flash
GEMINI_API_KEY=your_actual_gemini_api_key_here
```

#### Option C: Live OpenAI LLM
```ini
EXECUTION_MODE=live
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=your_actual_openai_api_key_here
```

> **Security Mandate:** Never commit `.env` or paste live API keys into public Git branches. The repository `.gitignore` automatically ignores `.env`.

---

## 4. Running the Application

### 4.1 CLI Demonstration Runner
Run the interactive synthetic enterprise demonstration:

```bash
# Offline test double mode (fast, deterministic, zero network)
python -m crewai_service.main --mode test_double

# Live execution mode (requires GEMINI_API_KEY or OPENAI_API_KEY)
python -m crewai_service.main --mode live --provider gemini --model gemini-1.5-flash
```

Expected output:
- Sequential execution of all five agents (Customer Support, HR, Finance, Branch, Workflow Coordinator).
- Event-driven execution of `EnterpriseLifecycleFlow`.
- Gateway action proposals and deterministic policy checks.
- Dual Trace summary logging all 9 execution spans.

---

## 5. Running the Test Suites

### 5.1 Run CrewAI Service Test Suite (34 Tests)
```bash
python -m pytest crewai_service/tests -v
```

### 5.2 Run Backend Integration Tests (Including 5 CrewAI Tests)
```bash
python -m pytest backend/tests/unit/test_crewai_business_agents.py -v
```

### 5.3 Run Full Backend Regression Suite (288+ Tests)
```bash
python -m pytest backend/tests/unit/ -q
```

---

## 6. Troubleshooting Common Issues

### Issue 1: `GEMINI_API_KEY is not configured in environment`
- **Cause:** `EXECUTION_MODE=live` was requested but no API key was provided.
- **Solution:** Add your API key to `crewai_service/.env` or set environment variable:
  ```powershell
  $env:GEMINI_API_KEY="AIzaSy..."
  ```
  Alternatively, run with `--mode test_double` for offline testing.

### Issue 2: `[Errno 11001] getaddrinfo failed`
- **Cause:** Developer workstation has restricted outbound network access (corporate proxy, firewalled runner, or sandboxed execution).
- **Solution:** Use `--mode test_double`. The test double adapter provides 100% schema-compliant output without attempting external DNS resolution.

### Issue 3: `ImportError: cannot import name 'Agent' from 'crewai'`
- **Cause:** Official `crewai` package is not installed in the active Python virtual environment.
- **Solution:** Not required! The `crewai_service/framework.py` runtime automatically activates its built-in, fully-compliant CrewAI execution engine.
