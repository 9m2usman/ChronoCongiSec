# ChronoCogniSec (AMSC) — Enterprise Credentials & Authentication Directory

This document contains all pre-seeded accounts, roles, passwords, company slugs, and branch codes for the **ChronoCogniSec — Agent Memory Security Center (AMSC)** platform.

---

## 1. Quick-Start Login Reference (Copy & Paste)

You can use these credentials to log in to the AMSC Frontend Workstation at **[http://localhost:5173/login](http://localhost:5173/login)** or authenticate directly against the Backend API at **[http://127.0.0.1:8000/auth/login](http://127.0.0.1:8000/auth/login)**.

| Role | Email Address | Password | Company Slug | Access Scope |
| :--- | :--- | :--- | :--- | :--- |
| **TENANT_ADMIN** | `admin@company-a.com` | `SecurePassword123!` | `company-a` | Full enterprise administration, employee approval, agent policy configuration |
| **TENANT_ADMIN** | `sarah.admin@alphacorp.com` | `SecurePassword123!` | `alphacorp` | Full enterprise administration (PostgreSQL seed profile) |
| **SECURITY_ANALYST** | `analyst@company-a.com` | `SecurePassword123!` | `company-a` | Incident triage, memory quarantine, dual-trace inspection, security drift analysis |
| **SECURITY_ANALYST** | `alex.analyst@alphacorp.com` | `SecurePassword123!` | `alphacorp` | Incident triage, memory quarantine (PostgreSQL seed profile) |
| **AI_DEVELOPER** | `developer@company-a.com` | `SecurePassword123!` | `company-a` | Agent registration, tool binding, system prompt configuration, trace playback |
| **AI_DEVELOPER** | `dave.developer@alphacorp.com` | `SecurePassword123!` | `alphacorp` | Agent registration, tool binding (PostgreSQL seed profile) |
| **AI_DEVELOPER (Karachi)** | `karachi-dev@company-a.com` | `SecurePassword123!` | `company-a` | Branch-restricted developer bounded strictly to Maritime & Logistics (`KHI`) |
| **AI_DEVELOPER (Lahore)** | `lahore-dev@company-a.com` | `SecurePassword123!` | `company-a` | Branch-restricted developer bounded strictly to Finance & Operations (`LHR`) |
| **AUDITOR** | `auditor@company-a.com` | `SecurePassword123!` | `company-a` | Read-only compliance review, tamper-evident audit logs, verification reports |

> **Password Note**: All pre-seeded accounts use the standard password:  
> `SecurePassword123!`

---

## 2. Organization & Workspace Details

The production model represents **One Single Enterprise Company** operating across geographical branch locations:

- **Enterprise Name**: ChronoCogniSec Enterprise (or AlphaCorp)
- **Primary Tenant ID**: `tenant-a-uuid-001`
- **Supported Company Slugs** (interchangeable aliases):
  - `company-a`
  - `alphacorp`
  - `chronocognisec`

### Enterprise Branch Structure

| Branch Code | Branch Name | Branch ID | Functional Scope |
| :--- | :--- | :--- | :--- |
| **`HO`** | Head Office — Core Security | `branch-ho-001` | Central Governance, IAM, Executive Oversight |
| **`LHR`** | Finance & Regional Operations | `branch-lhr-002` | Disbursements, Invoicing, Regional Operations |
| **`KHI`** | Maritime & Logistics Operations | `branch-khi-003` | Supply Chain, Fleet Logistics, Port Customs |
| **`ISB`** | Corporate Affairs & HR Branch | `branch-isb-004` | Policy Handbooks, Employee Relations, Legal |

---

## 3. How to Log In & Navigate the Workstation

1. Open your browser to **`http://localhost:5173/login`**.
2. Fill out the login form:
   - **Work Email**: `admin@company-a.com` (or any email from the table above)
   - **Password**: `SecurePassword123!`
   - **Company Workspace Slug**: `company-a` (or `alphacorp`)
3. Click **Sign In to AMSC**.
4. The application will authenticate your session, issue an HMAC-SHA256 JWT token, store it in local storage, and navigate you to the **Overview Dashboard** (`/overview`).

---

## 4. How to Test Employee Self-Registration & Approval (Phase 1 IAM)

### Step 1: Submit an Employee Registration Request
1. Open **`http://localhost:5173/register`**.
2. Enter the new employee details:
   - **Full Name**: e.g., `Zayd Khan`
   - **Work Email**: e.g., `zayd.khan@company-a.com`
   - **Password**: at least 8 characters (e.g., `EmployeePass123!`)
   - **Company Slug**: `company-a`
   - **Requested Branch**: Select `Lahore Branch (LHR)`
3. Click **Submit Registration Request**.
4. You will receive a unique tracking ID (e.g., `reg-7f3b89a12c4e`). Note: pending employees cannot log in until approved.

### Step 2: Administrator Approves the Request
1. Log out or open an incognito window, then log in as the Tenant Administrator:
   - Email: `admin@company-a.com`
   - Password: `SecurePassword123!`
2. Navigate to **Settings & Governance** (`/settings`) -> **User Management & Registrations**.
3. Locate `Zayd Khan` in the **Pending Registration Requests** queue.
4. Assign their approved Role (`AI_DEVELOPER`, `SECURITY_ANALYST`, or `AUDITOR`) and Branch (`LHR`).
5. Click **Approve**.
6. Now the new user can immediately log in with their credentials at `/login`!

---

## 5. Autonomous CrewAI Business Agents (Gateway Identities)

AMSC mediates all 5 autonomous CrewAI business agents. Each agent possesses a registered identity, role ceiling, and authorized branch context:

| Agent Identifier | Agent Name | Runtime | Primary Model | Parameter Ceiling |
| :--- | :--- | :--- | :--- | :--- |
| `agent-crew-support-001` | Customer Support Specialist | CrewAI | `gemini-1.5-flash` | Standard Customer Service Tools |
| `agent-crew-hr-002` | HR Operations Specialist | CrewAI | `gemini-1.5-flash` | Official Company Handbooks |
| `agent-crew-finance-003` | Finance Operations Specialist | CrewAI | `gemini-1.5-flash` | **$300.00 Ceiling** (requires human dual-custody above $300) |
| `agent-crew-branch-004` | Branch Operations Specialist | CrewAI | `gemini-1.5-flash` | Bounded to branch-specific inventory |
| `agent-crew-coord-005` | Enterprise Workflow Coordinator | CrewAI | `gemini-1.5-flash` | Cross-branch workflow orchestration |

### How CrewAI Connects to the AMSC Gateway
In `crewai_service/.env`:
```ini
CHRONOCONGISEC_API_BASE_URL=http://127.0.0.1:8000/api/v1
CHRONOCONGISEC_TENANT_ID=tenant-a-uuid-001
CHRONOCONGISEC_AUTH_EMAIL=analyst@company-a.com
CHRONOCONGISEC_AUTH_PASSWORD=SecurePassword123!
CHRONOCONGISEC_TENANT_SLUG=company-a
```

---

## 6. Testing Authentication via cURL / PowerShell

To verify authentication directly via command line:

```powershell
$body = @{
    email = "admin@company-a.com"
    password = "SecurePassword123!"
    tenant_slug = "company-a"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://127.0.0.1:8000/auth/login" -Method Post -ContentType "application/json" -Body $body
$token = $response.access_token

Write-Host "Authenticated successfully! Access token:"
Write-Host $token

# Test authenticated /auth/me profile
Invoke-RestMethod -Uri "http://127.0.0.1:8000/auth/me" -Headers @{ Authorization = "Bearer $token" }
```
