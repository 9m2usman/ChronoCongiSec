"""M6 / M7 Database Seed: Reproducible Multi-Tenant Canonical Seed Data.

Module: backend.app.database.seed
Owner: M6 (Data Schema) + M7 (Test/Dev Fixtures)

Implements Canonical Architecture:
- AMSC-DOC-005 Section 3: Identity, Tenancy, Agents, Sources, and Memories
- Seeds Company A (Financial), Company B (Cyber), Company C (Autonomous)
"""

from datetime import datetime, timezone
import logging
from typing import Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.security import hash_password
from backend.app.database.models.agents import Agent, ToolRegistration, AgentToolPermission
from backend.app.database.models.baseline import AgentSecurityProfile
from backend.app.database.models.memory import Source

from backend.app.database.models.identity import (
    Branch,
    Membership,
    Tenant,
    User,
)

logger = logging.getLogger("amsc.database.seed")


# Canonical tenants
TENANTS = [
    {
        "id": "tenant-a-uuid-001",
        "name": "ChronoCongiSec Enterprise",
        "slug": "alphacorp",
        "status": "ACTIVE",
    },
    {
        "id": "tenant-b-uuid-002",
        "name": "BetaShield Defense AI",
        "slug": "betashield",
        "status": "ACTIVE",
    },
    {
        "id": "tenant-c-uuid-003",
        "name": "GammaAI Autonomous Ops",
        "slug": "gammaai",
        "status": "ACTIVE",
    },
]

# Canonical users with argon2id hashed passwords
USERS = [
    {
        "id": "usr-admin-sarah-01",
        "email": "sarah.admin@alphacorp.com",
        "full_name": "Sarah Chen",
        "status": "ACTIVE",
        "is_superadmin": False,
    },
    {
        "id": "usr-analyst-alex-02",
        "email": "alex.analyst@alphacorp.com",
        "full_name": "Alex Mercer",
        "status": "ACTIVE",
        "is_superadmin": False,
    },
    {
        "id": "usr-dev-dave-03",
        "email": "dave.developer@alphacorp.com",
        "full_name": "Dave Miller",
        "status": "ACTIVE",
        "is_superadmin": False,
    },
    {
        "id": "usr-analyst-comp-a",
        "email": "analyst@company-a.com",
        "full_name": "Alice Analyst",
        "status": "ACTIVE",
        "is_superadmin": False,
    },
]

# Memberships
MEMBERSHIPS = [
    {
        "id": "mem-sarah-admin-01",
        "user_id": "usr-admin-sarah-01",
        "tenant_id": "tenant-a-uuid-001",
        "role": "TENANT_ADMIN",
        "status": "ACTIVE",
        "branch_id": "branch-ho-001",
    },
    {
        "id": "mem-alex-analyst-02",
        "user_id": "usr-analyst-alex-02",
        "tenant_id": "tenant-a-uuid-001",
        "role": "SECURITY_ANALYST",
        "status": "ACTIVE",
        "branch_id": "branch-lhr-002",
    },
    {
        "id": "mem-dave-dev-03",
        "user_id": "usr-dev-dave-03",
        "tenant_id": "tenant-a-uuid-001",
        "role": "AI_DEVELOPER",
        "status": "ACTIVE",
        "branch_id": "branch-khi-003",
    },
    {
        "id": "mem-analyst-comp-a-01",
        "user_id": "usr-analyst-comp-a",
        "tenant_id": "tenant-a-uuid-001",
        "role": "SECURITY_ANALYST",
        "status": "ACTIVE",
        "branch_id": "branch-ho-001",
    },
]

# Branches
BRANCHES = [
    {
        "id": "branch-ho-001",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Head Office - Core Security",
        "code": "HO",
        "status": "ACTIVE",
    },
    {
        "id": "branch-lhr-002",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Finance & Regional Operations Branch (Lahore)",
        "code": "LHR",
        "status": "ACTIVE",
    },
    {
        "id": "branch-khi-003",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Maritime & Logistics Operations Branch (Karachi)",
        "code": "KHI",
        "status": "ACTIVE",
    },
    {
        "id": "branch-isb-004",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Corporate Affairs & HR Branch (Islamabad)",
        "code": "ISB",
        "status": "ACTIVE",
    },
]

# Genuine CrewAI Business Agents
CREWAI_AGENTS = [
    {
        "id": "agent-crew-support-001",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Customer Support Specialist",
        "runtime": "CREWAI",
        "model": "gemini-1.5-flash",
        "status": "ACTIVE",
        "config_version": "v1.0.0",
        "system_prompt": "Authorized CrewAI Customer Support Specialist bounded by ChronoCogniSec Security Gateway.",
    },
    {
        "id": "agent-crew-hr-002",
        "tenant_id": "tenant-a-uuid-001",
        "name": "HR Operations Specialist",
        "runtime": "CREWAI",
        "model": "gemini-1.5-flash",
        "status": "ACTIVE",
        "config_version": "v1.0.0",
        "system_prompt": "Authorized CrewAI HR Operations Specialist enforcing official company handbooks.",
    },
    {
        "id": "agent-crew-finance-003",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Finance Operations Specialist",
        "runtime": "CREWAI",
        "model": "gemini-1.5-flash",
        "status": "ACTIVE",
        "config_version": "v1.0.0",
        "system_prompt": "Authorized CrewAI Finance Operations Specialist enforcing $300 dual-custody threshold.",
    },
    {
        "id": "agent-crew-branch-004",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Branch Operations Specialist",
        "runtime": "CREWAI",
        "model": "gemini-1.5-flash",
        "status": "ACTIVE",
        "config_version": "v1.0.0",
        "system_prompt": "Authorized CrewAI Branch Operations Specialist bounded strictly by assigned branch scope.",
    },
    {
        "id": "agent-crew-coord-005",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Enterprise Workflow Coordinator",
        "runtime": "CREWAI",
        "model": "gemini-1.5-flash",
        "status": "ACTIVE",
        "config_version": "v1.0.0",
        "system_prompt": "Authorized CrewAI Enterprise Workflow Coordinator managing cross-department workflows.",
    },
]


async def seed_database(session: AsyncSession) -> Dict[str, int]:
    """Execute reproducible seed script against active database session."""
    stats = {"tenants": 0, "users": 0, "memberships": 0, "branches": 0}
    now = datetime.now(timezone.utc)

    # 1. Seed Tenants
    for t_data in TENANTS:
        res = await session.execute(select(Tenant).where(Tenant.id == t_data["id"]))
        if res.scalar_one_or_none() is None:
            tenant = Tenant(
                id=t_data["id"],
                name=t_data["name"],
                slug=t_data["slug"],
                status=t_data["status"],
                created_at=now,
                updated_at=now,
            )
            session.add(tenant)
            stats["tenants"] += 1

    # 2. Seed Users
    default_pw_hash = hash_password("SecurePassword123!")
    for u_data in USERS:
        res = await session.execute(select(User).where(User.id == u_data["id"]))
        if res.scalar_one_or_none() is None:
            user = User(
                id=u_data["id"],
                email=u_data["email"],
                full_name=u_data["full_name"],
                hashed_password=default_pw_hash,
                status=u_data["status"],
                created_at=now,
            )
            session.add(user)
            stats["users"] += 1

    # 3. Seed Branches
    for b_data in BRANCHES:
        res = await session.execute(select(Branch).where(Branch.id == b_data["id"]))
        if res.scalar_one_or_none() is None:
            branch = Branch(
                id=b_data["id"],
                tenant_id=b_data["tenant_id"],
                name=b_data["name"],
                code=b_data["code"],
                status=b_data["status"],
                created_at=now,
            )
            session.add(branch)
            stats["branches"] += 1

    # 4. Seed Memberships
    for m_data in MEMBERSHIPS:
        res = await session.execute(select(Membership).where(Membership.id == m_data["id"]))
        existing_membership = res.scalar_one_or_none()
        if existing_membership is None:
            mem = Membership(
                id=m_data["id"],
                user_id=m_data["user_id"],
                tenant_id=m_data["tenant_id"],
                role=m_data["role"],
                status=m_data["status"],
                branch_id=m_data["branch_id"],
                created_at=now,
            )
            session.add(mem)
            stats["memberships"] += 1
        elif existing_membership.branch_id is None:
            # Backfill only missing demo branch assignments; preserve admin changes.
            existing_membership.branch_id = m_data["branch_id"]

    # 5. Seed Genuine CrewAI Agents
    stats["agents"] = 0
    for a_data in CREWAI_AGENTS:
        res = await session.execute(select(Agent).where(Agent.id == a_data["id"]))
        if res.scalar_one_or_none() is None:
            agent = Agent(
                id=a_data["id"],
                tenant_id=a_data["tenant_id"],
                name=a_data["name"],
                runtime=a_data["runtime"],
                model=a_data["model"],
                status=a_data["status"],
                config_version=a_data["config_version"],
                system_prompt=a_data["system_prompt"],
                created_at=now,
                updated_at=now,
            )
            session.add(agent)
            stats["agents"] += 1

    # Ensure agent rows exist before their governed profile foreign keys are inserted.
    await session.flush()

    # 6. Seed governed security profiles. Profile branch scope is authoritative.
    profile_specs = {
        "agent-crew-support-001": ("Customer Support", "branch-ho-001"),
        "agent-crew-hr-002": ("Human Resources", "branch-isb-004"),
        "agent-crew-finance-003": ("Finance", "branch-lhr-002"),
        "agent-crew-branch-004": ("Branch Operations", "branch-khi-003"),
        "agent-crew-coord-005": ("Enterprise Operations", "branch-ho-001"),
    }
    stats["agent_profiles"] = 0
    for agent_id, (department, profile_branch_id) in profile_specs.items():
        existing_profile = (
            await session.execute(
                select(AgentSecurityProfile).where(
                    AgentSecurityProfile.tenant_id == "tenant-a-uuid-001",
                    AgentSecurityProfile.agent_id == agent_id,
                )
            )
        ).scalar_one_or_none()
        if existing_profile is None:
            session.add(
                AgentSecurityProfile(
                    id=f"profile-{agent_id}",
                    tenant_id="tenant-a-uuid-001",
                    agent_id=agent_id,
                    owner_department=department,
                    approved_purpose=f"Perform approved {department.lower()} workflows for the company",
                    approved_goals_json=[
                        "Complete assigned company tasks within approved purpose and branch scope"
                    ],
                    branch_id=profile_branch_id,
                    data_scope_json=[f"branch:{profile_branch_id}:*"],
                    operational_restrictions_json={
                        "require_complete_mediation": True,
                        "no_direct_database_access": True,
                        "no_arbitrary_filesystem_access": True,
                    },
                    approval_requirements_json={"high_impact_mutations": "REQUIRE_HUMAN_APPROVAL"},
                    profile_version="v1.0.0",
                    status="ACTIVE",
                    governed_by_user_id="usr-admin-sarah-01",
                    created_at=now,
                    updated_at=now,
                )
            )
            stats["agent_profiles"] += 1

    # 7. Seed Protected Tool Registrations & Agent Permissions
    res_tool = await session.execute(
        select(ToolRegistration).where(
            ToolRegistration.tenant_id == "tenant-a-uuid-001",
            ToolRegistration.name == "sandbox_transfer",
        )
    )
    tool_reg = res_tool.scalar_one_or_none()
    if tool_reg is None:
        tool_reg = ToolRegistration(
            id="tool-sandbox-transfer",
            tenant_id="tenant-a-uuid-001",
            name="sandbox_transfer",
            adapter_type="INTERNAL",
            description="Sandbox funds transfer and disbursement tool",
            is_protected=True,
            schema_definition={"type": "object", "properties": {"destination": {"type": "string"}, "amount": {"type": "number"}}},
            created_at=now,
        )
        session.add(tool_reg)
        await session.flush()

    for aid, ops, max_amt in [
        ("agent-crew-support-001", "transfer_funds", 300.0),
        ("agent-crew-finance-003", "transfer_funds", 10000.0),
    ]:
        res_perm = await session.execute(
            select(AgentToolPermission).where(
                AgentToolPermission.agent_id == aid,
                AgentToolPermission.tool_id == tool_reg.id,
            )
        )
        if res_perm.scalar_one_or_none() is None:
            perm = AgentToolPermission(
                id=f"perm-{aid[:16]}-transfer",
                tenant_id="tenant-a-uuid-001",
                agent_id=aid,
                tool_id=tool_reg.id,
                allowed_operations=ops,
                constraints_json={"max_amount": max_amt, "approval_threshold_amount": 300.0},
                created_at=now,
            )
            session.add(perm)

    # 7b. Phase 3: protected company-operations tool (server-side adapter reached only
    # through the gateway). Grants follow the seeded agents' approved purposes; the
    # adapter additionally enforces each agent profile's branch data scope.
    res_company_tool = await session.execute(
        select(ToolRegistration).where(
            ToolRegistration.tenant_id == "tenant-a-uuid-001",
            ToolRegistration.name == "company_workspace",
        )
    )
    company_tool = res_company_tool.scalar_one_or_none()
    if company_tool is None:
        company_tool = ToolRegistration(
            id="tool-company-workspace",
            tenant_id="tenant-a-uuid-001",
            name="company_workspace",
            adapter_type="INTERNAL",
            description="Protected company files, tasks, handoffs, messages and file transfers",
            is_protected=True,
            schema_definition={
                "type": "object",
                "description": "Operation-specific parameters; scope is derived from the authenticated context.",
            },
            created_at=now,
        )
        session.add(company_tool)
        await session.flush()

    company_grants = [
        # Branch Operations Specialist: full branch workspace operations in its own branch.
        ("agent-crew-branch-004", ",".join([
            "list_workspaces", "list_files", "read_file", "create_file", "update_file",
            "transfer_file", "create_task", "update_task_status", "handoff_task",
            "send_message", "read_inbox",
        ])),
        # Enterprise Workflow Coordinator: cross-department task coordination and messaging.
        ("agent-crew-coord-005", ",".join([
            "list_workspaces", "list_files", "read_file", "create_task",
            "update_task_status", "handoff_task", "send_message", "read_inbox",
        ])),
    ]
    for aid, ops in company_grants:
        res_perm = await session.execute(
            select(AgentToolPermission).where(
                AgentToolPermission.agent_id == aid,
                AgentToolPermission.tool_id == company_tool.id,
            )
        )
        if res_perm.scalar_one_or_none() is None:
            session.add(AgentToolPermission(
                id=f"perm-{aid[:16]}-company",
                tenant_id="tenant-a-uuid-001",
                agent_id=aid,
                tool_id=company_tool.id,
                allowed_operations=ops,
                constraints_json={},
                created_at=now,
            ))

    # 7. Seed Canonical Knowledge Sources (Document 05 Table 5)
    stats["sources"] = 0
    sources_to_seed = [
        ("src-doc-001", "Treasury Policy Memo", "DOCUMENT_FEED"),
        ("src-accounting-policy-v2.pdf", "Accounting Policy v2", "DOCUMENT_FEED"),
        ("src-hr-handbook-v1.pdf", "HR Employee Handbook", "DOCUMENT_FEED"),
        ("src-support-guide-v1.pdf", "Customer Support Protocols", "DOCUMENT_FEED"),
        ("src-branch-ops-v1.pdf", "Branch Operations Manual", "DOCUMENT_FEED"),
        ("src-workflow-gov-v1.pdf", "Cross-Department Workflow Governance", "DOCUMENT_FEED"),
    ]
    for sid, sname, stype in sources_to_seed:
        res_source = await session.execute(
            select(Source).where(
                Source.tenant_id == "tenant-a-uuid-001",
                Source.id == sid,
            )
        )
        if res_source.scalar_one_or_none() is None:
            src = Source(
                id=sid,
                tenant_id="tenant-a-uuid-001",
                name=sname,
                source_type=stype,
                status="ACTIVE",
                created_at=now,
            )
            session.add(src)
            stats["sources"] += 1

    await session.commit()
    logger.info(f"Database seed complete: {stats}")
    return stats
