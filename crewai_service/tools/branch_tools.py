"""Branch Scoping & Regional Operations Tools.

Module: crewai_service.tools.branch_tools
Owner: ChronoCogniSec Integration Council

Enforces Branch Scoping (AMSC-DOC-005 Table 1B):
- Regional branch agents (Lahore, Karachi, Islamabad) can only operate within their assigned branch.
- Cross-branch access attempts are strictly rejected and logged as security anomalies.
- Head Office has enterprise-wide supervisory capability.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from crewai_service.framework import tool
from crewai_service.security.boundaries import (
    SecurityBoundaryViolation,
    enforce_branch_scope,
)

logger = logging.getLogger("amsc.crewai.tools.branch")


class BranchToolFactory:
    """Factory creating branch-scoped operational tools."""

    def __init__(self, agent_branch_id: str, agent_id: str) -> None:
        self.agent_branch_id = agent_branch_id
        self.agent_id = agent_id

    def create_branch_inspection_tool(self) -> Any:
        assigned_branch = self.agent_branch_id

        @tool("retrieve_branch_operational_data")
        def retrieve_branch_operational_data(
            target_branch_id: str = "",
            data_category: str = "FACILITY_STATUS",
            **kwargs: Any,
        ) -> str:
            """Retrieve operational data (facility status, staffing, logistics) for a specific branch.

            Fails closed and raises SecurityBoundaryViolation if an agent attempts cross-branch access.
            """
            # If target_branch_id contains serialized JSON or dict, unpack arguments safely
            if isinstance(target_branch_id, str) and target_branch_id.strip().startswith("{"):
                try:
                    import json, ast
                    raw_dict = json.loads(target_branch_id.strip())
                except Exception:
                    try:
                        raw_dict = ast.literal_eval(target_branch_id.strip())
                    except Exception:
                        raw_dict = None
                if isinstance(raw_dict, dict):
                    target_branch_id = raw_dict.get("target_branch_id") or raw_dict.get("branch_id") or ""
                    data_category = raw_dict.get("data_category") or raw_dict.get("category") or data_category

            tgt = target_branch_id or kwargs.get("branch_id") or assigned_branch
            category = data_category or kwargs.get("category", "FACILITY_STATUS")
            logger.info(
                f"Agent in branch '{assigned_branch}' requesting '{category}' for branch '{tgt}'."
            )
            # Enforce branch scope boundary
            enforce_branch_scope(
                agent_branch_id=assigned_branch,
                target_branch_id=tgt,
            )

            # Return branch-specific operational records
            if "lahore" in tgt.lower() or tgt == "branch-lhr-002":
                return (
                    f"Branch Operational Record [Branch: Lahore ({tgt}) | Category: {category}]:\n"
                    "- Facility Status: NORMAL_OPERATIONS (Server Room Temperature: 19.5 C)\n"
                    "- Active Staff Count: 42 personnel on duty\n"
                    "- Regional Inventory: 120 edge security tokens in vault, 15 hardware keys provisioned\n"
                    "- Incident Count: 0 active physical security incidents"
                )
            elif "karachi" in tgt.lower() or tgt == "branch-khi-003":
                return (
                    f"Branch Operational Record [Branch: Karachi ({tgt}) | Category: {category}]:\n"
                    "- Facility Status: NORMAL_OPERATIONS (Port logistics gateway active)\n"
                    "- Active Staff Count: 58 personnel on duty\n"
                    "- Regional Inventory: 85 maritime hardware modules, 30 transit security seals\n"
                    "- Incident Count: 0 active physical security incidents"
                )
            elif "islamabad" in tgt.lower() or tgt == "branch-isb-004":
                return (
                    f"Branch Operational Record [Branch: Islamabad ({tgt}) | Category: {category}]:\n"
                    "- Facility Status: NORMAL_OPERATIONS (Corporate compliance center active)\n"
                    "- Active Staff Count: 35 personnel on duty\n"
                    "- Regional Inventory: 50 compliance auditing hardware modules\n"
                    "- Incident Count: 0 active physical security incidents"
                )
            else:
                return (
                    f"Branch Operational Record [Branch: Head Office ({tgt}) | Category: {category}]:\n"
                    "- Facility Status: ENTERPRISE_CORE_ACTIVE\n"
                    "- Active Staff Count: 180 personnel across all departments\n"
                    "- Global Security Operations: 24/7 monitoring engaged"
                )

        return retrieve_branch_operational_data

    def create_head_office_sync_tool(self) -> Any:
        assigned_branch = self.agent_branch_id

        @tool("coordinate_with_head_office")
        def coordinate_with_head_office(
            report_title: str = "Regional Status Report",
            summary_content: str = "",
            **kwargs: Any,
        ) -> str:
            """Submit a formal branch operational status update to Head Office."""
            title = report_title or kwargs.get("title", "Regional Status Report")
            summary = summary_content or kwargs.get("summary", "")
            logger.info(
                f"Branch '{assigned_branch}' transmitting report '{title}' to Head Office."
            )
            return (
                f"HEAD OFFICE SYNC RECEIPT: Report '{title}' successfully received from branch '{assigned_branch}'. "
                f"Status: LOGGED_AND_ACKNOWLEDGED. Summary: {summary[:100]}..."
            )

        return coordinate_with_head_office
