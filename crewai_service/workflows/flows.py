"""CrewAI Flow Controller for Enterprise Workflows.

Module: crewai_service.workflows.flows
Owner: ChronoCogniSec CrewAI Architect

Implements:
- CrewAI Flow controller with @start and @listen method decorators.
- Orchestrates multi-agent business operations deterministically.
- State management across workflow stages.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
import uuid

from crewai_service.agents.workflow_coordinator import (
    EnterpriseWorkflowInput,
    EnterpriseWorkflowReport,
    execute_enterprise_workflow,
)
from crewai_service.framework import Flow, listen, start
from crewai_service.tools.amsc_client import ChronoCogniSecClient

logger = logging.getLogger("amsc.crewai.flow")


class EnterpriseLifecycleFlow(Flow):
    """Overall workflow controller utilizing CrewAI Flow architecture."""

    def __init__(
        self,
        workflow_input: EnterpriseWorkflowInput,
        client: Optional[ChronoCogniSecClient] = None,
        llm: Optional[Any] = None,
    ) -> None:
        super().__init__()
        self.workflow_input = workflow_input
        self.client = client or ChronoCogniSecClient()
        self.llm = llm
        self.report: Optional[EnterpriseWorkflowReport] = None

    @start()
    def initialize_enterprise_workflow(self) -> Dict[str, Any]:
        """Validate initiative parameters and initialize workflow state."""
        logger.info(
            f"[FLOW START] Initializing enterprise workflow '{self.workflow_input.workflow_id}': "
            f"'{self.workflow_input.initiative_title}'."
        )
        self.state["workflow_id"] = self.workflow_input.workflow_id
        self.state["initiative_title"] = self.workflow_input.initiative_title
        self.state["tenant_id"] = self.client.tenant_id
        self.state["initialized"] = True
        return self.state

    @listen(initialize_enterprise_workflow)
    def dispatch_and_consolidate(self, init_state: Dict[str, Any]) -> EnterpriseWorkflowReport:
        """Execute specialist agents and synthesize consolidated enterprise report."""
        logger.info(
            f"[FLOW LISTEN] Dispatching initiative '{init_state['initiative_title']}' to specialist agents."
        )
        report = execute_enterprise_workflow(
            workflow_input=self.workflow_input,
            client=self.client,
            llm=self.llm,
        )
        self.report = report
        self.state["report"] = report.model_dump()
        logger.info(f"[FLOW COMPLETE] Workflow finished with status: {report.status}")
        return report
