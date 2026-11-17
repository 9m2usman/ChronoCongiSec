"""Expected tenant-consistent relationships (independent source of truth for tests).

Owner: M6
Kept separate from the models and the migrations on purpose: tests assert that
the migrated database matches THIS list exactly, so dropping or weakening a
relationship in either place is caught.
"""

from typing import NamedTuple


class Rel(NamedTuple):
    child: str
    column: str
    parent: str
    on_delete: str  # "CASCADE" or "SET NULL"

    @property
    def id(self) -> str:
        return f"{self.child}.{self.column}"


TENANT_RELATIONSHIPS: tuple[Rel, ...] = (
    Rel("agent_versions", "agent_id", "agents", "CASCADE"),
    Rel("agent_tool_permissions", "agent_id", "agents", "CASCADE"),
    Rel("agent_tool_permissions", "tool_id", "tool_registrations", "CASCADE"),
    Rel("documents", "source_id", "sources", "CASCADE"),
    Rel("memory_records", "agent_id", "agents", "SET NULL"),
    Rel("memory_records", "source_id", "sources", "SET NULL"),
    Rel("memory_versions", "record_id", "memory_records", "CASCADE"),
    Rel("transformations", "input_record_id", "memory_records", "CASCADE"),
    Rel("transformations", "output_record_id", "memory_records", "CASCADE"),
    Rel("provenance_edges", "from_record_id", "memory_records", "CASCADE"),
    Rel("provenance_edges", "to_record_id", "memory_records", "CASCADE"),
    Rel("retrieval_events", "agent_id", "agents", "CASCADE"),
    Rel("retrieval_events", "record_id", "memory_records", "CASCADE"),
    Rel("tool_proposals", "agent_id", "agents", "CASCADE"),
    Rel("policy_decisions", "proposal_id", "tool_proposals", "CASCADE"),
    Rel("policy_decisions", "incident_id", "incidents", "SET NULL"),
    Rel("approvals", "decision_id", "policy_decisions", "CASCADE"),
    Rel("tool_executions", "proposal_id", "tool_proposals", "CASCADE"),
    Rel("tool_executions", "decision_id", "policy_decisions", "CASCADE"),
    Rel("incidents", "affected_record_id", "memory_records", "SET NULL"),
    Rel("incidents", "agent_id", "agents", "SET NULL"),
    Rel("incident_evidence", "incident_id", "incidents", "CASCADE"),
    Rel("quarantines", "record_id", "memory_records", "CASCADE"),
    Rel("quarantines", "incident_id", "incidents", "SET NULL"),
    Rel("checkpoints", "agent_id", "agents", "SET NULL"),
    Rel("checkpoint_items", "checkpoint_id", "checkpoints", "CASCADE"),
    Rel("checkpoint_items", "record_id", "memory_records", "CASCADE"),
    Rel("checkpoint_items", "version_id", "memory_versions", "CASCADE"),
    Rel("recovery_plans", "incident_id", "incidents", "SET NULL"),
    Rel("recovery_plans", "checkpoint_id", "checkpoints", "CASCADE"),
    Rel("recovery_plans", "target_record_id", "memory_records", "SET NULL"),
    Rel("recovery_actions", "plan_id", "recovery_plans", "CASCADE"),
    Rel("knowledge_relations", "source_entity_id", "knowledge_entities", "CASCADE"),
    Rel("knowledge_relations", "target_entity_id", "knowledge_entities", "CASCADE"),
    Rel("drift_observations", "record_id", "memory_records", "CASCADE"),
    Rel("traces", "agent_id", "agents", "SET NULL"),
    Rel("trace_spans", "trace_id", "traces", "CASCADE"),
)

# Columns that look like references but intentionally have no FK.
# resource_id / actor_id columns are polymorphic identifiers, not references.
SOFT_REFERENCES = frozenset({
    ("trace_spans", "parent_span_id"),  # child spans can arrive before their parent
})
