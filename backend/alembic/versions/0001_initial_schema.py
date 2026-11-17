"""Initial schema: all 36 AMSC tables exactly as specified in AMSC-DOC-005 Section 3.

Revision ID: 0001
Revises:
Create Date: 2026-11-17

Owner: M6. Generated with autogenerate from backend.app.database.models and then
reviewed line by line against DOC-005. Foreign keys here are the plain
single-column references from the DOC-005 DDL; composite tenant-consistent
foreign keys are added in revision 0002.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '0001'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('permissions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_permissions')),
    sa.UniqueConstraint('key', name=op.f('uq_permissions_key'))
    )
    op.create_table('tenants',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('slug', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'ACTIVE'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tenants')),
    sa.UniqueConstraint('slug', name=op.f('uq_tenants_slug'))
    )
    op.create_index('idx_tenants_slug', 'tenants', ['slug'], unique=False)
    op.create_table('users',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('hashed_password', sa.String(length=255), nullable=False),
    sa.Column('full_name', sa.String(length=255), nullable=False),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'ACTIVE'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('email', name=op.f('uq_users_email'))
    )
    op.create_index('idx_users_email', 'users', ['email'], unique=False)
    op.create_table('agents',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('runtime', sa.String(length=64), server_default=sa.text("'LANGCHAIN'"), nullable=False),
    sa.Column('model', sa.String(length=64), server_default=sa.text("'gpt-4o'"), nullable=False),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'ACTIVE'"), nullable=False),
    sa.Column('config_version', sa.String(length=32), server_default=sa.text("'v1.0.0'"), nullable=False),
    sa.Column('system_prompt', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_agents_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_agents'))
    )
    op.create_index('idx_agents_tenant', 'agents', ['tenant_id'], unique=False)
    op.create_table('audit_events',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('actor_id', sa.String(length=128), nullable=False),
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('resource_id', sa.String(length=128), nullable=False),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('outcome', sa.String(length=32), nullable=False),
    sa.Column('trace_id', sa.String(length=128), nullable=True),
    sa.Column('details_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_audit_events_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events'))
    )
    op.create_index('idx_audit_tenant_occurred', 'audit_events', ['tenant_id', sa.literal_column('occurred_at DESC')], unique=False)
    op.create_table('branches',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('code', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'ACTIVE'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_branches_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_branches')),
    sa.UniqueConstraint('tenant_id', 'code', name='uq_tenant_branch_code')
    )
    op.create_index('idx_branches_tenant', 'branches', ['tenant_id'], unique=False)
    op.create_table('knowledge_entities',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('label', sa.String(length=255), nullable=False),
    sa.Column('entity_type', sa.String(length=64), server_default=sa.text("'CONCEPT'"), nullable=False),
    sa.Column('properties_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_knowledge_entities_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_knowledge_entities'))
    )
    op.create_table('memberships',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('role', sa.String(length=64), server_default=sa.text("'SECURITY_ANALYST'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_memberships_tenant_id_tenants'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_memberships_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_memberships')),
    sa.UniqueConstraint('tenant_id', 'user_id', name='uq_tenant_user')
    )
    op.create_index('idx_memberships_tenant_user', 'memberships', ['tenant_id', 'user_id'], unique=False)
    op.create_table('outbox_events',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'PENDING'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_outbox_events_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_outbox_events'))
    )
    op.create_index('idx_outbox_pending', 'outbox_events', ['status', 'created_at'], unique=False)
    op.create_table('roles',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=True),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_roles_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_roles'))
    )
    op.create_table('sources',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('source_type', sa.String(length=64), server_default=sa.text("'DOCUMENT_FEED'"), nullable=False),
    sa.Column('uri', sa.String(length=1024), nullable=True),
    sa.Column('trust_state', sa.String(length=32), server_default=sa.text("'UNVERIFIED'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_sources_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sources'))
    )
    op.create_table('tool_registrations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('adapter_type', sa.String(length=64), server_default=sa.text("'SANDBOX_REST'"), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('is_protected', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('schema_definition', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_tool_registrations_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tool_registrations')),
    sa.UniqueConstraint('tenant_id', 'name', name='uq_tenant_tool_name')
    )
    op.create_table('agent_tool_permissions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('agent_id', sa.String(length=36), nullable=False),
    sa.Column('tool_id', sa.String(length=36), nullable=False),
    sa.Column('allowed_operations', sa.String(length=255), server_default=sa.text("'*'"), nullable=False),
    sa.Column('constraints_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_agent_tool_permissions_agent_id_agents'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_agent_tool_permissions_tenant_id_tenants'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tool_id'], ['tool_registrations.id'], name=op.f('fk_agent_tool_permissions_tool_id_tool_registrations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_agent_tool_permissions')),
    sa.UniqueConstraint('agent_id', 'tool_id', name='uq_agent_tool_perm')
    )
    op.create_table('agent_versions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('agent_id', sa.String(length=36), nullable=False),
    sa.Column('version', sa.String(length=32), nullable=False),
    sa.Column('config_payload', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_agent_versions_agent_id_agents'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_agent_versions_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_agent_versions')),
    sa.UniqueConstraint('agent_id', 'version', name='uq_agent_version')
    )
    op.create_table('checkpoints',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('agent_id', sa.String(length=36), nullable=True),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('integrity_hash', sa.String(length=64), nullable=False),
    sa.Column('record_count', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('snapshot_data_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_checkpoints_agent_id_agents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_checkpoints_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_checkpoints'))
    )
    op.create_table('documents',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('source_id', sa.String(length=36), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('content_ref', sa.String(length=1024), nullable=True),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['source_id'], ['sources.id'], name=op.f('fk_documents_source_id_sources'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_documents_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_documents'))
    )
    op.create_table('knowledge_relations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('source_entity_id', sa.String(length=36), nullable=False),
    sa.Column('target_entity_id', sa.String(length=36), nullable=False),
    sa.Column('relation_type', sa.String(length=64), server_default=sa.text("'REFERENCES'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['source_entity_id'], ['knowledge_entities.id'], name=op.f('fk_knowledge_relations_source_entity_id_knowledge_entities'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['target_entity_id'], ['knowledge_entities.id'], name=op.f('fk_knowledge_relations_target_entity_id_knowledge_entities'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_knowledge_relations_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_knowledge_relations'))
    )
    op.create_table('memory_records',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('agent_id', sa.String(length=36), nullable=True),
    sa.Column('source_id', sa.String(length=36), nullable=True),
    sa.Column('record_type', sa.String(length=64), server_default=sa.text("'KNOWLEDGE'"), nullable=False),
    sa.Column('trust_state', sa.String(length=32), server_default=sa.text("'UNVERIFIED'"), nullable=False),
    sa.Column('current_version', sa.Integer(), server_default=sa.text('1'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_memory_records_agent_id_agents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['source_id'], ['sources.id'], name=op.f('fk_memory_records_source_id_sources'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_memory_records_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_memory_records'))
    )
    op.create_index('idx_memory_records_tenant_trust', 'memory_records', ['tenant_id', 'trust_state'], unique=False)
    op.create_table('role_permissions',
    sa.Column('role_id', sa.String(length=36), nullable=False),
    sa.Column('permission_id', sa.String(length=36), nullable=False),
    sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], name=op.f('fk_role_permissions_permission_id_permissions'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name=op.f('fk_role_permissions_role_id_roles'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('role_id', 'permission_id', name=op.f('pk_role_permissions'))
    )
    op.create_table('tool_proposals',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('agent_id', sa.String(length=36), nullable=False),
    sa.Column('action_id', sa.String(length=128), nullable=False),
    sa.Column('tool_name', sa.String(length=128), nullable=False),
    sa.Column('operation', sa.String(length=128), nullable=False),
    sa.Column('parameters_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('memory_refs_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
    sa.Column('idempotency_key', sa.String(length=255), nullable=False),
    sa.Column('trace_id', sa.String(length=128), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_tool_proposals_agent_id_agents'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_tool_proposals_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tool_proposals')),
    sa.UniqueConstraint('tenant_id', 'idempotency_key', name='uq_tenant_idemp_key')
    )
    op.create_index('idx_tool_proposals_trace', 'tool_proposals', ['tenant_id', 'trace_id'], unique=False)
    op.create_table('traces',
    sa.Column('id', sa.String(length=128), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('agent_id', sa.String(length=36), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'COMPLETED'"), nullable=False),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_traces_agent_id_agents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_traces_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_traces'))
    )
    op.create_table('drift_observations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('record_id', sa.String(length=36), nullable=False),
    sa.Column('classification', sa.String(length=64), server_default=sa.text("'POTENTIAL_POISONING'"), nullable=False),
    sa.Column('divergence_score', sa.String(length=32), server_default=sa.text("'0.78'"), nullable=False),
    sa.Column('evidence_summary', sa.Text(), nullable=False),
    sa.Column('reviewer_status', sa.String(length=32), server_default=sa.text("'PENDING'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['record_id'], ['memory_records.id'], name=op.f('fk_drift_observations_record_id_memory_records'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_drift_observations_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_drift_observations'))
    )
    op.create_table('incidents',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('classification', sa.String(length=64), nullable=False),
    sa.Column('severity', sa.String(length=32), server_default=sa.text("'HIGH'"), nullable=False),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'OPEN'"), nullable=False),
    sa.Column('affected_record_id', sa.String(length=36), nullable=True),
    sa.Column('agent_id', sa.String(length=36), nullable=True),
    sa.Column('evidence_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['affected_record_id'], ['memory_records.id'], name=op.f('fk_incidents_affected_record_id_memory_records'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_incidents_agent_id_agents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_incidents_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incidents'))
    )
    op.create_table('memory_versions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('record_id', sa.String(length=36), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('checksum', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['record_id'], ['memory_records.id'], name=op.f('fk_memory_versions_record_id_memory_records'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_memory_versions_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_memory_versions')),
    sa.UniqueConstraint('record_id', 'version', name='uq_record_version')
    )
    op.create_index('idx_memory_versions_checksum', 'memory_versions', ['checksum'], unique=False)
    op.create_table('policy_decisions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('proposal_id', sa.String(length=36), nullable=False),
    sa.Column('decision', sa.String(length=32), nullable=False),
    sa.Column('memory_trust', sa.String(length=32), nullable=False),
    sa.Column('policy_result', sa.String(length=32), nullable=False),
    sa.Column('reasons_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=True),
    sa.Column('execution_status', sa.String(length=32), server_default=sa.text("'NOT_EXECUTED'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['proposal_id'], ['tool_proposals.id'], name=op.f('fk_policy_decisions_proposal_id_tool_proposals'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_policy_decisions_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_policy_decisions')),
    sa.UniqueConstraint('proposal_id', name=op.f('uq_policy_decisions_proposal_id'))
    )
    op.create_table('provenance_edges',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('from_record_id', sa.String(length=36), nullable=False),
    sa.Column('to_record_id', sa.String(length=36), nullable=False),
    sa.Column('relation_type', sa.String(length=64), server_default=sa.text("'DERIVED_FROM'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['from_record_id'], ['memory_records.id'], name=op.f('fk_provenance_edges_from_record_id_memory_records'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_provenance_edges_tenant_id_tenants'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['to_record_id'], ['memory_records.id'], name=op.f('fk_provenance_edges_to_record_id_memory_records'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_provenance_edges'))
    )
    op.create_index('idx_provenance_from', 'provenance_edges', ['tenant_id', 'from_record_id'], unique=False)
    op.create_index('idx_provenance_to', 'provenance_edges', ['tenant_id', 'to_record_id'], unique=False)
    op.create_table('retrieval_events',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('agent_id', sa.String(length=36), nullable=False),
    sa.Column('record_id', sa.String(length=36), nullable=False),
    sa.Column('trace_id', sa.String(length=128), nullable=False),
    sa.Column('query_text', sa.Text(), nullable=True),
    sa.Column('occurred_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_retrieval_events_agent_id_agents'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['record_id'], ['memory_records.id'], name=op.f('fk_retrieval_events_record_id_memory_records'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_retrieval_events_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_retrieval_events'))
    )
    op.create_index('idx_retrieval_trace', 'retrieval_events', ['tenant_id', 'trace_id'], unique=False)
    op.create_table('trace_spans',
    sa.Column('id', sa.String(length=128), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('trace_id', sa.String(length=128), nullable=False),
    sa.Column('parent_span_id', sa.String(length=128), nullable=True),
    sa.Column('operation', sa.String(length=128), nullable=False),
    sa.Column('duration_ms', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_trace_spans_tenant_id_tenants'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['trace_id'], ['traces.id'], name=op.f('fk_trace_spans_trace_id_traces'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_trace_spans'))
    )
    op.create_table('transformations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('input_record_id', sa.String(length=36), nullable=False),
    sa.Column('output_record_id', sa.String(length=36), nullable=False),
    sa.Column('operation', sa.String(length=64), nullable=False),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['input_record_id'], ['memory_records.id'], name=op.f('fk_transformations_input_record_id_memory_records'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['output_record_id'], ['memory_records.id'], name=op.f('fk_transformations_output_record_id_memory_records'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_transformations_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_transformations'))
    )
    op.create_table('approvals',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('decision_id', sa.String(length=36), nullable=False),
    sa.Column('approver_user_id', sa.String(length=36), nullable=True),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'PENDING'"), nullable=False),
    sa.Column('comments', sa.Text(), nullable=True),
    sa.Column('responded_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['approver_user_id'], ['users.id'], name=op.f('fk_approvals_approver_user_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['decision_id'], ['policy_decisions.id'], name=op.f('fk_approvals_decision_id_policy_decisions'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_approvals_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_approvals'))
    )
    op.create_table('checkpoint_items',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('checkpoint_id', sa.String(length=36), nullable=False),
    sa.Column('record_id', sa.String(length=36), nullable=False),
    sa.Column('version_id', sa.String(length=36), nullable=False),
    sa.Column('checksum', sa.String(length=64), nullable=False),
    sa.ForeignKeyConstraint(['checkpoint_id'], ['checkpoints.id'], name=op.f('fk_checkpoint_items_checkpoint_id_checkpoints'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['record_id'], ['memory_records.id'], name=op.f('fk_checkpoint_items_record_id_memory_records'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_checkpoint_items_tenant_id_tenants'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['version_id'], ['memory_versions.id'], name=op.f('fk_checkpoint_items_version_id_memory_versions'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_checkpoint_items'))
    )
    op.create_table('incident_evidence',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=False),
    sa.Column('evidence_type', sa.String(length=64), nullable=False),
    sa.Column('resource_id', sa.String(length=128), nullable=False),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_incident_evidence_incident_id_incidents'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_incident_evidence_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incident_evidence'))
    )
    op.create_table('quarantines',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('record_id', sa.String(length=36), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=True),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('quarantined_by', sa.String(length=128), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_quarantines_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['record_id'], ['memory_records.id'], name=op.f('fk_quarantines_record_id_memory_records'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_quarantines_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_quarantines'))
    )
    op.create_table('recovery_plans',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=True),
    sa.Column('checkpoint_id', sa.String(length=36), nullable=False),
    sa.Column('target_record_id', sa.String(length=36), nullable=True),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'PENDING'"), nullable=False),
    sa.Column('pre_recovery_snapshot_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('impact_preview_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['checkpoint_id'], ['checkpoints.id'], name=op.f('fk_recovery_plans_checkpoint_id_checkpoints'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_recovery_plans_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['target_record_id'], ['memory_records.id'], name=op.f('fk_recovery_plans_target_record_id_memory_records'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_recovery_plans_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_recovery_plans'))
    )
    op.create_table('tool_executions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('proposal_id', sa.String(length=36), nullable=False),
    sa.Column('decision_id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'SUCCESS'"), nullable=False),
    sa.Column('status_code', sa.Integer(), server_default=sa.text('200'), nullable=False),
    sa.Column('result_payload_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('duration_ms', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('executed_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.ForeignKeyConstraint(['decision_id'], ['policy_decisions.id'], name=op.f('fk_tool_executions_decision_id_policy_decisions'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['proposal_id'], ['tool_proposals.id'], name=op.f('fk_tool_executions_proposal_id_tool_proposals'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_tool_executions_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tool_executions')),
    sa.UniqueConstraint('proposal_id', name=op.f('uq_tool_executions_proposal_id'))
    )
    op.create_table('recovery_actions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('plan_id', sa.String(length=36), nullable=False),
    sa.Column('resource_id', sa.String(length=128), nullable=False),
    sa.Column('action_taken', sa.String(length=64), nullable=False),
    sa.Column('outcome', sa.String(length=32), server_default=sa.text("'SUCCESS'"), nullable=False),
    sa.ForeignKeyConstraint(['plan_id'], ['recovery_plans.id'], name=op.f('fk_recovery_actions_plan_id_recovery_plans'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_recovery_actions_tenant_id_tenants'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_recovery_actions'))
    )


def downgrade() -> None:
    op.drop_table('recovery_actions')
    op.drop_table('tool_executions')
    op.drop_table('recovery_plans')
    op.drop_table('quarantines')
    op.drop_table('incident_evidence')
    op.drop_table('checkpoint_items')
    op.drop_table('approvals')
    op.drop_table('transformations')
    op.drop_table('trace_spans')
    op.drop_index('idx_retrieval_trace', table_name='retrieval_events')
    op.drop_table('retrieval_events')
    op.drop_index('idx_provenance_to', table_name='provenance_edges')
    op.drop_index('idx_provenance_from', table_name='provenance_edges')
    op.drop_table('provenance_edges')
    op.drop_table('policy_decisions')
    op.drop_index('idx_memory_versions_checksum', table_name='memory_versions')
    op.drop_table('memory_versions')
    op.drop_table('incidents')
    op.drop_table('drift_observations')
    op.drop_table('traces')
    op.drop_index('idx_tool_proposals_trace', table_name='tool_proposals')
    op.drop_table('tool_proposals')
    op.drop_table('role_permissions')
    op.drop_index('idx_memory_records_tenant_trust', table_name='memory_records')
    op.drop_table('memory_records')
    op.drop_table('knowledge_relations')
    op.drop_table('documents')
    op.drop_table('checkpoints')
    op.drop_table('agent_versions')
    op.drop_table('agent_tool_permissions')
    op.drop_table('tool_registrations')
    op.drop_table('sources')
    op.drop_table('roles')
    op.drop_index('idx_outbox_pending', table_name='outbox_events')
    op.drop_table('outbox_events')
    op.drop_index('idx_memberships_tenant_user', table_name='memberships')
    op.drop_table('memberships')
    op.drop_table('knowledge_entities')
    op.drop_index('idx_branches_tenant', table_name='branches')
    op.drop_table('branches')
    op.drop_index('idx_audit_tenant_occurred', table_name='audit_events')
    op.drop_table('audit_events')
    op.drop_index('idx_agents_tenant', table_name='agents')
    op.drop_table('agents')
    op.drop_index('idx_users_email', table_name='users')
    op.drop_table('users')
    op.drop_index('idx_tenants_slug', table_name='tenants')
    op.drop_table('tenants')
    op.drop_table('permissions')
