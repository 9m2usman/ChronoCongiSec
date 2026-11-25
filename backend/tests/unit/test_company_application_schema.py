"""Schema contract tests for the persisted company application domain."""
from sqlalchemy import ForeignKeyConstraint, UniqueConstraint

from backend.app.database.base import Base
from backend.app.database.models.company import (
    CompanyActivity,
    CompanyFile,
    CompanyFileTransfer,
    CompanyFileVersion,
    CompanyMessage,
    CompanyNotification,
    CompanyTask,
    CompanyTaskEvent,
    CompanyWorkspace,
)


def test_company_application_tables_are_registered():
    expected = {
        "company_workspaces",
        "company_files",
        "company_file_versions",
        "company_file_transfers",
        "company_tasks",
        "company_task_events",
        "company_messages",
        "company_notifications",
        "company_activity",
    }
    assert expected.issubset(Base.metadata.tables)


def test_company_tables_require_tenant_scope():
    models = (
        CompanyWorkspace, CompanyFile, CompanyFileVersion, CompanyFileTransfer,
        CompanyTask, CompanyTaskEvent, CompanyMessage, CompanyNotification,
        CompanyActivity,
    )
    for model in models:
        tenant_column = model.__table__.columns["tenant_id"]
        assert tenant_column.nullable is False
        assert any(
            fk.column.table.name == "tenants"
            for fk in tenant_column.foreign_keys
        )


def test_branch_and_membership_references_are_composite():
    workspace_constraints = [
        constraint for constraint in CompanyWorkspace.__table__.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    ]
    assert any(
        tuple(column.name for column in constraint.columns) == ("tenant_id", "branch_id")
        and tuple(element.column.table.name for element in constraint.elements) == ("branches", "branches")
        for constraint in workspace_constraints
    )
    assert any(
        tuple(column.name for column in constraint.columns) == ("tenant_id", "owner_user_id")
        and tuple(element.column.table.name for element in constraint.elements) == ("memberships", "memberships")
        for constraint in workspace_constraints
    )


def test_file_versions_are_unique_and_preserve_content_checksum():
    constraints = [
        constraint for constraint in CompanyFileVersion.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    ]
    assert any(
        tuple(column.name for column in constraint.columns)
        == ("tenant_id", "file_id", "version_number")
        for constraint in constraints
    )
    assert CompanyFileVersion.__table__.columns["content"].nullable is False
    assert CompanyFileVersion.__table__.columns["checksum"].type.length == 64


def test_messages_and_transfers_are_bound_to_two_memberships():
    for model in (CompanyMessage, CompanyFileTransfer):
        membership_fks = [
            constraint for constraint in model.__table__.constraints
            if isinstance(constraint, ForeignKeyConstraint)
            and all(element.column.table.name == "memberships" for element in constraint.elements)
        ]
        assert len(membership_fks) == 2
