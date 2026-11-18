"""Tenant-scoped repository base (AMSC-DOC-005 §4.1 "Database Row Scoping").

Module: backend.app.database.repositories.base
Owner: M6

A repository is bound to ONE tenant at construction time. Every read, update and
delete is filtered by that tenant, and ``add()`` stamps the tenant itself, so a
caller cannot forget the filter or write into another tenant. The database
(composite FKs + tenant_id immutability trigger) remains the final line of
defence if this layer is bypassed.

The repository never commits: the caller (or the Day 4 unit of work) owns the
transaction boundary.
"""

from collections.abc import Sequence
from typing import Any, ClassVar, Generic, Optional, TypeVar

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.base import Base

ModelT = TypeVar("ModelT", bound=Base)

# AMSC-DOC-002 (TRD) "Paginated List APIs": default page size 50, maximum 100.
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
IMMUTABLE_FIELDS = frozenset({"id", "tenant_id"})


class TenantScopeError(ValueError):
    """Raised when an operation would cross or change a tenant boundary."""


def check_page(limit: Any, offset: Any) -> None:
    """Pagination contract shared by every repository: 1 <= limit <= 100 (int), offset >= 0 (int)."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PAGE_SIZE:
        raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be an integer >= 0")


class TenantScopedRepository(Generic[ModelT]):
    """CRUD for one tenant-owned model, always filtered by ``tenant_id``.

    Use either a subclass (``model = Agent``) or pass ``model=`` to the constructor.
    """

    model: ClassVar[type[Base]]

    def __init__(self, session: AsyncSession, tenant_id: str, model: Optional[type[ModelT]] = None) -> None:
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise TenantScopeError("A non-empty tenant_id is required for a tenant-scoped repository.")
        resolved = model or getattr(type(self), "model", None)
        if resolved is None:
            raise TypeError("TenantScopedRepository needs a model (subclass attribute or model=).")
        tenant_column = resolved.__table__.columns.get("tenant_id")
        if tenant_column is None or tenant_column.nullable:
            raise TypeError(f"{resolved.__name__} is not a tenant-owned model (NOT NULL tenant_id required).")
        self.session = session
        self.tenant_id = tenant_id
        self._model: type[ModelT] = resolved  # type: ignore[assignment]

    # -- reads --------------------------------------------------------------

    async def get(self, entity_id: str) -> Optional[ModelT]:
        stmt = select(self._model).where(
            self._model.id == entity_id, self._model.tenant_id == self.tenant_id
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def list(self, *, limit: int = DEFAULT_PAGE_SIZE, offset: int = 0, **filters: Any) -> Sequence[ModelT]:
        check_page(limit, offset)
        self._check_fields(filters)
        stmt = select(self._model).where(self._model.tenant_id == self.tenant_id)
        for name, value in filters.items():
            stmt = stmt.where(getattr(self._model, name) == value)
        stmt = stmt.order_by(self._model.id).limit(limit).offset(offset)
        return (await self.session.execute(stmt)).scalars().all()

    # -- writes -------------------------------------------------------------

    async def add(self, entity: ModelT) -> ModelT:
        if not isinstance(entity, self._model):
            raise TypeError(f"Expected {self._model.__name__}, got {type(entity).__name__}")
        if entity.tenant_id is not None and entity.tenant_id != self.tenant_id:
            raise TenantScopeError("Entity belongs to a different tenant than this repository.")
        entity.tenant_id = self.tenant_id
        self.session.add(entity)
        await self.session.flush()
        return entity

    async def update(self, entity_id: str, **values: Any) -> Optional[ModelT]:
        """Update fields of one row in this tenant. Returns None if the row is not visible."""
        if not values:
            raise ValueError("No fields to update.")
        forbidden = IMMUTABLE_FIELDS & values.keys()
        if forbidden:
            raise TenantScopeError(f"Fields cannot be changed: {sorted(forbidden)}")
        self._check_fields(values)
        stmt = (
            update(self._model)
            .where(self._model.id == entity_id, self._model.tenant_id == self.tenant_id)
            .values(**values)
            .returning(self._model)
            .execution_options(synchronize_session="fetch")
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def delete(self, entity_id: str) -> bool:
        stmt = (
            delete(self._model)
            .where(self._model.id == entity_id, self._model.tenant_id == self.tenant_id)
            .execution_options(synchronize_session="fetch")
        )
        result = await self.session.execute(stmt)
        return result.rowcount == 1

    # -- helpers ------------------------------------------------------------

    def _check_fields(self, fields: dict[str, Any]) -> None:
        unknown = set(fields) - set(self._model.__table__.columns.keys())
        if unknown:
            raise ValueError(f"Unknown {self._model.__name__} fields: {sorted(unknown)}")
