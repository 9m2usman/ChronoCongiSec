"""Membership lookups for authentication (M1 contract).

Module: backend.app.database.repositories.memberships
Owner: M6

M1's login flow (``backend/app/api/auth.py``) resolves the tenant first and then
asks for the user's membership in that tenant. This repository returns the
stored row, including ``status``, exactly as it is in the database. It never
creates a membership and never interprets ``status``: M1 decides that only
``ACTIVE`` grants access.
"""

from typing import Optional

from sqlalchemy import select

from backend.app.database.models import Membership
from backend.app.database.repositories.base import TenantScopedRepository


class MembershipRepository(TenantScopedRepository[Membership]):
    model = Membership

    async def get_for_user(self, user_id: str) -> Optional[Membership]:
        """The user's membership in this repository's tenant, or None if there is none."""
        stmt = select(Membership).where(
            Membership.tenant_id == self.tenant_id, Membership.user_id == user_id
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()
