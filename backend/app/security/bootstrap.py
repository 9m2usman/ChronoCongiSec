"""Secure First Tenant Administrator Bootstrap Procedure.

Module: backend.app.security.bootstrap
Owner: M1 / M6

Follows:
- AMSC Phase 1 Section 5: Secure First Tenant Admin Provisioning
- NIST SP 800-63B Authenticator Assurance

Usage:
    python -m backend.app.security.bootstrap --email sarah.admin@alphacorp.com --name "Sarah Chen" --tenant alphacorp
    (Password is prompted securely via getpass or read from AMSC_BOOTSTRAP_PASSWORD env var)
"""

import argparse
import asyncio
import getpass
import os
import sys

from backend.app.core.config import get_settings
from backend.app.core.security import hash_password
from backend.app.database.repositories.auth import DatabaseAuthRepository
from backend.app.database.session import create_engine, create_session_factory


async def bootstrap_admin_cli(
    tenant_slug: str,
    admin_email: str,
    admin_full_name: str,
    password: str,
) -> None:
    settings = get_settings()

    if len(password) < 8:
        print("[ERROR] Administrator password must be at least 8 characters.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Initializing secure admin bootstrap for tenant '{tenant_slug}'...")

    engine = create_engine()
    session_factory = create_session_factory(engine)
    repo = DatabaseAuthRepository(session_factory)

    pw_hash = hash_password(password)

    try:
        tenant, user, mem = await repo.bootstrap_tenant_admin(
            tenant_slug=tenant_slug,
            admin_email=admin_email,
            admin_full_name=admin_full_name,
            password_hash=pw_hash,
        )
        print(f"[SUCCESS] Bootstrapped Tenant Administrator successfully:")
        print(f"          Tenant:   {tenant.name} (slug: {tenant.slug}, id: {tenant.id})")
        print(f"          User:     {user.full_name} ({user.email}, id: {user.id})")
        print(f"          Role:     {mem.role} (status: {mem.status})")
    except RuntimeError as exc:
        print(f"[REFUSED] {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Bootstrap failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bootstrap initial Tenant Administrator for AMSC company workspace."
    )
    parser.add_argument(
        "--tenant",
        default="alphacorp",
        help="Target tenant slug (default: alphacorp)",
    )
    parser.add_argument(
        "--email",
        required=True,
        help="Administrator work email address",
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Administrator full name",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Administrator password (if not provided, will read from AMSC_BOOTSTRAP_PASSWORD or prompt securely)",
    )

    args = parser.parse_args()

    password = args.password or os.environ.get("AMSC_BOOTSTRAP_PASSWORD")
    if not password:
        password = getpass.getpass("Enter secure password for initial Tenant Admin: ")
        confirm = getpass.getpass("Confirm secure password: ")
        if password != confirm:
            print("[ERROR] Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    asyncio.run(
        bootstrap_admin_cli(
            tenant_slug=args.tenant,
            admin_email=args.email,
            admin_full_name=args.name,
            password=password,
        )
    )


if __name__ == "__main__":
    main()
