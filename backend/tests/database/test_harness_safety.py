"""Safety of the M6 database test harness (it creates and drops databases).

Owner: M6
Destructive setup must only ever run against an explicit, local (or explicitly
allowed) test server, and may only drop databases the harness created itself.
"""

import asyncio

import asyncpg
import pytest

from backend.tests.database import helpers
from backend.tests.database.helpers import UnsafeTestDatabaseError, resolve_test_server_url

LOCAL = "postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/postgres"


def test_missing_test_database_url_fails_safely() -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="TEST_DATABASE_URL is required"):
        resolve_test_server_url({})


def test_database_url_alone_is_never_used() -> None:
    env = {"DATABASE_URL": "postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/amsc"}
    with pytest.raises(UnsafeTestDatabaseError, match="TEST_DATABASE_URL is required"):
        resolve_test_server_url(env)


def test_valid_local_test_server_is_accepted() -> None:
    url = resolve_test_server_url({"TEST_DATABASE_URL": LOCAL})
    assert url.host == "localhost" and url.database == "postgres"


def test_dedicated_amsc_test_database_is_accepted() -> None:
    url = resolve_test_server_url({"TEST_DATABASE_URL": "postgresql://amsc:x@127.0.0.1:5432/amsc_test_ci"})
    assert url.database == "amsc_test_ci"


@pytest.mark.parametrize("database", ["amsc", "app", "amsc_dev", "test_amsc", ""])
def test_application_or_unknown_database_names_are_rejected(database: str) -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="not allowed"):
        resolve_test_server_url({"TEST_DATABASE_URL": f"postgresql+asyncpg://amsc:x@localhost:5432/{database}"})


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://amsc:x@db.prod.example.com:5432/postgres",
        "postgresql+asyncpg://amsc:x@amsc-production-db:5432/postgres",
    ],
)
def test_remote_or_production_hosts_are_rejected(url: str) -> None:
    with pytest.raises(UnsafeTestDatabaseError):
        resolve_test_server_url({"TEST_DATABASE_URL": url})


def test_production_host_is_rejected_even_when_allowlisted() -> None:
    env = {
        "TEST_DATABASE_URL": "postgresql+asyncpg://amsc:x@prod-db:5432/postgres",
        "TEST_DATABASE_ALLOWED_HOSTS": "prod-db",
    }
    with pytest.raises(UnsafeTestDatabaseError, match="looks like production"):
        resolve_test_server_url(env)


@pytest.mark.parametrize("database", ["amsc_test_prod", "amsc_test_live"])
def test_production_looking_database_names_are_rejected(database: str) -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="looks like production"):
        resolve_test_server_url({"TEST_DATABASE_URL": f"postgresql://amsc:x@localhost/{database}"})


def test_production_looking_user_is_rejected() -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="looks like production"):
        resolve_test_server_url({"TEST_DATABASE_URL": "postgresql://prod_admin:x@localhost/postgres"})


def test_ci_service_host_is_accepted_only_when_allowlisted() -> None:
    url = "postgresql+asyncpg://amsc:x@postgres:5432/postgres"
    with pytest.raises(UnsafeTestDatabaseError, match="not local"):
        resolve_test_server_url({"TEST_DATABASE_URL": url})
    assert resolve_test_server_url(
        {"TEST_DATABASE_URL": url, "TEST_DATABASE_ALLOWED_HOSTS": "postgres, other"}
    ).host == "postgres"


def test_same_target_as_application_database_is_rejected() -> None:
    env = {
        "TEST_DATABASE_URL": "postgresql+asyncpg://amsc:x@localhost:5432/amsc_test_shared",
        "DATABASE_URL": "postgresql+asyncpg://amsc:y@LOCALHOST:5432/amsc_test_shared",
    }
    with pytest.raises(UnsafeTestDatabaseError, match="same database as DATABASE_URL"):
        resolve_test_server_url(env)


@pytest.mark.parametrize("url", ["mysql://amsc:x@localhost/postgres", "not a url"])
def test_non_postgres_or_malformed_urls_are_rejected(url: str) -> None:
    with pytest.raises(UnsafeTestDatabaseError):
        resolve_test_server_url({"TEST_DATABASE_URL": url})


@pytest.mark.parametrize(
    "name",
    ["amsc", "postgres", "amsc_test_", "amsc_test_xyz", "amsc_test_0123456789abcdef; DROP", "AMSC_TEST_0123456789ABCDEF"],
)
def test_drop_refuses_anything_but_harness_databases(name: str) -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="Refusing"):
        helpers.drop_temp_database(name)


async def _database_exists(name: str) -> bool:
    conn = await asyncpg.connect(helpers.asyncpg_dsn(helpers.MAINTENANCE_DATABASE))
    try:
        return await conn.fetchval("SELECT count(*) FROM pg_database WHERE datname = $1", name) == 1
    finally:
        await conn.close()


def test_temporary_database_is_created_and_cleaned_up() -> None:
    name = helpers.create_temp_database()
    try:
        assert helpers.TEMP_DB_PATTERN.fullmatch(name)
        assert asyncio.run(_database_exists(name))
    finally:
        helpers.drop_temp_database(name)
    assert not asyncio.run(_database_exists(name))
