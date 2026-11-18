"""Migration history governance (no database needed).

Owner: M6
- Merged migrations (listed in migration_manifest.py) are never edited.
- Revisions are a single, gap-free, numbered chain whose file names match their revision.
"""

import re

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from backend.tests.database import helpers
from backend.tests.database.migration_manifest import (
    MERGED_MIGRATIONS,
    VERSIONS_DIR,
    current_hashes,
    migration_sha256,
)

FILE_PATTERN = re.compile(r"^(\d{4})_[a-z0-9_]+\.py$")


def _script() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(helpers.ALEMBIC_INI)))


@pytest.mark.parametrize("name", sorted(MERGED_MIGRATIONS))
def test_merged_migration_is_unchanged(name: str) -> None:
    path = VERSIONS_DIR / name
    assert path.exists(), f"merged migration {name} was deleted or renamed"
    assert migration_sha256(path) == MERGED_MIGRATIONS[name], (
        f"merged migration {name} was edited. Never edit a merged migration: add a new one. "
        "If this change is intentional and approved, the manifest must be updated in the same PR."
    )


def test_every_older_migration_is_in_the_manifest() -> None:
    """A file numbered at or below the newest manifest entry must itself be listed (no back-filled history)."""
    newest = max(int(n[:4]) for n in MERGED_MIGRATIONS)
    unlisted = [n for n in current_hashes() if int(n[:4]) <= newest and n not in MERGED_MIGRATIONS]
    assert unlisted == [], f"migrations inserted into merged history: {unlisted}"


def test_file_names_match_revisions_and_chain_is_gap_free() -> None:
    script = _script()
    revisions = list(reversed(list(script.walk_revisions())))  # base -> head
    assert [r.revision for r in revisions] == [f"{i:04d}" for i in range(1, len(revisions) + 1)]
    for index, rev in enumerate(revisions):
        name = rev.path.replace("\\", "/").rsplit("/", 1)[-1]
        match = FILE_PATTERN.fullmatch(name)
        assert match and match.group(1) == rev.revision, f"{name} does not match revision {rev.revision}"
        expected_down = None if index == 0 else revisions[index - 1].revision
        assert rev.down_revision == expected_down, f"{rev.revision} must follow {expected_down}"


def test_every_migration_documents_itself() -> None:
    for rev in _script().walk_revisions():
        assert rev.doc and rev.doc.strip(), f"migration {rev.revision} has no docstring"
