"""Checksums of MERGED Alembic migrations (guard against editing migration history).

Owner: M6
Rule: a migration that is merged into ``main`` is never edited; changes go into a NEW
migration. ``test_migration_governance.py`` fails if a file listed here changes.

The hash is SHA-256 over the file text with line endings normalised to ``\\n`` (so a
Windows checkout with CRLF and a Linux checkout give the same value).

After a new migration is merged into main, add its line here (see INTEGRATION-GUIDE.md):

    .venv\\Scripts\\python.exe -m backend.tests.database.migration_manifest

prints the current hash of every migration file; copy the new file's line into
``MERGED_MIGRATIONS`` in the same PR or a follow-up PR.
"""

import hashlib
from pathlib import Path

VERSIONS_DIR = Path(__file__).resolve().parents[2] / "alembic" / "versions"

MERGED_MIGRATIONS: dict[str, str] = {
    # Recorded 2026-11-18 from main at e25c628 (Day 6 merged); cross-checked against the git blobs.
    "0001_initial_schema.py": "9e6d883b6256c0463b28368f201cba8ce747f2767ad132ce1c85685d23fa6f7c",
    "0002_composite_tenant_foreign_keys.py": "923824687fc60e46e2e84264051890529f04bf8e44ebafb093adbab0dc183890",
    "0003_membership_status_and_forensic_retention.py": "7905953450d30c60b4429389633243e0b2da13a9417a8d22ead6ddc18f699e49",
    "0004_audit_events_append_only.py": "f737b1987a090180002f856e0b87d892b9d971ed07cbd5cdf5c129237ba13005",
    "0005_checkpoint_version_record_integrity.py": "5673b74faf476e8fc38fb0487024ec27b133dfd233b8fed8e6c5a9b976ff145f",
    "0006_source_status_and_provenance_edge_rules.py": "16b6d0e1ed2e9ef271dafc57421bbb4c885e6f88a772bcbfa93a30185b7142fb",
    "0007_gateway_chain_integrity.py": "6410cc666f8d7a84e3785d0aab8ab2f0f6f8d3ff2dfe4374ee7b91e6612037c3",
    "0008_recovery_snapshot_and_chain_integrity.py": "099cf02005e24741586d586f7bd5813d1d9a1493c36be276a1bdf9cfee67d044",
    "0009_audit_hash_chain_and_decision_immutability.py": "ea62ade5b8393124a0b9e9e222661ddd6dbb566a5208ed6aebdaccf942b112b5",
}


def migration_sha256(path: Path) -> str:
    text = path.read_bytes().decode("utf-8").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def current_hashes() -> dict[str, str]:
    return {p.name: migration_sha256(p) for p in sorted(VERSIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.py"))}


if __name__ == "__main__":
    for name, digest in current_hashes().items():
        print(f'    "{name}": "{digest}",')
