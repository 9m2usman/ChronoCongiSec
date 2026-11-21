"""CLI entry point for running a tenant memory cryptographic integrity audit.

Usage:
    python -m backend.app.memory.integrity_audit --tenant-id <tenant_id>

Module: backend.app.memory.integrity_audit
Owner: M3 — Knowledge & Memory Systems Lead
"""

import argparse
import asyncio
import sys

from backend.app.memory.integrity import audit_memory_integrity
from backend.app.memory.repository import get_default_repository


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit cryptographic checksum integrity across memory versions for a tenant."
    )
    parser.add_argument(
        "--tenant-id",
        required=True,
        help="Unique tenant identifier to audit.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Repository pagination batch size (default: 100).",
    )
    args = parser.parse_args()

    # ASSUMPTION (M3): Using in-memory stand-in repository only for now; persistent M6 integration pending.
    print("=================================================================")
    print("AMSC Memory Cryptographic Integrity Audit Runner")
    print("NOTE: Using in-memory repository stand-in (ASSUMPTION: persistent M6 database integration pending).")
    print(f"Tenant Target: {args.tenant_id}")
    print("=================================================================")

    repo = get_default_repository()
    report = asyncio.run(
        audit_memory_integrity(
            tenant_id=args.tenant_id,
            repository=repo,
            batch_size=args.batch_size,
        )
    )

    print(f"Started at:        {report.started_at.isoformat()}")
    print(f"Finished at:       {report.finished_at.isoformat()}")
    print(f"Total Records:     {report.total_records}")
    print(f"Total Versions:    {report.total_versions}")
    print(f"Matched Versions:  {report.matched}")
    print(f"Mismatched:        {len(report.mismatched)}")
    print(f"Missing Versions:  {len(report.missing_versions)}")
    print(f"Match Percentage:  {report.match_percentage:.2f}%")

    if report.mismatched:
        print("\nMISMATCHED VERSIONS DETECTED:")
        for item in report.mismatched:
            print(f"  - Record: {item.record_id}, Version: {item.version}")

    if report.missing_versions:
        print("\nRECORDS MISSING CURRENT VERSION ROW:")
        for rec_id in report.missing_versions:
            print(f"  - Record: {rec_id}")

    if report.mismatched or report.missing_versions:
        print("\nAUDIT RESULT: FAILED (integrity violations detected)")
        sys.exit(1)
    else:
        print("\nAUDIT RESULT: PASSED (100% cryptographic integrity verified)")
        sys.exit(0)


if __name__ == "__main__":
    main()
