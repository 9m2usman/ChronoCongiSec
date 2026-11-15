"""Local development hash-chain audit sink.

This is tamper-evident for modifications to retained records, not an immutable
or independently anchored production ledger. Production deployments must use
a transactional PostgreSQL sink and periodically anchor chain heads outside
the database trust boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any


_GENESIS = "0" * 64


class AuditUnavailable(RuntimeError):
    """Raised when a required audit write cannot be persisted."""


class JsonlHashChainAuditSink:
    """Single-process JSONL audit sink with fsync and hash-chain verification."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            verification = self.verify()
            if not verification["valid"]:
                raise AuditUnavailable("Existing audit chain failed verification")
            previous_hash = verification["head_hash"]
            sequence = verification["event_count"] + 1
            body = {"sequence": sequence, "previous_hash": previous_hash, "event": event}
            record = {**body, "event_hash": hashlib.sha256(self._canonical(body)).hexdigest()}
            try:
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                raise AuditUnavailable("Could not persist audit event") from exc
            return record

    def verify(self) -> dict[str, Any]:
        previous_hash = _GENESIS
        count = 0
        if not self.path.exists():
            return {"valid": True, "event_count": 0, "head_hash": _GENESIS}
        try:
            with self.path.open("r", encoding="utf-8") as stream:
                for expected_sequence, line in enumerate(stream, start=1):
                    record = json.loads(line)
                    body = {
                        "sequence": record["sequence"],
                        "previous_hash": record["previous_hash"],
                        "event": record["event"],
                    }
                    expected_hash = hashlib.sha256(self._canonical(body)).hexdigest()
                    if (
                        record["sequence"] != expected_sequence
                        or record["previous_hash"] != previous_hash
                        or record["event_hash"] != expected_hash
                    ):
                        return {"valid": False, "event_count": count, "head_hash": previous_hash}
                    previous_hash = expected_hash
                    count += 1
        except (OSError, ValueError, KeyError, TypeError):
            return {"valid": False, "event_count": count, "head_hash": previous_hash}
        return {"valid": True, "event_count": count, "head_hash": previous_hash}
