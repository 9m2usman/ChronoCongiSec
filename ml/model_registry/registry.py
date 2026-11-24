"""Integrity-verified JSON artifact registry for AMSC security models.

Artifacts are data, not executable pickle files. Each artifact is written
atomically and its SHA-256 digest is recorded in an atomically replaced
manifest. Loading always verifies the manifest entry and artifact bytes
before parsing or returning the payload.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


class ModelIntegrityError(RuntimeError):
    """Raised when a model artifact is missing, malformed, or fails integrity checks."""


@dataclass(frozen=True)
class ModelArtifactMetadata:
    model_id: str
    version: str
    algorithm: str
    trained_on_dataset: str
    sha256: str
    metrics: Mapping[str, Any]


class ModelRegistry:
    """Store and verify JSON model artifacts using a SHA-256 manifest."""

    _MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

    def __init__(self, registry_dir: Path | str | None = None) -> None:
        # An explicitly supplied directory is the artifact directory. This keeps
        # test and caller-managed registries self-contained and predictable.
        self.registry_dir = Path(registry_dir) if registry_dir is not None else (
            Path(__file__).resolve().parent / "artifacts"
        )
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.registry_dir / "manifest.json"

    @classmethod
    def _validate_model_id(cls, model_id: str) -> str:
        if not isinstance(model_id, str) or not cls._MODEL_ID_PATTERN.fullmatch(model_id):
            raise ValueError("model_id must be a simple 1-128 character identifier")
        return model_id

    @staticmethod
    def _canonical_json(value: Any) -> bytes:
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Artifact payload must be finite JSON data: {exc}") from exc

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, path)
        except Exception:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise

    def _read_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return {"schema_version": 1, "artifacts": {}}
        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ModelIntegrityError(f"Model registry manifest is unreadable: {type(exc).__name__}") from exc
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema_version") != 1
            or not isinstance(manifest.get("artifacts"), dict)
        ):
            raise ModelIntegrityError("Model registry manifest has an invalid schema")
        return manifest

    def save_artifact(
        self,
        *,
        model_id: str,
        version: str,
        algorithm: str,
        payload: Mapping[str, Any],
        trained_on_dataset: str,
        metrics: Mapping[str, Any] | None = None,
    ) -> ModelArtifactMetadata:
        """Persist a JSON artifact and register its exact SHA-256 digest."""
        model_id = self._validate_model_id(model_id)
        if not isinstance(version, str) or not version.strip():
            raise ValueError("version is required")
        if not isinstance(algorithm, str) or not algorithm.strip():
            raise ValueError("algorithm is required")
        if not isinstance(trained_on_dataset, str) or not trained_on_dataset.strip():
            raise ValueError("trained_on_dataset is required")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        artifact_bytes = self._canonical_json(dict(payload))
        digest = hashlib.sha256(artifact_bytes).hexdigest()
        artifact_path = self.registry_dir / f"{model_id}.json"
        manifest = self._read_manifest()
        metadata = {
            "model_id": model_id,
            "version": version,
            "algorithm": algorithm,
            "trained_on_dataset": trained_on_dataset,
            "sha256": digest,
            "metrics": dict(metrics or {}),
        }
        # Write artifact first. A crash before manifest replacement leaves an
        # untrusted artifact, which load_artifact will reject (fail closed).
        self._atomic_write(artifact_path, artifact_bytes)
        manifest["artifacts"][model_id] = metadata
        self._atomic_write(self.manifest_path, self._canonical_json(manifest))
        return ModelArtifactMetadata(**metadata)

    def load_artifact(self, model_id: str) -> tuple[ModelArtifactMetadata, dict[str, Any]]:
        """Verify and load an artifact; never return bytes absent trusted metadata."""
        model_id = self._validate_model_id(model_id)
        manifest = self._read_manifest()
        raw_metadata = manifest["artifacts"].get(model_id)
        if not isinstance(raw_metadata, dict):
            raise ModelIntegrityError(f"Model artifact '{model_id}' is not registered")
        try:
            metadata = ModelArtifactMetadata(
                model_id=str(raw_metadata["model_id"]),
                version=str(raw_metadata["version"]),
                algorithm=str(raw_metadata["algorithm"]),
                trained_on_dataset=str(raw_metadata["trained_on_dataset"]),
                sha256=str(raw_metadata["sha256"]),
                metrics=dict(raw_metadata.get("metrics", {})),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ModelIntegrityError(f"Model artifact '{model_id}' has invalid manifest metadata") from exc
        if metadata.model_id != model_id or not re.fullmatch(r"[0-9a-f]{64}", metadata.sha256):
            raise ModelIntegrityError(f"Model artifact '{model_id}' has invalid integrity metadata")

        artifact_path = self.registry_dir / f"{model_id}.json"
        try:
            artifact_bytes = artifact_path.read_bytes()
        except OSError as exc:
            raise ModelIntegrityError(f"Model artifact '{model_id}' is missing or unreadable") from exc
        actual_digest = hashlib.sha256(artifact_bytes).hexdigest()
        if not hmac.compare_digest(actual_digest, metadata.sha256):
            raise ModelIntegrityError(f"Model artifact '{model_id}' failed SHA-256 integrity verification")
        try:
            payload = json.loads(artifact_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ModelIntegrityError(f"Model artifact '{model_id}' contains invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ModelIntegrityError(f"Model artifact '{model_id}' payload must be a JSON object")
        return metadata, payload
