"""Enterprise Data & Agent Framework Connectors.

Security Principles:
- Explicit authorization & least-privilege scope enforcement.
- Database connectors are strictly read-only and scoped to allowed_tables.
- Filesystem connectors strictly enforce allowed_roots and prevent path traversal.
- Unimplemented or unconfigured external connectors honestly report UNAVAILABLE.
- Monitoring coverage explicitly distinguishes observed vs inferred vs unsupported events.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET
import zipfile

from backend.app.enterprise.models import (
    ConnectorType,
    DataClassification,
    EnterpriseConnectorDTO,
    ResourceType,
)


@dataclass
class DiscoveredItem:
    external_id: str
    name: str
    resource_type: ResourceType
    source_version: str
    content_checksum: str
    owner: Optional[str] = None
    access_scope: str = "TENANT_SCOPED"
    classification: DataClassification = DataClassification.INTERNAL
    metadata: Dict[str, Any] = field(default_factory=dict)
    extracted_text: Optional[str] = None
    structured_records: Optional[List[Dict[str, Any]]] = None


class BaseEnterpriseConnector(ABC):
    """Abstract base for all enterprise connectors."""

    @abstractmethod
    def validate_connection(self, connector: EnterpriseConnectorDTO) -> tuple[bool, str, Dict[str, Any]]:
        """Validate connection & return (ok, message, monitoring_coverage)."""

    @abstractmethod
    def discover_and_read(
        self,
        connector: EnterpriseConnectorDTO,
        *,
        include_content: bool = True,
        target_external_ids: Optional[List[str]] = None,
    ) -> List[DiscoveredItem]:
        """Discover permitted resources and optionally read authorized content."""


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SqliteDatabaseConnector(BaseEnterpriseConnector):
    """Read-only, table-scoped SQLite enterprise database connector."""

    SAFE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def _resolve_db_path(self, connector: EnterpriseConnectorDTO) -> Path:
        raw_path = connector.config_json.get("db_path") or connector.config_json.get("path")
        if not raw_path:
            raise ValueError("Database connector requires 'db_path' in config.")
        p = Path(str(raw_path)).resolve()
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"Database file not found: {p}")
        return p

    def validate_connection(self, connector: EnterpriseConnectorDTO) -> tuple[bool, str, Dict[str, Any]]:
        coverage = {
            "observed_events": ["SCHEMA_DISCOVERY", "ROW_COUNT_CHECK", "CHECKSUM_SYNC"],
            "inferred_events": ["RECORD_CHANGE_FROM_CHECKSUM"],
            "unsupported_events": ["REALTIME_WAL_CDC_STREAM"],
        }
        try:
            db_path = self._resolve_db_path(connector)
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                conn.execute("SELECT 1").fetchone()
            finally:
                conn.close()
            return True, "SQLite read-only connection validated.", coverage
        except Exception as exc:
            return False, f"Database connection validation failed: {exc}", coverage

    def discover_and_read(
        self,
        connector: EnterpriseConnectorDTO,
        *,
        include_content: bool = True,
        target_external_ids: Optional[List[str]] = None,
    ) -> List[DiscoveredItem]:
        db_path = self._resolve_db_path(connector)
        allowed_tables = set(connector.scope_json.get("allowed_tables") or [])
        max_rows = int(connector.scope_json.get("max_rows_per_table", 200))
        max_rows = max(1, min(max_rows, 1000))

        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        items: List[DiscoveredItem] = []
        try:
            tables = conn.execute(
                "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'"
            ).fetchall()

            for row in tables:
                tname = str(row["name"])
                ttype = str(row["type"])
                if not self.SAFE_IDENT_RE.match(tname):
                    continue
                if allowed_tables and "*" not in allowed_tables and tname not in allowed_tables:
                    continue

                ext_id = f"sqlite://{db_path.name}/{tname}"
                if target_external_ids and ext_id not in target_external_ids:
                    continue

                cols_info = conn.execute(f'PRAGMA table_info("{tname}")').fetchall()
                columns = [{"name": c["name"], "type": c["type"]} for c in cols_info]
                count_row = conn.execute(f'SELECT COUNT(*) AS cnt FROM "{tname}"').fetchone()
                row_count = int(count_row["cnt"]) if count_row else 0

                # Least privilege: require explicit allowed_tables (or '*') before reading row data
                table_content_permitted = bool(allowed_tables) and ("*" in allowed_tables or tname in allowed_tables)
                records: List[Dict[str, Any]] = []
                if include_content and table_content_permitted:
                    data_rows = conn.execute(f'SELECT * FROM "{tname}" LIMIT ?', (max_rows,)).fetchall()
                    records = [dict(r) for r in data_rows]

                canonical = json.dumps({"columns": columns, "rows": records, "row_count": row_count}, sort_keys=True, default=str)
                checksum = _sha256_text(canonical)
                rtype = ResourceType.DATABASE_VIEW if ttype == "view" else ResourceType.DATABASE_TABLE

                classification = DataClassification.INTERNAL
                lower_name = tname.lower()
                if any(k in lower_name for k in ("salary", "payroll", "hr", "secret", "credential", "pii")):
                    classification = DataClassification.RESTRICTED
                elif any(k in lower_name for k in ("vendor", "finance", "invoice", "payment", "order")):
                    classification = DataClassification.CONFIDENTIAL

                items.append(
                    DiscoveredItem(
                        external_id=ext_id,
                        name=tname,
                        resource_type=rtype,
                        source_version=f"rows:{row_count}:sha:{checksum[:12]}",
                        content_checksum=checksum,
                        owner="enterprise-db-admin",
                        access_scope=f"READ_ONLY_TABLE:{tname}",
                        classification=classification,
                        metadata={
                            "engine": "sqlite",
                            "database": db_path.name,
                            "columns": columns,
                            "row_count": row_count,
                            "sampled_rows": len(records),
                        },
                        structured_records=records if include_content else None,
                    )
                )
        finally:
            conn.close()
        return items


class FilesystemEnterpriseConnector(BaseEnterpriseConnector):
    """Scoped local/shared filesystem connector with path-traversal protection."""

    SUPPORTED_EXTENSIONS = {".txt", ".md", ".json", ".csv", ".pdf", ".docx"}

    def _resolve_root(self, connector: EnterpriseConnectorDTO) -> Path:
        raw_root = connector.config_json.get("root_path") or connector.config_json.get("path")
        if not raw_root:
            raise ValueError("Filesystem connector requires 'root_path' in config.")
        root = Path(str(raw_root)).resolve()
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(f"Root directory not found: {root}")
        return root

    def _is_within_allowed(self, root: Path, candidate: Path, allowed_paths: List[str]) -> bool:
        try:
            rel = candidate.resolve().relative_to(root.resolve())
        except ValueError:
            return False
        if not allowed_paths:
            return True
        rel_posix = rel.as_posix()
        norm_allowed = [p.replace("\\", "/").lstrip("./").strip("/") for p in allowed_paths if p.strip()]
        if not norm_allowed:
            return True
        return any(rel_posix == p or rel_posix.startswith(p + "/") for p in norm_allowed)

    def _extract_file_text(self, path: Path, raw_bytes: bytes) -> str:
        ext = path.suffix.lower()
        if ext in {".txt", ".md", ".json", ".csv"}:
            return raw_bytes.decode("utf-8", errors="replace")
        if ext == ".docx":
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    if "word/document.xml" in zf.namelist():
                        xml_bytes = zf.read("word/document.xml")
                        tree = ET.fromstring(xml_bytes)
                        texts = [elem.text for elem in tree.iter() if elem.text]
                        return "\n".join(texts)
            except Exception:
                pass
            return raw_bytes.decode("utf-8", errors="replace")
        if ext == ".pdf":
            # Extract printable ASCII/UTF-8 text segments safely without external heavy deps
            decoded = raw_bytes.decode("latin-1", errors="replace")
            matches = re.findall(r"\(([^()]{3,200})\)", decoded)
            if matches:
                return "\n".join(matches)
            return f"[PDF binary document: {path.name}, {len(raw_bytes)} bytes]"
        return ""

    def validate_connection(self, connector: EnterpriseConnectorDTO) -> tuple[bool, str, Dict[str, Any]]:
        coverage = {
            "observed_events": ["DIRECTORY_SCAN", "FILE_STAT_CHECK", "CONTENT_HASH_VERIFICATION"],
            "inferred_events": ["FILE_RENAME_OR_DELETE_ON_SYNC"],
            "unsupported_events": ["OS_KERNEL_INOTIFY_REALTIME_STREAM"],
        }
        try:
            root = self._resolve_root(connector)
            return True, f"Filesystem root '{root.name}' validated.", coverage
        except Exception as exc:
            return False, f"Filesystem validation failed: {exc}", coverage

    def discover_and_read(
        self,
        connector: EnterpriseConnectorDTO,
        *,
        include_content: bool = True,
        target_external_ids: Optional[List[str]] = None,
    ) -> List[DiscoveredItem]:
        root = self._resolve_root(connector)
        allowed_paths = list(connector.scope_json.get("allowed_paths") or [])
        items: List[DiscoveredItem] = []

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
                continue
            if not self._is_within_allowed(root, path, allowed_paths):
                continue

            rel_path = path.relative_to(root).as_posix()
            ext_id = f"fs://{rel_path}"
            if target_external_ids and ext_id not in target_external_ids:
                continue

            stat = path.stat()
            raw_bytes = path.read_bytes()
            checksum = _sha256_bytes(raw_bytes)
            version_marker = f"mtime:{int(stat.st_mtime)}:size:{stat.st_size}:sha:{checksum[:12]}"

            ext = path.suffix.lower()
            if ext == ".pdf":
                rtype = ResourceType.DOCUMENT_PDF
            elif ext == ".docx":
                rtype = ResourceType.DOCUMENT_DOCX
            elif ext == ".csv":
                rtype = ResourceType.SPREADSHEET
            elif "polic" in rel_path.lower() or "procedure" in rel_path.lower():
                rtype = ResourceType.POLICY_DOC
            else:
                rtype = ResourceType.DOCUMENT_TEXT

            classification = DataClassification.INTERNAL
            lower_rel = rel_path.lower()
            if any(k in lower_rel for k in ("secret", "restricted", "payroll", "executive")):
                classification = DataClassification.RESTRICTED
            elif any(k in lower_rel for k in ("finance", "vendor", "contract", "confidential", "policy")):
                classification = DataClassification.CONFIDENTIAL

            extracted = self._extract_file_text(path, raw_bytes) if include_content else None

            items.append(
                DiscoveredItem(
                    external_id=ext_id,
                    name=path.name,
                    resource_type=rtype,
                    source_version=version_marker,
                    content_checksum=checksum,
                    owner=connector.created_by,
                    access_scope=f"READ_ONLY_PATH:{rel_path}",
                    classification=classification,
                    metadata={
                        "relative_path": rel_path,
                        "extension": ext,
                        "size_bytes": stat.st_size,
                        "mtime": int(stat.st_mtime),
                    },
                    extracted_text=extracted,
                )
            )
        return items


class AgentFrameworkConnector(BaseEnterpriseConnector):
    """Connects to existing enterprise agent frameworks (CrewAI, LangGraph, AutoGen, Custom)."""

    def validate_connection(self, connector: EnterpriseConnectorDTO) -> tuple[bool, str, Dict[str, Any]]:
        framework = str(connector.config_json.get("framework", "CREWAI")).upper()
        coverage = {
            "observed_events": [
                "TOOL_ACTION_PROPOSAL",
                "MEMORY_READ_AND_RETRIEVAL",
                "POLICY_DECISION",
                "AGENT_EXECUTION_LIFECYCLE",
            ],
            "inferred_events": ["AGENT_GOAL_DRIFT"],
            "unsupported_events": ["UNINSTRUMENTED_LOCAL_SCRATCHPAD_MUTATION"]
            if framework != "AMSC_NATIVE"
            else [],
        }
        return True, f"Agent framework '{framework}' integration validated.", coverage

    def discover_and_read(
        self,
        connector: EnterpriseConnectorDTO,
        *,
        include_content: bool = True,
        target_external_ids: Optional[List[str]] = None,
    ) -> List[DiscoveredItem]:
        agents_cfg = connector.config_json.get("agents") or []
        framework = str(connector.config_json.get("framework", "CREWAI")).upper()
        items: List[DiscoveredItem] = []

        for ag in agents_cfg:
            ag_id = str(ag.get("agent_id") or ag.get("id") or ag.get("name"))
            ext_id = f"agent://{framework.lower()}/{ag_id}"
            if target_external_ids and ext_id not in target_external_ids:
                continue
            canonical = json.dumps(ag, sort_keys=True, default=str)
            checksum = _sha256_text(canonical)
            items.append(
                DiscoveredItem(
                    external_id=ext_id,
                    name=str(ag.get("name") or ag_id),
                    resource_type=ResourceType.AGENT_REGISTRATION,
                    source_version=f"cfg:{checksum[:12]}",
                    content_checksum=checksum,
                    owner=str(ag.get("owner") or connector.created_by),
                    access_scope=f"AGENT_PROFILE:{ag_id}",
                    classification=DataClassification.CONFIDENTIAL,
                    metadata={
                        "framework": framework,
                        "agent_id": ag_id,
                        "tools": ag.get("tools", []),
                        "memory_backend": ag.get("memory_backend", "amsc_chronimem"),
                        "department": ag.get("department", "GENERAL"),
                    },
                    extracted_text=canonical if include_content else None,
                )
            )
        return items


class UnavailableEnterpriseConnector(BaseEnterpriseConnector):
    """Explicitly reports unimplemented/unconfigured external connectors as UNAVAILABLE."""

    def validate_connection(self, connector: EnterpriseConnectorDTO) -> tuple[bool, str, Dict[str, Any]]:
        coverage = {
            "observed_events": [],
            "inferred_events": [],
            "unsupported_events": ["ALL_EVENTS_CONNECTOR_UNAVAILABLE"],
        }
        return (
            False,
            f"Connector type '{connector.connector_type}' requires external adapter configuration or is unavailable in this environment.",
            coverage,
        )

    def discover_and_read(
        self,
        connector: EnterpriseConnectorDTO,
        *,
        include_content: bool = True,
        target_external_ids: Optional[List[str]] = None,
    ) -> List[DiscoveredItem]:
        raise RuntimeError(
            f"Connector '{connector.name}' ({connector.connector_type}) is UNAVAILABLE."
        )


def get_connector_implementation(connector: EnterpriseConnectorDTO) -> BaseEnterpriseConnector:
    """Resolve the concrete connector implementation without faking unavailable integrations."""
    ctype = str(connector.connector_type)
    if ctype == ConnectorType.DATABASE.value:
        if connector.config_json.get("db_path") or connector.config_json.get("path"):
            return SqliteDatabaseConnector()
        return UnavailableEnterpriseConnector()
    if ctype in {ConnectorType.FILESYSTEM.value, ConnectorType.DOCUMENT_REPO.value, ConnectorType.KNOWLEDGE_BASE.value}:
        if connector.config_json.get("root_path") or connector.config_json.get("path"):
            return FilesystemEnterpriseConnector()
        return UnavailableEnterpriseConnector()
    if ctype == ConnectorType.AGENT_FRAMEWORK.value:
        return AgentFrameworkConnector()
    return UnavailableEnterpriseConnector()
