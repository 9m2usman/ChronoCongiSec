"""Application Logging Configuration with Sensitive Data Redaction.

Module: backend.app.core.logging
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 Section 3: High-Assurance Gateway
- Master Prompt Section 9.6: Logging Security (No secrets, passwords, or complete tokens)
"""

import json
import logging
import re
from typing import Any, Optional


# Regular expressions for identifying sensitive data in log streams
SENSITIVE_PATTERNS = [
    # Authorization header / Bearer token
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{10,}", re.IGNORECASE), r"\1[REDACTED]"),
    # General Authorization and API Key headers in key-value or JSON structures
    (re.compile(r"((?:authorization|x-api-key)['\"]?\s*[:=]\s*['\"]?)(?:Bearer\s+)?[^\s,'\"]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED]\2"),
    # JWT tokens in general (header.payload.signature)
    (re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]+"), r"[JWT_REDACTED]"),
    # Database and cache connection URIs with embedded credentials (e.g., postgresql+asyncpg://user:pass@host, redis://:pass@host)
    (re.compile(r"([a-zA-Z0-9\+\.\-]+://(?:[^:\s]*:))([^@\s]+)(@)"), r"\1[REDACTED]\3"),
    # Quoted password/secret parameters in JSON, dicts, or strings (including passwords with spaces inside quotes)
    (re.compile(r"((?:password|passwd|hashed_password|current_password|new_password|client_secret|secret_key|api[_-]?key|access_token|refresh_token|private_key)['\"]?\s*[:=]\s*['\"])(?:\\.|[^'\"])*(['\"])", re.IGNORECASE), r"\1[REDACTED]\2"),
    # Unquoted password/secret parameters in key-value, YAML, CLI, or log outputs (e.g., password: MySecret or password = MySecret)
    (re.compile(r"((?:password|passwd|hashed_password|current_password|new_password|client_secret|secret_key|api[_-]?key|access_token|refresh_token|private_key)['\"]?\s*[:=]\s*)(?!['\"])[^\s,;}{)\]&]+", re.IGNORECASE), r"\1[REDACTED]"),
    # Query / URL parameters with passwords, tokens, or keys
    (re.compile(r"((?:token|secret|password|passwd|api[_-]?key|client[_-]?secret)\s*=\s*)[^\s&]+", re.IGNORECASE), r"\1[REDACTED]"),
    # Private cryptographic keys (PEM format)
    (re.compile(r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----", re.IGNORECASE), "[PRIVATE_KEY_REDACTED]"),
    # Sensitive prompt disclosures in logs
    (re.compile(r"((?:system_prompt|prompt)['\"]?\s*[:=]\s*['\"])(?:\\.|[^'\"])*(['\"])", re.IGNORECASE), r"\1[PROMPT_REDACTED]\2"),
    (re.compile(r"((?:system_prompt|prompt)['\"]?\s*[:=]\s*)(?!['\"])[^\s,;}{)\]&]+", re.IGNORECASE), r"\1[PROMPT_REDACTED]"),
]


class SensitiveDataFilter(logging.Filter):
    """Log filter to scrub passwords, tokens, and secrets from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (self.redact(v) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, (tuple, list)):
                record.args = tuple(
                    (self.redact(arg) if isinstance(arg, str) else arg)
                    for arg in record.args
                )
        if hasattr(record, "exc_text") and record.exc_text:
            record.exc_text = self.redact(record.exc_text)
        return True

    @staticmethod
    def redact(text: str) -> str:
        """Apply regex redactions to input text string."""
        for pattern, replacement in SENSITIVE_PATTERNS:
            text = pattern.sub(replacement, text)
        return text


class RedactingFormatter(logging.Formatter):
    """Logging formatter that scrubs sensitive patterns from messages and tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        s = super().format(record)
        return SensitiveDataFilter.redact(s)

    def formatException(self, ei) -> str:
        s = super().formatException(ei)
        return SensitiveDataFilter.redact(s)


class StructuredJsonFormatter(logging.Formatter):
    """Structured allowlisted JSON log formatter (Finding G / GAP-034).

    Strictly logs allowlisted safe fields: timestamp, level, logger, message,
    correlation_id, event_id, error_category, tenant_id, record_id.
    Prevents raw tracebacks, unvetted extras, secrets, tokens, and sensitive memory from leaking.
    """
    ALLOWLISTED_FIELDS = {
        "event_id",
        "error_category",
        "correlation_id",
        "tenant_id",
        "record_id",
        "span_id",
        "service",
    }

    def format(self, record: logging.LogRecord) -> str:
        base_msg = record.getMessage()
        sanitized_msg = SensitiveDataFilter.redact(base_msg)

        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitized_msg,
        }

        # Include allowlisted structured extras
        for field in self.ALLOWLISTED_FIELDS:
            val = getattr(record, field, None)
            if val is not None:
                payload[field] = SensitiveDataFilter.redact(str(val))

        # Include safe sanitized exception summary if present (never raw dump)
        if record.exc_info and record.exc_info[0]:
            payload["exception_class"] = record.exc_info[0].__name__
            if record.exc_info[1]:
                payload["error_summary"] = SensitiveDataFilter.redact(str(record.exc_info[1]))

        return json.dumps(payload)


def setup_logging(log_level: str = "INFO", structured_json: bool = False) -> logging.Logger:
    """Configure centralized application logger.

    Args:
        log_level: Logging level name ('DEBUG', 'INFO', 'WARNING', 'ERROR')
        structured_json: Flag to format output as structured allowlisted JSON (Finding G)

    Returns:
        Configured logger instance.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    if structured_json:
        formatter: logging.Formatter = StructuredJsonFormatter()
    else:
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    data_filter = SensitiveDataFilter()

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        handler.addFilter(data_filter)
        root_logger.addHandler(handler)
    else:
        for handler in root_logger.handlers:
            handler.setLevel(numeric_level)
            handler.setFormatter(formatter)
            handler.addFilter(data_filter)

    logger = logging.getLogger("amsc")
    logger.setLevel(numeric_level)
    return logger
