"""Application Logging Configuration with Sensitive Data Redaction.

Module: backend.app.core.logging
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 Section 3: High-Assurance Gateway
- Master Prompt Section 9.6: Logging Security (No secrets, passwords, or complete tokens)
"""

import logging
import re
from typing import Optional


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
    # Password parameters / fields in JSON, query strings, or key-value pairs (including passwords with spaces inside quotes)
    (re.compile(r"((?:password|passwd|hashed_password|current_password|new_password|client_secret|secret_key)['\"]?\s*[:=]\s*['\"])[^'\"]*(['\"])", re.IGNORECASE), r"\1[REDACTED]\2"),
    # Query / URL parameters with passwords, tokens, or keys
    (re.compile(r"((?:token|secret|password|passwd|api[_-]?key|client[_-]?secret)=)[^&\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    # Secret keys / tokens / private keys
    (re.compile(r"((?:api[_-]?key|secret|token|private_key)['\"]?\s*[:=]\s*['\"])[^'\"]*(['\"])", re.IGNORECASE), r"\1[REDACTED]\2"),
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


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configure centralized application logger.

    Args:
        log_level: Logging level name ('DEBUG', 'INFO', 'WARNING', 'ERROR')

    Returns:
        Configured logger instance.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

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
