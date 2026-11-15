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
    # JWT tokens in general
    (re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]+"), r"[JWT_REDACTED]"),
    # Password parameters / fields
    (re.compile(r"(password['\"]?\s*[:=]\s*['\"])[^'\",\s]+(['\"])", re.IGNORECASE), r"\1[REDACTED]\2"),
    # Secret keys / tokens
    (re.compile(r"((?:api[_-]?key|secret|token|private_key)['\"]?\s*[:=]\s*['\"])[^'\",\s]+(['\"])", re.IGNORECASE), r"\1[REDACTED]\2"),
]


class SensitiveDataFilter(logging.Filter):
    """Log filter to scrub passwords, tokens, and secrets from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self.redact(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self.redact(str(arg)) for arg in record.args)
        return True

    @staticmethod
    def redact(text: str) -> str:
        """Apply regex redactions to input text string."""
        for pattern, replacement in SENSITIVE_PATTERNS:
            text = pattern.sub(replacement, text)
        return text


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

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(SensitiveDataFilter())
        root_logger.addHandler(handler)
    else:
        for handler in root_logger.handlers:
            handler.setLevel(numeric_level)
            handler.addFilter(SensitiveDataFilter())

    logger = logging.getLogger("amsc")
    logger.setLevel(numeric_level)
    return logger
