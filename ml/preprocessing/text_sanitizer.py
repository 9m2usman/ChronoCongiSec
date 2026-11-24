"""Input validation, normalization, secret redaction, and tokenization for ML."""

from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Tuple

MAX_TEXT_CHARS = 32_768
MAX_TOKEN_COUNT = 4_096

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE_RE = re.compile(r"\s+")
_WORD_RE = re.compile(r"[a-z0-9_]{2,}")

# Redaction patterns so sensitive enterprise data never leaks into ML logs/artifacts
_SECRET_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(?:bearer|token|api[_-]?key|secret|password|passwd)\s*[:=]\s*['\"]?[^\s'\"]{6,}"), "[REDACTED_SECRET]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
)


def sanitize_text_for_ml(raw: object, max_chars: int = MAX_TEXT_CHARS) -> Tuple[str, bool]:
    """Validate and normalize untrusted text before ML feature extraction.

    Returns ``(clean_text, was_truncated)``.
    Raises ``ValueError`` if input is not a string.
    """
    if not isinstance(raw, str):
        raise ValueError(f"Expected str input for ML text sanitizer, got {type(raw).__name__}")

    was_truncated = len(raw) > max_chars
    bounded = raw[:max_chars]
    # NFKC normalization collapses homoglyphs / full-width evasion characters
    normalized = unicodedata.normalize("NFKC", bounded)
    stripped = _CONTROL_CHARS_RE.sub(" ", normalized)
    collapsed = _WHITESPACE_RE.sub(" ", stripped).strip()
    return collapsed, was_truncated


def redact_sensitive_text(text: str) -> str:
    """Redact secrets and PII before writing any ML diagnostic or evaluation log."""
    out = text
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def extract_ngrams(
    text: str,
    word_ngram_range: Tuple[int, int] = (1, 2),
    char_ngram_range: Tuple[int, int] = (3, 5),
    max_tokens: int = MAX_TOKEN_COUNT,
) -> List[str]:
    """Extract deterministic word + character n-gram tokens from normalized text."""
    lowered = text.lower()
    words = _WORD_RE.findall(lowered)[:max_tokens]
    tokens: List[str] = []

    w_min, w_max = word_ngram_range
    for n in range(w_min, w_max + 1):
        if n == 1:
            tokens.extend(f"w:{w}" for w in words)
        else:
            for i in range(max(0, len(words) - n + 1)):
                tokens.append("w:" + "_".join(words[i : i + n]))

    # Character n-grams on bounded lowercase text (catch obfuscation/leetspeak/splits)
    char_src = lowered[:2048]
    c_min, c_max = char_ngram_range
    padded = f" {char_src} "
    for n in range(c_min, c_max + 1):
        for i in range(max(0, len(padded) - n + 1)):
            gram = padded[i : i + n]
            if gram.strip():
                tokens.append(f"c:{gram}")

    return tokens


def term_frequency(tokens: List[str]) -> Dict[str, int]:
    """Compute raw term frequency dictionary."""
    tf: Dict[str, int] = {}
    for tok in tokens:
        tf[tok] = tf.get(tok, 0) + 1
    return tf
