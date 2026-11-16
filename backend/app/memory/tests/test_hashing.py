"""Tests for SHA-256 content hashing in the Memory & Provenance engine."""

import hashlib
import sys
from pathlib import Path

# Ensure repo root is in sys.path
repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

try:
    from backend.app.memory.hashing import sha256_hex
except ModuleNotFoundError:
    from ..hashing import sha256_hex


EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_same_content_gives_same_hash():
    """Identical content must produce identical SHA-256 hex digests."""
    text_a = "Standard operational procedure for Treasury agent wire verification."
    text_b = "Standard operational procedure for Treasury agent wire verification."

    hash_a = sha256_hex(text_a)
    hash_b = sha256_hex(text_b)

    assert hash_a == hash_b
    assert len(hash_a) == 64
    assert hash_a == hashlib.sha256(text_a.strip().encode("utf-8")).hexdigest()


def test_line_ending_normalization_gives_same_hash():
    """Content with CRLF, CR, and LF line endings must produce the exact same hash."""
    lf_content = "Line 1\nLine 2\nLine 3"
    crlf_content = "Line 1\r\nLine 2\r\nLine 3"
    cr_content = "Line 1\rLine 2\rLine 3"

    hash_lf = sha256_hex(lf_content)
    hash_crlf = sha256_hex(crlf_content)
    hash_cr = sha256_hex(cr_content)

    assert hash_lf == hash_crlf
    assert hash_lf == hash_cr


def test_whitespace_and_newline_stripping():
    """Document 02 §15.1: SHA256(UTF8(Strip(content))). 'abc' and '  abc\\n' produce identical hashes."""
    assert sha256_hex("abc") == sha256_hex("  abc\n")


def test_changed_content_gives_different_hash():
    """Any modification in content must produce a different SHA-256 hash."""
    original = "Transfer routing: Account 12345 to Vendor Acme Corp."
    tampered = "Transfer routing: Account 12345 to Attacker ACC-ATTACKER-999."

    hash_original = sha256_hex(original)
    hash_tampered = sha256_hex(tampered)

    assert hash_original != hash_tampered

    # Single character difference
    hash_single_char_diff = sha256_hex(original + "!")
    assert hash_original != hash_single_char_diff


def test_empty_input_handled():
    """Empty string, whitespace-only, and None must be handled safely without error, returning canonical empty hash."""
    hash_empty = sha256_hex("")
    assert hash_empty == EMPTY_SHA256
    assert len(hash_empty) == 64

    # Whitespace-only string strips to empty string
    hash_whitespace = sha256_hex("   \n\r\n  ")
    assert hash_whitespace == EMPTY_SHA256

    # None handling
    hash_none = sha256_hex(None)
    assert hash_none == EMPTY_SHA256
