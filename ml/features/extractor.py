"""Feature extraction from authorized AMSC observations, memory, and proposals."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from ml.preprocessing.text_sanitizer import extract_ngrams, sanitize_text_for_ml

_STOPWORDS: Set[str] = {
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "were",
    "have", "has", "had", "will", "would", "shall", "should", "can", "could",
    "may", "might", "into", "onto", "upon", "about", "under", "over", "between",
    "through", "during", "before", "after", "above", "below", "been", "being",
    "their", "there", "these", "those", "which", "what", "when", "where", "who",
    "whom", "whose", "they", "them", "then", "than", "also", "only", "such",
}

_DIRECTIVE_MARKERS = re.compile(
    r"(?i)\b(?:ignore|disregard|override|bypass|forget|supersede|replace|execute|"
    r"forward|exfiltrate|transmit|escalate|grant|elevate|disable|reveal|dump|print)\b"
)
_BOUNDARY_MARKERS = re.compile(
    r"(?i)(?:<\|.*?\|>|\[/?(?:system|inst|admin|override|assistant)\]|---+\s*(?:begin|end)|```\s*system)"
)
_BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{28,}={0,2}\b")

_NEGATION_RE = re.compile(
    r"(?i)\b(?:not|never|no|none|neither|nor|prohibited|forbidden|disallowed|"
    r"unauthorized|unpermitted|blocked|restricted|revoked|denied|without|cannot|must\s+not)\b"
)
_PERMISSIVE_RE = re.compile(
    r"(?i)\b(?:allowed|permitted|authorized|approved|unrestricted|granted|exempt|"
    r"valid|active|enabled|waived|unlimited)\b"
)
_CONSTRAINT_RE = re.compile(
    r"(?i)\b(?:must|shall|required|requires|approval|ceiling|limit|maximum|max|"
    r"confidential|restricted|only|strictly|prohibited|forbidden|never)\b"
)
_CURRENCY_OR_NUM_RE = re.compile(r"\$?\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?)")


@dataclass(frozen=True)
class TextSecurityFeatures:
    """Extracted structural + lexical features for injection/poisoning analysis."""

    clean_text: str
    was_truncated: bool
    char_length: int
    directive_density: float
    boundary_marker_count: int
    base64_blob_count: int
    tokens: Tuple[str, ...]


def extract_text_security_features(raw_text: str) -> TextSecurityFeatures:
    """Sanitize and extract structural + n-gram features from untrusted text."""
    clean, truncated = sanitize_text_for_ml(raw_text)
    tokens = tuple(extract_ngrams(clean, word_ngram_range=(1, 2), char_ngram_range=(3, 5)))
    word_count = max(1, len(clean.split()))
    directives = len(_DIRECTIVE_MARKERS.findall(clean))
    boundaries = len(_BOUNDARY_MARKERS.findall(clean))
    b64_count = len(_BASE64_BLOB_RE.findall(clean))
    return TextSecurityFeatures(
        clean_text=clean,
        was_truncated=truncated,
        char_length=len(clean),
        directive_density=min(1.0, directives / word_count),
        boundary_marker_count=boundaries,
        base64_blob_count=b64_count,
        tokens=tokens,
    )


def _content_words(text: str) -> Set[str]:
    words = re.findall(r"\b[a-z]{3,}\b", text.lower())
    return {w for w in words if w not in _STOPWORDS}


def _extract_numbers(text: str) -> List[float]:
    nums: List[float] = []
    for match in _CURRENCY_OR_NUM_RE.findall(text):
        try:
            val = float(match.replace(",", ""))
            if math.isfinite(val):
                nums.append(val)
        except ValueError:
            continue
    return nums


def _tfidf_cosine(text_a: str, text_b: str) -> float:
    """Compute character+word n-gram cosine similarity between two texts."""
    toks_a = extract_ngrams(text_a, word_ngram_range=(1, 2), char_ngram_range=(3, 4))
    toks_b = extract_ngrams(text_b, word_ngram_range=(1, 2), char_ngram_range=(3, 4))
    if not toks_a or not toks_b:
        return 0.0
    tf_a: Dict[str, float] = {}
    tf_b: Dict[str, float] = {}
    for t in toks_a:
        tf_a[t] = tf_a.get(t, 0.0) + 1.0
    for t in toks_b:
        tf_b[t] = tf_b.get(t, 0.0) + 1.0

    # Sublinear TF scaling: 1 + log(tf)
    for k in tf_a:
        tf_a[k] = 1.0 + math.log(tf_a[k])
    for k in tf_b:
        tf_b[k] = 1.0 + math.log(tf_b[k])

    dot = sum(tf_a[k] * tf_b[k] for k in tf_a if k in tf_b)
    norm_a = math.sqrt(sum(v * v for v in tf_a.values()))
    norm_b = math.sqrt(sum(v * v for v in tf_b.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return max(0.0, min(1.0, dot / (norm_a * norm_b)))


@dataclass(frozen=True)
class SemanticPairFeatures:
    """Feature vector comparing a derived/claim text against a source/baseline text."""

    cosine_similarity: float
    entity_coverage: float
    constraint_preservation: float
    negation_flip: float
    permissive_expansion: float
    numeric_expansion_ratio: float
    length_ratio: float

    def to_vector(self) -> List[float]:
        return [
            self.cosine_similarity,
            self.entity_coverage,
            self.constraint_preservation,
            self.negation_flip,
            self.permissive_expansion,
            self.numeric_expansion_ratio,
            self.length_ratio,
        ]

    def to_dict(self) -> Dict[str, float]:
        return {
            "cosine_similarity": round(self.cosine_similarity, 4),
            "entity_coverage": round(self.entity_coverage, 4),
            "constraint_preservation": round(self.constraint_preservation, 4),
            "negation_flip": round(self.negation_flip, 4),
            "permissive_expansion": round(self.permissive_expansion, 4),
            "numeric_expansion_ratio": round(self.numeric_expansion_ratio, 4),
            "length_ratio": round(self.length_ratio, 4),
        }


def extract_semantic_pair_features(
    claim_text: str,
    reference_text: str,
) -> SemanticPairFeatures:
    """Extract semantic drift, contradiction, and grounding features."""
    clean_claim, _ = sanitize_text_for_ml(claim_text)
    clean_ref, _ = sanitize_text_for_ml(reference_text)

    cosine = _tfidf_cosine(clean_claim, clean_ref)
    claim_words = _content_words(clean_claim)
    ref_words = _content_words(clean_ref)
    if ref_words:
        entity_cov = len(claim_words & ref_words) / max(1, min(len(ref_words), max(1, len(claim_words))))
        entity_cov = min(1.0, entity_cov)
    else:
        entity_cov = 0.0

    ref_constraints = {m.lower() for m in _CONSTRAINT_RE.findall(clean_ref)}
    claim_constraints = {m.lower() for m in _CONSTRAINT_RE.findall(clean_claim)}
    if ref_constraints:
        constraint_pres = len(ref_constraints & claim_constraints) / len(ref_constraints)
    else:
        constraint_pres = 1.0

    ref_neg = len(_NEGATION_RE.findall(clean_ref))
    claim_neg = len(_NEGATION_RE.findall(clean_claim))
    ref_perm = len(_PERMISSIVE_RE.findall(clean_ref))
    claim_perm = len(_PERMISSIVE_RE.findall(clean_claim))

    negation_flip = 1.0 if ((ref_neg > 0 and claim_neg == 0) or (ref_neg == 0 and claim_neg > 0)) else 0.0
    permissive_exp = 1.0 if (ref_neg > 0 and claim_perm > ref_perm and claim_neg == 0) else 0.0

    ref_nums = _extract_numbers(clean_ref)
    claim_nums = _extract_numbers(clean_claim)
    if ref_nums and claim_nums:
        ref_max = max(ref_nums)
        claim_max = max(claim_nums)
        if ref_max > 0:
            ratio = claim_max / ref_max
            # Squash ratio > 1 into [0, 1] via 1 - 1/ratio
            num_exp = 0.0 if ratio <= 1.05 else min(1.0, 1.0 - (1.0 / ratio))
        else:
            num_exp = 1.0 if claim_max > 0 else 0.0
    else:
        num_exp = 0.0

    len_ratio = min(1.0, len(clean_claim) / max(1, len(clean_ref)))
    return SemanticPairFeatures(
        cosine_similarity=cosine,
        entity_coverage=entity_cov,
        constraint_preservation=constraint_pres,
        negation_flip=negation_flip,
        permissive_expansion=permissive_exp,
        numeric_expansion_ratio=num_exp,
        length_ratio=len_ratio,
    )


@dataclass(frozen=True)
class BehavioralEvent:
    """Normalized behavioral event extracted from AMSC ObservationEvent or Proposal."""

    tenant_id: str
    branch_id: str
    agent_id: str
    department: str
    tool_name: str
    operation: str
    amount: Optional[float] = None
    timestamp: float = 0.0
    outcome: str = "SUBMITTED"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def action_key(self) -> str:
        return f"{self.tool_name}:{self.operation}".lower()


def extract_behavioral_event(
    tenant_id: str,
    agent_id: str,
    tool_name: str,
    operation: str,
    parameters: Optional[Mapping[str, Any]] = None,
    branch_id: Optional[str] = None,
    department: Optional[str] = None,
    timestamp: Optional[float] = None,
    outcome: str = "SUBMITTED",
) -> BehavioralEvent:
    """Build a strictly validated, tenant-scoped BehavioralEvent."""
    if not tenant_id or not isinstance(tenant_id, str):
        raise ValueError("tenant_id is required for behavioral feature extraction")
    if not agent_id or not isinstance(agent_id, str):
        raise ValueError("agent_id is required for behavioral feature extraction")

    params = parameters if isinstance(parameters, Mapping) else {}
    amount: Optional[float] = None
    raw_amt = params.get("amount")
    if raw_amt is not None and not isinstance(raw_amt, bool):
        try:
            parsed = float(raw_amt)
            if math.isfinite(parsed):
                amount = parsed
        except (TypeError, ValueError):
            amount = None

    ts = 0.0
    if timestamp is not None and not isinstance(timestamp, bool):
        try:
            parsed_ts = float(timestamp)
            if math.isfinite(parsed_ts) and parsed_ts >= 0.0:
                ts = parsed_ts
        except (TypeError, ValueError):
            ts = 0.0

    return BehavioralEvent(
        tenant_id=tenant_id,
        branch_id=branch_id or "default",
        agent_id=agent_id,
        department=(department or "general").lower(),
        tool_name=(tool_name or "unknown").strip()[:128],
        operation=(operation or "unknown").strip()[:128],
        amount=amount,
        timestamp=ts,
        outcome=outcome,
    )
