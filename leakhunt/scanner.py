"""Core scanning engine for LeakHunt."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .patterns import PATTERNS, SecretPattern
from .utils import shannon_entropy

SAFE_KEYWORDS = ("fake", "test", "dummy", "example")
FALSE_CONTEXT_WINDOW = 30


def is_false_context(text: str, start: int, end: int) -> bool:
    """Return True when words around a match indicate sample/test data."""
    window = text[
        max(0, start - FALSE_CONTEXT_WINDOW) : end + FALSE_CONTEXT_WINDOW
    ].lower()
    return any(word in window for word in SAFE_KEYWORDS)


def is_safe(value: str) -> bool:
    """Return True when the candidate value itself is clearly allowlisted."""
    return any(keyword in value.lower() for keyword in SAFE_KEYWORDS)


def looks_like_secret(value: str) -> bool:
    """Apply a lightweight token-shape check before entropy-only decisions."""
    return (
        len(value) > 16
        and any(char.isdigit() for char in value)
        and any(char.isalpha() for char in value)
    )


def normalize_entropy(entropy: float) -> float:
    """Normalize Shannon entropy into the 0-1 range used by hybrid scoring."""
    return min(entropy / 5.0, 1.0)


def calculate_score(
    pattern_score: float, entropy_score: float, context_score: float
) -> float:
    """Calculate the weighted classifier score for a candidate secret."""
    return max(
        0.0,
        min(1.0, (0.5 * pattern_score) + (0.3 * entropy_score) + (0.2 * context_score)),
    )


@dataclass(frozen=True)
class SecretFinding:
    source: str
    secret_type: str
    value: str
    severity: str
    entropy: float
    score: float
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["entropy"] = round(self.entropy, 3)
        data["score"] = round(self.score, 3)
        data["reasons"] = list(self.reasons)
        return data


def _candidate_from_match(
    content: str,
    source: str,
    pattern: SecretPattern,
    match,
    entropy_threshold: float,
) -> SecretFinding | None:
    # Keep the full regex match internally. Any masking/truncation is done only by output code.
    value = match.group(0).strip()
    if is_safe(value) or is_false_context(content, match.start(), match.end()):
        return None

    entropy = shannon_entropy(value)
    entropy_score = normalize_entropy(entropy)
    pattern_score = 1.0
    context_score = 0.0
    score = calculate_score(pattern_score, entropy_score, context_score)

    if pattern.entropy_required:
        if not looks_like_secret(value):
            return None
        minimum_score = calculate_score(
            pattern_score, normalize_entropy(entropy_threshold), context_score
        )
        if score < minimum_score:
            return None

    reasons = [
        f"regex_match: {pattern.name}",
        f"entropy_score: {entropy:.2f}",
        "context: clean",
        f"weighted_score: {score:.2f}",
    ]

    return SecretFinding(
        source=source,
        secret_type=pattern.name,
        value=value,
        severity=pattern.severity,
        entropy=entropy,
        score=score,
        reasons=tuple(reasons),
    )


def scan_content(
    content: str,
    source: str,
    entropy_threshold: float = 3.5,
    patterns: tuple[SecretPattern, ...] | None = None,
) -> list[SecretFinding]:
    findings_set: set[SecretFinding] = set()
    active_patterns = PATTERNS if patterns is None else patterns

    for pattern in active_patterns:
        for match in pattern.regex.finditer(content):
            finding = _candidate_from_match(
                content, source, pattern, match, entropy_threshold
            )
            if finding is not None:
                findings_set.add(finding)

    return sorted(
        findings_set,
        key=lambda f: (
            f.source,
            f.secret_type,
            -f.score,
            -f.entropy,
            f.severity,
            f.value,
        ),
    )


def scan_many(
    items: list[tuple[str, str]],
    entropy_threshold: float = 3.5,
    patterns: tuple[SecretPattern, ...] | None = None,
) -> list[SecretFinding]:
    all_findings: list[SecretFinding] = []
    for source, content in items:
        all_findings.extend(
            scan_content(
                content,
                source,
                entropy_threshold=entropy_threshold,
                patterns=patterns,
            )
        )
    return sorted(
        all_findings,
        key=lambda f: (
            f.source,
            f.secret_type,
            -f.score,
            -f.entropy,
            f.severity,
            f.value,
        ),
    )
