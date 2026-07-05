"""Core scanning engine for LeakHunt."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .patterns import PATTERNS, SecretPattern
from .utils import shannon_entropy

SAFE_KEYWORDS = ("fake", "test", "dummy", "example")
FALSE_CONTEXT_WINDOW = 30
FRONTEND_KEY_MARKERS = ("data-", "aria-", "class", "id", "style", "offset", "title")
SENSITIVE_KEYWORDS = ("KEY", "TOKEN", "SECRET", "PASS", "AUTH", "URL")
NON_SECRET_VALUE_MARKERS = ("toast", "drag", "modal", "title", "--")
GENERIC_SECRET_TYPES = {
    "Generic API Key",
    "Generic Token",
    "Generic Secret",
    "Environment Variable",
}
MIN_SCORE = 0.85
JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
KEY_VALUE_RE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_-]*)\s*[=:]\s*[\"']?(?P<value>[A-Za-z0-9_+./=-]{20,})[\"']?"
)


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


def _is_generic_pattern(pattern: SecretPattern) -> bool:
    return pattern.name in GENERIC_SECRET_TYPES


def _is_js_source(source: str) -> bool:
    return source.lower().split("?", 1)[0].endswith(JS_EXTENSIONS)


def _extract_key_value(value: str) -> tuple[str | None, str]:
    match = KEY_VALUE_RE.search(value)
    if match is None:
        return None, value.strip("'\"")
    return match.group("key"), match.group("value").strip("'\"")


def _has_sensitive_keyword(key: str | None) -> bool:
    if key is None:
        return False
    return any(keyword in key.upper() for keyword in SENSITIVE_KEYWORDS)


def _is_frontend_key(key: str | None) -> bool:
    if key is None:
        return False
    lowered = key.lower()
    return any(marker in lowered for marker in FRONTEND_KEY_MARKERS)


def _is_non_secret_value(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in NON_SECRET_VALUE_MARKERS)


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
    key, secret_value = _extract_key_value(value)
    generic_pattern = _is_generic_pattern(pattern)

    if is_safe(value) or is_false_context(content, match.start(), match.end()):
        return None
    if _is_frontend_key(key) or _is_non_secret_value(secret_value):
        return None

    has_sensitive_keyword = _has_sensitive_keyword(key)
    entropy = shannon_entropy(secret_value if generic_pattern else value)
    entropy_score = normalize_entropy(entropy)
    pattern_score = 1.0
    context_score = 1.0 if (has_sensitive_keyword or not generic_pattern) else 0.0
    score = calculate_score(pattern_score, entropy_score, context_score)

    if generic_pattern:
        if not has_sensitive_keyword:
            return None
        if not looks_like_secret(secret_value):
            return None
        if entropy < entropy_threshold:
            return None
        if _is_js_source(source) and score < 0.95:
            return None
    elif pattern.entropy_required:
        if not looks_like_secret(value):
            return None
        if entropy < entropy_threshold:
            return None

    if score < MIN_SCORE:
        return None

    reasons = [
        f"regex_match: {pattern.name}",
        f"entropy_score: {entropy:.2f}",
        "context: sensitive_key" if has_sensitive_keyword else "context: clean",
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
    seen_values: set[str] = set()
    active_patterns = PATTERNS if patterns is None else patterns

    for pattern in active_patterns:
        for match in pattern.regex.finditer(content):
            finding = _candidate_from_match(
                content, source, pattern, match, entropy_threshold
            )
            if finding is not None:
                _, secret_value = _extract_key_value(finding.value)
                dedupe_value = secret_value or finding.value
                if dedupe_value in seen_values:
                    continue
                seen_values.add(dedupe_value)
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
