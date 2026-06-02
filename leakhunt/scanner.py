"""Core scanning engine for LeakHunt."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .patterns import PATTERNS, SecretPattern
from .utils import shannon_entropy


@dataclass(frozen=True)
class SecretFinding:
    source: str
    secret_type: str
    value: str
    severity: str
    entropy: float

    def to_dict(self) -> dict:
        data = asdict(self)
        data["entropy"] = round(self.entropy, 3)
        return data


def scan_content(
    content: str,
    source: str,
    entropy_threshold: float = 3.5,
    patterns: tuple[SecretPattern, ...] | None = None,
) -> list[SecretFinding]:
    findings_set: set[tuple[str, str, str, str, float]] = set()
    active_patterns = PATTERNS if patterns is None else patterns

    for pattern in active_patterns:
        for match in pattern.regex.finditer(content):
            value = match.group(0).strip()
            entropy = shannon_entropy(value)

            # Skip entropy filtering only if explicitly marked
            if pattern.entropy_required and entropy < entropy_threshold:
                continue

            findings_set.add((source, pattern.name, value, pattern.severity, entropy))

    findings: list[SecretFinding] = [
        SecretFinding(src, stype, val, sev, ent)
        for src, stype, val, sev, ent in findings_set
    ]

    return sorted(
        findings,
        key=lambda f: (f.source, f.secret_type, -f.entropy, f.severity, f.value),
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
        key=lambda f: (f.source, f.secret_type, -f.entropy, f.severity, f.value),
    )
