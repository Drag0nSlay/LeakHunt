"""Core scanning engine for LeakHunt."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .patterns import PATTERNS
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


# Patterns that should NOT be filtered by entropy
STRICT_PATTERNS = {
    "AWS Access Key ID",
    "GitHub Token (classic)",
    "GitHub Fine-grained PAT",
    "Private Key Block",
}


def scan_content(
    content: str,
    source: str,
    entropy_threshold: float = 3.5,
) -> list[SecretFinding]:
    findings_set: set[tuple[str, str, str, str]] = set()

    for item in PATTERNS:
        for match in item.regex.finditer(content):
            value = match.group(0).strip()
            entropy = shannon_entropy(value)

            # Skip entropy filtering for strict patterns
            if (
                item.name not in STRICT_PATTERNS
                and entropy < entropy_threshold
            ):
                continue

            findings_set.add((source, item.name, value, item.severity))

    findings: list[SecretFinding] = [
        SecretFinding(
            source=src,
            secret_type=stype,
            value=val,
            severity=sev,
            entropy=shannon_entropy(val),
        )
        for src, stype, val, sev in findings_set
    ]

    return sorted(
        findings,
        key=lambda f: (f.source, f.secret_type, -f.entropy),
    )


def scan_many(
    items: list[tuple[str, str]],
    entropy_threshold: float = 3.5,
) -> list[SecretFinding]:
    all_findings: list[SecretFinding] = []
    for source, content in items:
        all_findings.extend(
            scan_content(
                content,
                source,
                entropy_threshold=entropy_threshold,
            )
        )
    return sorted(
        all_findings,
        key=lambda f: (f.source, f.secret_type, -f.entropy),
    )
