"""Regex patterns and metadata for secret detection."""

from __future__ import annotations

import re
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Pattern


DEFAULT_PATTERNS_DIR = Path(__file__).with_name("patterns")


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: Pattern[str]
    severity: str
    entropy_required: bool = True


def load_yaml_pattern(pattern_file: Path) -> list[SecretPattern]:
    """Load patterns from single YAML file."""
    patterns = []
    with open(pattern_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []
        for item in data:
            regex = re.compile(item["regex"], re.IGNORECASE | re.MULTILINE)
            patterns.append(SecretPattern(
                name=item["name"],
                regex=regex,
                severity=item["severity"],
                entropy_required=item.get("entropy_required", True)
            ))
    return patterns


def load_patterns(patterns_dir: str | Path | None = None) -> tuple[SecretPattern, ...]:
    """Load YAML patterns from directory."""
    patterns_dir_path = Path(patterns_dir) if patterns_dir is not None else DEFAULT_PATTERNS_DIR
    all_patterns = _hardcoded_fallback() if patterns_dir is None else []
    
    if patterns_dir_path.exists():
        for yaml_file in sorted(patterns_dir_path.glob("*.yaml")):
            try:
                all_patterns.extend(load_yaml_pattern(yaml_file))
            except Exception as e:
                print(f"Warning: Failed to load {yaml_file}: {e}")
    
    # Fallback to hardcoded if no YAML found in a custom directory
    if not all_patterns:
        all_patterns = _hardcoded_fallback()
    
    return tuple(all_patterns)


def _hardcoded_fallback() -> list[SecretPattern]:
    """Legacy hardcoded patterns as fallback."""
    return [
        SecretPattern("GitHub Token (classic)", re.compile(r"ghp_[A-Za-z0-9]{36,40}"), "high", False),
        SecretPattern("GitHub Fine-grained PAT", re.compile(r"github_pat_[A-Za-z0-9_]{80,}"), "high", False),
        SecretPattern("Discord Token", re.compile(r"[A-Za-z\d]{24}\.[\w-]{6}\.[\w-]{27}"), "high", False),
        SecretPattern("Firebase API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "medium", True),
        SecretPattern("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "high", False),
        SecretPattern("OAuth Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "medium", True),
        SecretPattern("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), "high", False),
        SecretPattern("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9_\-]{16,64}\.[A-Za-z0-9_\-]{16,64}"), "high", True),
        SecretPattern("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), "high", False),
        SecretPattern("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "high", False),
        SecretPattern("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}"), "medium", True),
        SecretPattern("Generic API Key", re.compile(r'api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9_-]{16,128}["\']?'), "medium", False),
        SecretPattern("Generic Token", re.compile(r'token\s*[=:]\s*["\']?[A-Za-z0-9_-]{16,128}["\']?'), "medium", False),
    ]


# Auto-load on import (supports --patterns-dir)
PATTERNS = load_patterns()
