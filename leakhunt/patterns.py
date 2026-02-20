"""Regex patterns and metadata for secret detection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: Pattern[str]
    severity: str


# Independent pattern bank (no external scanner dependencies).
PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("GitHub Token (classic)", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "high"),
    SecretPattern("GitHub Fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{80,}\b"), "high"),
    SecretPattern("Discord Token", re.compile(r"\b[A-Za-z\d]{24}\.[\w-]{6}\.[\w-]{27}\b"), "high"),
    SecretPattern("Firebase API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "medium"),
    SecretPattern("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "high"),
    SecretPattern("OAuth Bearer Token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b"), "medium"),
    SecretPattern("Mailgun API Key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "high"),
    SecretPattern("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,64}\.[A-Za-z0-9_\-]{16,64}\b"), "high"),
    SecretPattern("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    SecretPattern("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    SecretPattern("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b"), "medium"),
)