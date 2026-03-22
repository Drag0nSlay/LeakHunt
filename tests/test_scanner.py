from __future__ import annotations

from leakhunt.scanner import scan_many


def test_scan_many_returns_findings_in_sorted_order() -> None:
    items = [
        ("b.txt", "AKIA1234567890ABCDEF"),
        ("a.txt", "ghp_123456789012345678901234567890123456"),
    ]

    findings = scan_many(items)

    assert [finding.source for finding in findings] == ["a.txt", "b.txt"]
