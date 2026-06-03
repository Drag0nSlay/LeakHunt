from __future__ import annotations

from leakhunt.scanner import scan_many


def test_scan_many_returns_findings_in_sorted_order() -> None:
    items = [
        ("b.txt", "AKIA1234567890ABCDEF"),
        ("a.txt", "ghp_123456789012345678901234567890123456"),
    ]

    findings = scan_many(items)

    assert [finding.source for finding in findings] == ["a.txt", "b.txt"]


def test_scan_many_detects_spaced_generic_api_key_assignment() -> None:
    findings = scan_many(
        [("secrets.txt", 'api_key = "abcdefghijklmnopqrstuvwxyz123456"')]
    )

    assert any(finding.secret_type == "Generic API Key" for finding in findings)


def test_scan_many_keeps_full_secret_value() -> None:
    secret = "AKIA1234567890ABCDEF"

    findings = scan_many([("secrets.txt", secret)])

    assert any(finding.value == secret for finding in findings)


def test_scan_many_suppresses_fake_context() -> None:
    findings = scan_many(
        [("secrets.txt", "example fake key AKIAFAKEACCESSKEY123 for docs")]
    )

    assert not findings


def test_scan_many_adds_explainability_reasons_and_score() -> None:
    findings = scan_many([("secrets.txt", "xoxb-1234567890-ABCDEFGHIJ")])

    assert findings
    assert findings[0].score > 0
    assert any(reason.startswith("regex_match:") for reason in findings[0].reasons)
    assert any(reason.startswith("entropy_score:") for reason in findings[0].reasons)
    assert "context: clean" in findings[0].reasons
