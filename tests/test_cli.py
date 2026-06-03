from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from leakhunt import cli


def test_url_file_argument_scans_raw_text_when_path_does_not_exist(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main(["-U", "missing-targets.txt", "--no-color"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "No secrets found" in captured.out


def test_main_returns_error_for_invalid_output_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("hello world", encoding="utf-8")
    invalid_output = tmp_path / "missing-dir" / "findings.json"

    exit_code = cli.main(["-f", str(sample), "-o", str(invalid_output), "--no-color"])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert f"Failed to write JSON results to {invalid_output}" in captured.out


def test_parse_args_rejects_non_positive_threads() -> None:
    with pytest.raises(SystemExit):
        cli.parse_args(["-t", "0", "README.md"])


def test_parse_args_rejects_non_numeric_threads() -> None:
    with pytest.raises(SystemExit):
        cli.parse_args(["-t", "many", "README.md"])


def test_main_detects_generic_api_key_with_spaces(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text('api_key = "abcdefghijklmnopqrstuvwxyz123456"', encoding="utf-8")

    exit_code = cli.main(["-f", str(sample), "--no-color"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Generic API Key" in captured.out


def test_main_uses_custom_patterns_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("CUSTOM_SECRET", encoding="utf-8")
    patterns_dir = tmp_path / "patterns"
    patterns_dir.mkdir()
    (patterns_dir / "custom.yaml").write_text(
        "- name: Custom Secret\n"
        "  regex: CUSTOM_SECRET\n"
        "  severity: high\n"
        "  entropy_required: false\n",
        encoding="utf-8",
    )

    exit_code = cli.main(
        ["-f", str(sample), "--patterns-dir", str(patterns_dir), "--no-color"]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Custom Secret" in captured.out


def test_main_prints_structured_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("AKIA1234567890ABCDEF", encoding="utf-8")

    exit_code = cli.main(["-f", str(sample), "--json"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert '"findings"' in captured.out
    assert '"score"' in captured.out
    assert '"reasons"' in captured.out


def test_main_writes_structured_json_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "sample.txt"
    output = tmp_path / "findings.json"
    sample.write_text("AKIA1234567890ABCDEF", encoding="utf-8")

    exit_code = cli.main(["-f", str(sample), "-o", str(output), "--no-color"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Saved JSON results" in captured.out
    assert '"findings"' in output.read_text(encoding="utf-8")
