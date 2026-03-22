from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from leakhunt import cli


def test_main_returns_error_for_missing_target_list(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["-U", "missing-targets.txt", "--no-color"])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Failed to read target list missing-targets.txt" in captured.out


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
