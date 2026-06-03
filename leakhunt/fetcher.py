"""Fetch content from URLs and local files."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
from urllib.request import Request, urlopen


@dataclass
class FetchResult:
    source: str
    content: str
    error: str | None = None


def is_url(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme in {"http", "https"}


def detect_input_mode(target: str) -> str:
    """Detect whether a target is a URL, local file, or raw text snippet."""
    if target.startswith(("http://", "https://")):
        return "url"
    if os.path.exists(target):
        return "file"
    return "raw_text"


def _read_file_safely(path: Path) -> str:
    """
    Attempt to read file using multiple encodings.
    Prevents UTF-16 / BOM issues on Windows.
    """
    encodings_to_try = ["utf-8", "utf-8-sig", "utf-16", "latin-1"]

    for enc in encodings_to_try:
        try:
            return path.read_text(encoding=enc)
        except Exception:
            continue

    # Fallback raw decode
    return path.read_bytes().decode(errors="ignore")


def fetch_target(target: str, timeout: int = 10) -> FetchResult:
    mode = detect_input_mode(target)
    if mode == "url":
        try:
            req = Request(
                target,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            with urlopen(req, timeout=timeout) as response:  # noqa: S310
                return FetchResult(
                    source=target,
                    content=response.read().decode("utf-8", errors="ignore"),
                )
        except Exception as exc:  # noqa: BLE001
            return FetchResult(source=target, content="", error=str(exc))

    if mode == "raw_text":
        return FetchResult(source="raw_text", content=target)

    path = Path(target)
    if not path.is_file():
        return FetchResult(source=target, content="", error="Path is not a file")

    try:
        return FetchResult(source=target, content=_read_file_safely(path))
    except Exception as exc:  # noqa: BLE001
        return FetchResult(source=target, content="", error=str(exc))


def fetch_multiple(
    targets: Iterable[str], threads: int = 5, timeout: int = 10
) -> list[FetchResult]:
    ordered_targets = list(targets)
    results_by_target: dict[str, FetchResult] = {}
    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = {
            executor.submit(fetch_target, target, timeout): target
            for target in ordered_targets
        }
        for future in as_completed(futures):
            target = futures[future]
            results_by_target[target] = future.result()
    return [results_by_target[target] for target in ordered_targets]
