"""Utility helpers for logging and scoring."""

from __future__ import annotations

import json
import math
from typing import Any

RESET = "\033[0m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    freq = {ch: value.count(ch) / length for ch in set(value)}
    return -sum(p * math.log2(p) for p in freq.values())


def colorize(level: str, message: str, use_color: bool = True) -> str:
    if not use_color:
        return f"[{level}] {message}"
    color_map = {"INFO": BLUE, "DEBUG": YELLOW, "ERROR": RED, "FOUND": GREEN}
    color = color_map.get(level, RESET)
    return f"{color}[{level}]{RESET} {message}"


def log(level: str, message: str, verbose: bool = False, use_color: bool = True) -> None:
    if level == "DEBUG" and not verbose:
        return
    print(colorize(level, message, use_color=use_color))


def dump_json(data: Any, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)