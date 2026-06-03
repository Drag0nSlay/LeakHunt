"""Command-line interface for LeakHunt."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from typing import Sequence

from .fetcher import detect_input_mode, fetch_multiple
from .patterns import load_patterns
from .scanner import SecretFinding, scan_many
from .utils import dump_json, log


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("threads must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("threads must be a positive integer")
    return parsed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LeakHunt secret scanner")
    parser.add_argument(
        "targets", nargs="*", help="Mixed targets (URLs, local file paths, or raw text)"
    )
    parser.add_argument(
        "-u",
        "--url",
        action="append",
        default=[],
        help="Single URL to scan (repeatable)",
    )
    parser.add_argument(
        "-U", "--url-file", help="File containing targets, or a URL/raw text target"
    )
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        default=[],
        help="Local file or raw text to scan (repeatable)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=positive_int,
        default=5,
        help="Thread count for fetching",
    )
    parser.add_argument(
        "-o", "--output", help="Write structured JSON results to a file"
    )
    parser.add_argument(
        "--json", action="store_true", help="Print structured JSON results to stdout"
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=3.5,
        help="Entropy threshold for candidate secrets",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logs"
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument(
        "--safe-mode", action="store_true", help="Mask secret values in output"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Validate targets only, no scanning"
    )
    parser.add_argument("--patterns-dir", help="Directory for YAML patterns")
    return parser.parse_args(argv)


def load_targets_from_file(path: str) -> list[str]:
    entries: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)
    return entries


def _expand_url_file_argument(value: str) -> list[str]:
    if detect_input_mode(value) == "file":
        return load_targets_from_file(value)
    return [value]


def _display_value(value: str, mask_secrets: bool) -> str:
    if mask_secrets:
        return f"{value[:8]}...{value[-4:]}"
    return value


def _print_findings(
    findings: list[SecretFinding], use_color: bool, mask_secrets: bool
) -> None:
    for finding in findings:
        log(
            "FOUND",
            f"{finding.secret_type} ({finding.severity}) in {finding.source} | "
            f"score={finding.score:.2f} | entropy={finding.entropy:.2f} | "
            f"{_display_value(finding.value, mask_secrets)}",
            use_color=use_color,
        )
        for reason in finding.reasons:
            print(f"  - {reason}")


def _structured_payload(findings: list[SecretFinding]) -> dict:
    sources = list(dict.fromkeys(finding.source for finding in findings))
    return {
        "file": sources[0] if len(sources) == 1 else None,
        "sources": sources,
        "findings": [finding.to_dict() for finding in findings],
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    use_color = not args.no_color
    human_output = not args.json

    targets: list[str] = []
    targets.extend(args.targets)
    targets.extend(args.url)
    targets.extend(args.file)

    if args.url_file:
        try:
            targets.extend(_expand_url_file_argument(args.url_file))
        except OSError as exc:
            log(
                "ERROR",
                f"Failed to read target list {args.url_file}: {exc}",
                use_color=use_color,
            )
            return 1

    # Deduplicate while preserving insertion order.
    targets = list(dict.fromkeys(targets))

    if not targets:
        log(
            "ERROR",
            "No targets provided. Use positional targets, -u, -f, -U, or raw text.",
            use_color=use_color,
        )
        return 1

    if args.dry_run:
        if args.json:
            print(json.dumps({"targets": targets, "count": len(targets)}, indent=2))
        else:
            log(
                "INFO",
                f"Dry run: {len(targets)} valid targets ready for scanning:",
                use_color=use_color,
            )
            for i, target in enumerate(targets, 1):
                mode = detect_input_mode(target)
                log(
                    "DEBUG",
                    f"  {i}. {target} ({mode})",
                    verbose=args.verbose,
                    use_color=use_color,
                )
        return 0

    if human_output:
        log(
            "INFO",
            f"Scanning {len(targets)} target(s) with {args.threads} thread(s)",
            use_color=use_color,
        )

    fetch_results = fetch_multiple(targets, threads=args.threads, timeout=30)

    scan_inputs: list[tuple[str, str]] = []
    for result in fetch_results:
        if result.error:
            if human_output:
                log(
                    "ERROR",
                    f"Failed to fetch {result.source}: {result.error}",
                    verbose=args.verbose,
                    use_color=use_color,
                )
            continue
        if human_output:
            log(
                "DEBUG",
                f"Fetched {result.source} ({len(result.content)} bytes)",
                verbose=args.verbose,
                use_color=use_color,
            )
        scan_inputs.append((result.source, result.content))

    patterns = load_patterns(args.patterns_dir) if args.patterns_dir else None
    findings = scan_many(
        scan_inputs, entropy_threshold=args.entropy_threshold, patterns=patterns
    )

    if human_output:
        if not findings:
            print("[!] No secrets found")
        else:
            _print_findings(findings, use_color, args.safe_mode)
            summary = Counter(f.severity for f in findings)
            log(
                "INFO",
                f"Summary: total={len(findings)} high={summary.get('high', 0)} medium={summary.get('medium', 0)} low={summary.get('low', 0)}",
                use_color=use_color,
            )
    else:
        print(json.dumps(_structured_payload(findings), indent=2))

    if args.output:
        payload = _structured_payload(findings)
        try:
            dump_json(payload, args.output)
        except OSError as exc:
            log(
                "ERROR",
                f"Failed to write JSON results to {args.output}: {exc}",
                use_color=use_color,
            )
            return 1
        if human_output:
            log("INFO", f"Saved JSON results to {args.output}", use_color=use_color)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
