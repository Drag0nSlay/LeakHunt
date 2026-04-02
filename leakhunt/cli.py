"""Command-line interface for LeakHunt."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Sequence

from tqdm import tqdm
from .fetcher import fetch_multiple
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
    parser.add_argument("targets", nargs="*", help="Mixed targets (URLs or local file paths)")
    parser.add_argument("-u", "--url", action="append", default=[], help="Single URL to scan (repeatable)")
    parser.add_argument("-U", "--url-file", help="File containing URLs/paths, one per line")
    parser.add_argument("-f", "--file", action="append", default=[], help="Local file to scan (repeatable)")
    parser.add_argument("-t", "--threads", type=positive_int, default=5, help="Thread count for fetching")
    parser.add_argument("-o", "--output", help="Write results as JSON file")
    parser.add_argument("--entropy-threshold", type=float, default=3.5, help="Entropy threshold for candidate secrets")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logs")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--safe-mode", action="store_true", help="Mask secret values in output")
    parser.add_argument("--dry-run", action="store_true", help="Validate targets only, no scanning")
    parser.add_argument("--patterns-dir", default="patterns/", help="Directory for YAML patterns")
    return parser.parse_args(argv)


def load_targets_from_file(path: str) -> list[str]:
    entries: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)
    return entries


def _print_findings(findings: list[SecretFinding], use_color: bool, mask_secrets: bool) -> None:
    for finding in findings:
        masked = f"{finding.value[:8]}...{finding.value[-4:]}" if mask_secrets else finding.value
        log(
            "FOUND",
            f"{finding.secret_type} ({finding.severity}) in {finding.source} | entropy={finding.entropy:.2f} | {masked}",
            use_color=use_color,
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    use_color = not args.no_color

    targets: list[str] = []
    targets.extend(args.targets)
    targets.extend(args.url)
    targets.extend(args.file)

    if args.url_file:
        try:
            targets.extend(load_targets_from_file(args.url_file))
        except OSError as exc:
            log("ERROR", f"Failed to read target list {args.url_file}: {exc}", use_color=use_color)
            return 1

    # Deduplicate while preserving insertion order.
    targets = list(dict.fromkeys(targets))

    if not targets:
        log("ERROR", "No targets provided. Use positional targets, -u, -f, or -U.", use_color=use_color)
        return 1

    if args.dry_run:
        log("INFO", f"Dry run: {len(targets)} valid targets ready for scanning:", use_color=use_color)
        for i, target in enumerate(targets, 1):
            log("DEBUG", f"  {i}. {target}", verbose=args.verbose, use_color=use_color)
        return 0

    log("INFO", f"Scanning {len(targets)} target(s) with {args.threads} thread(s)", use_color=use_color)
    
    fetch_results = fetch_multiple(targets, threads=args.threads, timeout=30)

    scan_inputs: list[tuple[str, str]] = []
    for result in fetch_results:
        if result.error:
            log("ERROR", f"Failed to fetch {result.source}: {result.error}", verbose=args.verbose, use_color=use_color)
            continue
        log("DEBUG", f"Fetched {result.source} ({len(result.content)} bytes)", verbose=args.verbose, use_color=use_color)
        scan_inputs.append((result.source, result.content))

    findings = scan_many(scan_inputs, entropy_threshold=args.entropy_threshold)

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

    if args.output:
        payload = [f.to_dict() for f in findings]
        try:
            dump_json(payload, args.output)
        except OSError as exc:
            log("ERROR", f"Failed to write JSON results to {args.output}: {exc}", use_color=use_color)
            return 1
        log("INFO", f"Saved JSON results to {args.output}", use_color=use_color)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())            log("ERROR", f"Failed to write JSON results to {args.output}: {exc}", use_color=use_color)
            return 1
        log("INFO", f"Saved JSON results to {args.output}", use_color=use_color)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
