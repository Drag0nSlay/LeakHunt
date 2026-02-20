"""Command-line interface for LeakHunt."""

from __future__ import annotations

import argparse
from collections import Counter

from .fetcher import fetch_multiple
from .scanner import SecretFinding, scan_many
from .utils import dump_json, log


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LeakHunt secret scanner")
    parser.add_argument("targets", nargs="*", help="Mixed targets (URLs or local file paths)")
    parser.add_argument("-u", "--url", action="append", default=[], help="Single URL to scan (repeatable)")
    parser.add_argument("-U", "--url-file", help="File containing URLs/paths, one per line")
    parser.add_argument("-f", "--file", action="append", default=[], help="Local file to scan (repeatable)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Thread count for fetching")
    parser.add_argument("-o", "--output", help="Write results as JSON file")
    parser.add_argument("--entropy-threshold", type=float, default=3.5, help="Entropy threshold for candidate secrets")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logs")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return parser.parse_args()


def load_targets_from_file(path: str) -> list[str]:
    entries: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)
    return entries


def _print_findings(findings: list[SecretFinding], use_color: bool) -> None:
    for finding in findings:
        log(
            "FOUND",
            f"{finding.secret_type} ({finding.severity}) in {finding.source} | entropy={finding.entropy:.2f} | {finding.value}",
            use_color=use_color,
        )


def main() -> int:
    args = parse_args()
    use_color = not args.no_color

    targets: list[str] = []
    targets.extend(args.targets)
    targets.extend(args.url)
    targets.extend(args.file)

    if args.url_file:
        targets.extend(load_targets_from_file(args.url_file))

    # Deduplicate while preserving insertion order.
    targets = list(dict.fromkeys(targets))

    if not targets:
        log("ERROR", "No targets provided. Use positional targets, -u, -f, or -U.", use_color=use_color)
        return 1

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
        _print_findings(findings, use_color=use_color)
        summary = Counter(f.severity for f in findings)
        log(
            "INFO",
            f"Summary: total={len(findings)} high={summary.get('high', 0)} medium={summary.get('medium', 0)} low={summary.get('low', 0)}",
            use_color=use_color,
        )

    if args.output:
        payload = [f.to_dict() for f in findings]
        dump_json(payload, args.output)
        log("INFO", f"Saved JSON results to {args.output}", use_color=use_color)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())