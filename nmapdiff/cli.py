"""Command-line interface for nmapdiff.

Usage examples::

    nmapdiff diff baseline.xml current.xml
    nmapdiff diff baseline.xml current.xml --format json
    nmapdiff --version

Exit codes:
    0  no changes detected
    1  changes detected (findings present)
    2  usage / parse / IO error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from nmapdiff import TOOL_NAME, TOOL_VERSION
from nmapdiff.core import Diff, diff_scans, parse_scan_file


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Diff two nmap XML scans to surface new hosts/ports/services "
        "(defensive change-detection only).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )

    sub = parser.add_subparsers(dest="command")

    diff_p = sub.add_parser(
        "diff",
        help="compare a baseline scan against a current scan",
    )
    diff_p.add_argument("baseline", help="path to baseline nmap XML (-oX) file")
    diff_p.add_argument("current", help="path to current nmap XML (-oX) file")
    diff_p.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )

    return parser


def _render_table(diff: Diff, baseline: str, current: str) -> str:
    lines: List[str] = []
    lines.append(f"nmapdiff: {baseline} -> {current}")
    summary = diff.summary()
    lines.append(f"  findings: {summary['total_findings']}")
    if summary["by_kind"]:
        kinds = ", ".join(f"{k}={v}" for k, v in sorted(summary["by_kind"].items()))
        lines.append(f"  breakdown: {kinds}")

    if diff.host_changes:
        lines.append("")
        lines.append("HOST CHANGES")
        for h in diff.host_changes:
            detail = ""
            if h.before is not None or h.after is not None:
                detail = f"  [{h.before} -> {h.after}]"
            lines.append(f"  {h.kind:<14} {h.address}{detail}")

    if diff.port_changes:
        lines.append("")
        lines.append("PORT CHANGES")
        for p in diff.port_changes:
            target = f"{p.address}  {p.protocol}/{p.portid}"
            if p.kind == "new_port":
                lines.append(f"  + {target}  {p.after}")
            elif p.kind == "removed_port":
                lines.append(f"  - {target}  {p.before}")
            elif p.kind == "service_change":
                lines.append(f"  ~ {target}  {p.before} -> {p.after}")
            elif p.kind == "state_change":
                lines.append(f"  ! {target}  state {p.before} -> {p.after}")

    if not diff.has_findings():
        lines.append("")
        lines.append("No changes detected.")

    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "diff":
        parser.print_help(sys.stderr)
        return 2

    try:
        baseline = parse_scan_file(args.baseline)
        current = parse_scan_file(args.current)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return 2

    diff = diff_scans(baseline, current)

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "baseline": args.baseline,
            "current": args.current,
            "diff": diff.to_dict(),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_render_table(diff, args.baseline, args.current))

    return 1 if diff.has_findings() else 0


if __name__ == "__main__":
    raise SystemExit(main())
