"""Command-line interface for PacketStory."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .parser import analyze_capture
from .report import write_html, write_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packetstory",
        description="Turn PCAP/PCAPNG captures into a human-readable investigation timeline.",
    )
    parser.add_argument("--version", action="version", version=f"PacketStory {__version__}")
    parser.add_argument("--verbose", action="store_true", help="Show informational logging")
    parser.add_argument("--debug", action="store_true", help="Show full error details")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("analyze", "Analyze capture and optionally write reports"),
        ("timeline", "Print the chronological event timeline"),
        ("iocs", "List observed indicators"),
        ("stats", "Print capture statistics"),
        ("info", "Show capture metadata"),
    ):
        cmd = sub.add_parser(name, help=help_text, description=help_text)
        cmd.add_argument("capture", type=Path, help="Input .pcap or .pcapng file")
        if name == "analyze":
            cmd.add_argument("--output", type=Path, help="Write standalone HTML report")
            cmd.add_argument("--json", dest="json_output", type=Path, help="Write JSON analysis")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    try:
        result = analyze_capture(args.capture)
        if args.command == "analyze":
            if args.output:
                write_html(result, args.output)
                print(f"HTML report written to {args.output}")
            if args.json_output:
                write_json(result, args.json_output)
                print(f"JSON report written to {args.json_output}")
            if not args.output and not args.json_output:
                print(
                    f"PacketStory analyzed {result.capture['file_name']}: {result.statistics['total_packets']:,} packets, {len(result.timeline)} timeline events, {len(result.indicators)} indicators."
                )
        elif args.command == "timeline":
            for event in result.timeline:
                print(f"{event.timestamp}  {event.kind:<22} {event.summary}")
        elif args.command == "iocs":
            print(
                json.dumps(
                    [
                        item.__dict__
                        if hasattr(item, "__dict__")
                        else {
                            "value": item.value,
                            "kind": item.kind,
                            "label": item.label,
                            "reason": item.reason,
                            "first_seen": item.first_seen,
                        }
                        for item in result.indicators
                    ],
                    indent=2,
                )
            )
        elif args.command == "stats":
            print(json.dumps(result.statistics, indent=2))
        elif args.command == "info":
            print(json.dumps(result.capture, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"packetstory: error: {exc}", file=sys.stderr)
        if args.debug:
            logging.exception("Analysis failed")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
