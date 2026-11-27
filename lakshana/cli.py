"""Command line interface for lakshana."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import __version__
from .analyzer import Analysis, analyze


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def c(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def verdict(self, v: str, width: int = 10) -> str:
        code = {"high": "1;31", "suspicious": "33", "low": "32"}[v]
        return self.c(code, v.upper().ljust(width))


def visible_len(s: str) -> int:
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


def table(rows, headers) -> str:
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r[:-1]):
            widths[i] = max(widths[i], visible_len(cell))
    def fmt(r):
        cells = [cell + " " * (widths[i] - visible_len(cell)) for i, cell in enumerate(r[:-1])]
        return "  ".join(cells + [r[-1]]).rstrip()
    sep = ["-" * w for w in widths[:-1]] + ["-" * max(widths[-1], 8)]
    return "\n".join([fmt(headers), "  ".join(sep)] + [fmt(r) for r in rows])


def render_detail(a: Analysis, style: Style) -> str:
    lines = [f"URL       {a.url}",
             f"Host      {a.host or '-'}",
             f"Domain    {a.registered_domain or '-'}",
             f"Score     {a.score}/100  {style.verdict(a.verdict).rstrip()}"]
    if a.error:
        lines.append(f"Note      {a.error}")
    if a.signals:
        lines.append("")
        width = max(len(s.id) for s in a.signals)
        for s in sorted(a.signals, key=lambda s: -s.weight):
            lines.append(f"  +{s.weight:<3} {s.id.ljust(width)}  {s.detail}")
    else:
        lines.append("")
        lines.append("  no phishing indicators found")
    return "\n".join(lines)


def render_table(results: list[Analysis], style: Style) -> str:
    rows = []
    for a in results:
        top = ", ".join(s.id for s in sorted(a.signals, key=lambda s: -s.weight)[:3]) or "-"
        url = a.url if len(a.url) <= 60 else a.url[:57] + "..."
        rows.append([str(a.score).rjust(5), style.verdict(a.verdict), url, top])
    return table(rows, ["SCORE", "VERDICT", "URL", "TOP SIGNALS"])


def read_urls(path: str) -> list[str]:
    stream = sys.stdin if path == "-" else open(path, encoding="utf-8")
    try:
        return [line.strip() for line in stream
                if line.strip() and not line.lstrip().startswith("#")]
    finally:
        if stream is not sys.stdin:
            stream.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lakshana",
        description="Score URLs for phishing indicators using offline heuristics.")
    p.add_argument("urls", nargs="*", help="URLs to analyse")
    p.add_argument("-f", "--file", help="read URLs from a file, one per line ('-' for stdin)")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--detail", action="store_true", help="show full explanation for every URL")
    p.add_argument("--min-score", type=int, default=0, help="only show URLs scoring at least this")
    p.add_argument("--fail-at", type=int, default=50,
                   help="exit 1 if any URL scores at least this (default 50)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("--version", action="version", version=f"lakshana {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:  # look-alike hosts contain characters some consoles cannot encode
        sys.stdout.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    urls = list(args.urls)
    if args.file:
        try:
            urls += read_urls(args.file)
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    if not urls:
        parser.print_usage(sys.stderr)
        print("error: give at least one URL or --file", file=sys.stderr)
        return 2

    results = [analyze(u) for u in urls]
    shown = [r for r in results if r.score >= args.min_score]
    style = Style(not args.no_color and not args.json and sys.stdout.isatty()
                  and os.environ.get("NO_COLOR") is None)

    if args.json:
        payload = [r.to_dict() for r in shown]
        print(json.dumps(payload[0] if len(urls) == 1 and payload else payload, indent=2,
                         ensure_ascii=False))
    elif len(urls) == 1 or args.detail:
        print("\n\n".join(render_detail(r, style) for r in shown))
    else:
        print(render_table(shown, style))
        counts = {v: sum(r.verdict == v for r in results) for v in ("high", "suspicious", "low")}
        print(f"\n{len(results)} URLs: {counts['high']} high, {counts['suspicious']} suspicious, "
              f"{counts['low']} low")

    return 1 if any(r.score >= args.fail_at for r in results) else 0
