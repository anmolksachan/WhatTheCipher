"""Command-line interface.

wtc example.com
wtc example.com google.com github.com
wtc targets.txt --html --json -o report/
wtc --cidr 192.168.1.0/24 --threads 50
wtc mail.example.com --starttls smtp -p 587
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, exporters, reporter
from .parser import Target, parse_nmap_xml, parse_targets
from .scanner import ScanConfig, ScanResult, scan_all
from .utils import banner as banner_mod
from .utils.logger import configure, get_logger

log = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wtc",
        description="WhatTheCipher — modern TLS/SSL assessment framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="by Anmol K Sachan (@FR13ND0x7F) · "
        "https://github.com/anmolksachan/WhatTheCipher",
    )
    p.add_argument(
        "targets", nargs="*", help="domains, IPs, URLs, host:port, or a file of targets"
    )

    net = p.add_argument_group("targets & network")
    net.add_argument(
        "-p", "--port", type=int, default=443, help="default port (default: 443)"
    )
    net.add_argument(
        "--cidr",
        action="append",
        default=[],
        metavar="RANGE",
        help="scan a CIDR range, e.g. 192.168.1.0/24 (repeatable)",
    )
    net.add_argument(
        "--stdin", action="store_true", help="read additional targets from stdin"
    )
    net.add_argument(
        "--starttls",
        metavar="PROTO",
        choices=["smtp", "imap", "pop3", "ftp", "xmpp"],
        help="negotiate STARTTLS first (smtp/imap/pop3/ftp/xmpp)",
    )
    net.add_argument(
        "--nmap-xml",
        metavar="FILE",
        help="ingest an existing nmap ssl-enum-ciphers XML file",
    )

    perf = p.add_argument_group("performance")
    perf.add_argument(
        "--threads", type=int, default=20, help="concurrent workers (default: 20)"
    )
    perf.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="per-connection timeout in seconds (default: 8)",
    )

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="write a JSON report")
    out.add_argument("--html", action="store_true", help="write an HTML report")
    out.add_argument("--csv", action="store_true", help="write a CSV report")
    out.add_argument(
        "--markdown",
        "--md",
        dest="markdown",
        action="store_true",
        help="write a Markdown report",
    )
    out.add_argument(
        "-o",
        "--output",
        metavar="DIR",
        default="wtc-report",
        help="output directory for reports (default: wtc-report/)",
    )

    an = p.add_argument_group("analysis")
    an.add_argument("--grade", action="store_true", help="force grading (on by default)")
    an.add_argument(
        "--recommend", action="store_true", help="force recommendations (on by default)"
    )
    an.add_argument("--no-cert", action="store_true", help="skip certificate inspection")
    an.add_argument(
        "--no-features",
        action="store_true",
        help="skip ALPN/HSTS/compression feature detection",
    )

    ui = p.add_argument_group("interface")
    ui.add_argument("--no-banner", action="store_true", help="hide the banner")
    ui.add_argument(
        "--no-details", action="store_true", help="only print the summary table"
    )
    ui.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    ui.add_argument(
        "-q", "--quiet", action="store_true", help="errors only on the console"
    )
    ui.add_argument("--log-file", metavar="FILE", help="write a debug log file")
    ui.add_argument("--version", action="version", version=f"WhatTheCipher {__version__}")
    return p


def _collect_targets(args: argparse.Namespace) -> list[Target]:
    raw = list(args.targets) + list(args.cidr)
    return parse_targets(
        raw,
        default_port=args.port,
        starttls=args.starttls,
        read_stdin=args.stdin,
    )


def _write_reports(args, results, console) -> list[str]:
    formats = [
        f
        for f, on in [
            ("json", args.json),
            ("html", args.html),
            ("csv", args.csv),
            ("markdown", args.markdown),
        ]
        if on
    ]
    if not formats:
        return []
    os.makedirs(args.output, exist_ok=True)
    written: list[str] = []
    for fmt in formats:
        path = os.path.join(args.output, f"report.{exporters.extension(fmt)}")
        exporters.write(fmt, results, path, tool_version=__version__)
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)
    console = reporter.make_console()

    if not args.no_banner and not args.quiet:
        banner_mod.print_banner(__version__)

    # nmap XML ingestion is an alternate data source
    if args.nmap_xml:
        try:
            parsed = parse_nmap_xml(args.nmap_xml)
            console.print(
                f"[green]Parsed {len(parsed)} host(s) from " f"{args.nmap_xml}[/]"
            )
            for key, rec in parsed.items():
                console.print(f"  [cyan]{key}[/]: " f"{', '.join(rec['protocols'])}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Failed to parse nmap XML: {exc}[/]")
            return 2
        if not args.targets and not args.cidr:
            return 0

    targets = _collect_targets(args)
    if not targets:
        console.print(
            "[yellow]No targets provided.[/] " "Try:  wtc example.com   |   wtc --help"
        )
        return 1

    config = ScanConfig(
        timeout=args.timeout,
        threads=args.threads,
        check_certificate=not args.no_cert,
        check_features=not args.no_features,
    )

    console.print(
        f"[dim]Scanning {len(targets)} target(s) with "
        f"{min(config.threads, len(targets))} worker(s)…[/]\n"
    )

    results: list[ScanResult] = []
    try:
        with reporter.scan_progress(console, len(targets)) as progress:
            task = progress.add_task("scan", total=len(targets))

            def on_result(_res: ScanResult) -> None:
                progress.advance(task)

            results = scan_all(targets, config, on_result=on_result)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — reporting partial results.[/]")

    if not args.no_details:
        for res in results:
            reporter.render_host(console, res)

    reporter.render_summary(console, results)

    written = _write_reports(args, results, console)
    for path in written:
        console.print(f"[green]✓[/] wrote {path}")

    worst = _worst_grade(results)
    return 0 if worst not in {"F", "T", "M"} else 3


def _worst_grade(results: list[ScanResult]) -> str:
    order = ["A+", "A", "B", "C", "D", "E", "F", "T", "M"]
    worst = "A+"
    for r in results:
        g = r.grade.letter if r.grade else "A+"
        if g in order and order.index(g) > order.index(worst):
            worst = g
    return worst


if __name__ == "__main__":
    sys.exit(main())
