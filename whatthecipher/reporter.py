"""Terminal reporting via Rich.

Renders live progress during the scan, a detailed panel per host, and a final
summary table. Degrades to plain text if Rich is unavailable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .utils.colors import (
    SEVERITY_STYLE,
    STRENGTH_STYLE,
    grade_style,
)

if TYPE_CHECKING:  # pragma: no cover
    from .scanner import ScanResult

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.text import Text

    _RICH = True
except Exception:  # pragma: no cover
    _RICH = False


def make_console() -> Console:
    return Console()


def scan_progress(console: Console, total: int):
    """Return a Rich Progress context configured for the scan."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold]Scanning[/]"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TextColumn("·"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


# --------------------------------------------------------------------------- #
# Per-host detail
# --------------------------------------------------------------------------- #


def render_host(console: Console, result: ScanResult) -> None:
    if not _RICH:
        _render_host_plain(result)
        return

    grade = result.grade.letter if result.grade else "?"
    gstyle = grade_style(grade)
    title = Text()
    title.append(f" {result.host}:{result.port} ", style="bold")
    if result.ip:
        title.append(f"({result.ip}) ", style="dim")

    if not result.reachable:
        console.print(
            Panel(
                Text(f"unreachable — {result.error}", style="red"),
                title=title,
                border_style="red",
                expand=True,
            )
        )
        return

    body = Table.grid(padding=(0, 1))
    body.add_column(justify="left")

    # grade line
    score = f"{result.grade.score}/100" if result.grade else ""
    grade_line = Text()
    grade_line.append(f"Grade {grade} ", style=f"bold {gstyle}")
    grade_line.append(f"{score}", style="dim")
    if result.grade and result.grade.caps:
        grade_line.append("  (" + "; ".join(result.grade.caps) + ")", style="dim yellow")
    body.add_row(grade_line)

    # protocols
    proto_line = Text("Protocols  ", style="bold")
    for proto, ok in result.protocols.items():
        if ok:
            deprecated = proto in {"SSLv3", "TLS1.0", "TLS1.1"}
            proto_line.append(f"{proto} ", style="yellow" if deprecated else "green")
        else:
            proto_line.append(f"{proto} ", style="dim strike")
    body.add_row(proto_line)
    body.add_row(_cipher_table(result))
    cert_line = _cert_line(result)
    if cert_line:
        body.add_row(cert_line)
    vuln_line = _vuln_line(result)
    if vuln_line:
        body.add_row(vuln_line)

    console.print(Panel(body, title=title, border_style=gstyle, expand=True))


def _cipher_table(result: ScanResult) -> Table:
    table = Table(show_edge=False, pad_edge=False, box=None, expand=True)
    table.add_column("Cipher", style="cyan", no_wrap=True, max_width=48)
    table.add_column("Bits", justify="right")
    table.add_column("PFS", justify="center")
    table.add_column("AEAD", justify="center")
    table.add_column("Strength")
    any_row = False
    for _proto, ciphers in result.ciphers.items():
        for c in ciphers:
            any_row = True
            weak = f" [red]{' '.join(c.weaknesses)}[/]" if c.weaknesses else ""
            table.add_row(
                f"{c.name}{weak}",
                str(c.bits),
                "✓" if c.forward_secret else "·",
                "✓" if c.aead else "·",
                Text(c.strength, style=STRENGTH_STYLE.get(c.strength, "white")),
            )
    if not any_row:
        table.add_row("[dim]no suites enumerated[/]", "", "", "", "")
    return table


def _cert_line(result: ScanResult) -> Text | None:
    cert = result.certificate
    if not cert or (cert.errors and not cert.subject):
        if cert and cert.errors:
            return Text(f"Certificate  {cert.errors[0]}", style="dim red")
        return None
    line = Text("Certificate  ", style="bold")
    line.append(f"{cert.subject} ", style="white")
    line.append(f"· {cert.public_key_type} {cert.public_key_bits}-bit ", style="dim")
    line.append(f"· expires in {cert.days_until_expiry}d ", style="dim")
    for label, cond, style in [
        ("SELF-SIGNED", cert.self_signed, "yellow"),
        ("EXPIRED", cert.expired, "red"),
        ("MISMATCH", cert.hostname_mismatch, "red"),
        ("SHA1", cert.uses_sha1, "yellow"),
    ]:
        if cond:
            line.append(f"[{label}] ", style=f"bold {style}")
    return line


def _vuln_line(result: ScanResult) -> Text | None:
    present = [v for v in result.vulnerabilities if v.present]
    if not present:
        return None
    line = Text("Findings  ", style="bold")
    for v in sorted(present, key=lambda x: x.severity):
        line.append(f"{v.name} ", style=SEVERITY_STYLE.get(v.severity, "white"))
    return line


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #


def render_summary(console: Console, results: list[ScanResult]) -> None:
    if not _RICH:
        _render_summary_plain(results)
        return
    table = Table(title="Scan summary", expand=True, title_style="bold")
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Grade", justify="center")
    table.add_column("Protocols")
    table.add_column("Ciphers", justify="right")
    table.add_column("Findings", justify="right")
    for r in results:
        grade = r.grade.letter if r.grade else "?"
        if not r.reachable:
            table.add_row(f"{r.host}:{r.port}", "[dim]—[/]", f"[red]{r.error}[/]", "", "")
            continue
        protos = " ".join(p for p, ok in r.protocols.items() if ok) or "—"
        n_ciphers = sum(len(c) for c in r.ciphers.values())
        findings = sum(1 for v in r.vulnerabilities if v.present)
        fstyle = "red" if findings else "green"
        table.add_row(
            f"{r.host}:{r.port}",
            Text(grade, style=f"bold {grade_style(grade)}"),
            protos,
            str(n_ciphers),
            Text(str(findings), style=fstyle),
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# Plain-text fallbacks
# --------------------------------------------------------------------------- #


def _render_host_plain(result: ScanResult) -> None:
    print(f"\n=== {result.host}:{result.port} ===")
    if not result.reachable:
        print(f"  unreachable: {result.error}")
        return
    grade = result.grade.letter if result.grade else "?"
    print(f"  Grade: {grade}")
    print("  Protocols: " + ", ".join(p for p, ok in result.protocols.items() if ok))
    for proto, ciphers in result.ciphers.items():
        for c in ciphers:
            print(f"    [{proto}] {c.name} ({c.strength})")
    for v in result.vulnerabilities:
        if v.present:
            print(f"  ! {v.severity.upper()}: {v.name}")


def _render_summary_plain(results: list[ScanResult]) -> None:
    print("\n--- Summary ---")
    for r in results:
        grade = r.grade.letter if r.grade else "?"
        print(f"  {r.host}:{r.port}  grade={grade}  " f"reachable={r.reachable}")
