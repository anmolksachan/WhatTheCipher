"""CSV exporter — one summary row per host for spreadsheets / triage."""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ..scanner import ScanResult

FIELDS = [
    "target",
    "ip",
    "port",
    "reachable",
    "grade",
    "score",
    "protocols",
    "cipher_count",
    "weak_ciphers",
    "forward_secrecy",
    "cert_subject",
    "cert_issuer",
    "cert_expiry_days",
    "cert_key",
    "cert_sha1",
    "self_signed",
    "hostname_mismatch",
    "critical_vulns",
    "high_vulns",
    "error",
]


def _row(result: ScanResult) -> dict:
    supported = [p for p, ok in result.protocols.items() if ok]
    all_ciphers = [c for suites in result.ciphers.values() for c in suites]
    weak = [c.name for c in all_ciphers if c.weaknesses]
    cert = result.certificate
    crit = sum(
        1 for v in result.vulnerabilities if v.present and v.severity == "critical"
    )
    high = sum(1 for v in result.vulnerabilities if v.present and v.severity == "high")
    return {
        "target": result.host,
        "ip": result.ip,
        "port": result.port,
        "reachable": result.reachable,
        "grade": result.grade.letter if result.grade else "",
        "score": result.grade.score if result.grade else "",
        "protocols": " ".join(supported),
        "cipher_count": len(all_ciphers),
        "weak_ciphers": len(weak),
        "forward_secrecy": any(c.forward_secret for c in all_ciphers),
        "cert_subject": cert.subject if cert else "",
        "cert_issuer": cert.issuer if cert else "",
        "cert_expiry_days": cert.days_until_expiry if cert else "",
        "cert_key": f"{cert.public_key_type} {cert.public_key_bits}" if cert else "",
        "cert_sha1": cert.uses_sha1 if cert else "",
        "self_signed": cert.self_signed if cert else "",
        "hostname_mismatch": cert.hostname_mismatch if cert else "",
        "critical_vulns": crit,
        "high_vulns": high,
        "error": result.error or "",
    }


def export(results: list[ScanResult], tool_version: str = "") -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDS)
    writer.writeheader()
    for r in results:
        writer.writerow(_row(r))
    return buf.getvalue()


def write(results: list[ScanResult], path: str, tool_version: str = "") -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(export(results, tool_version))
