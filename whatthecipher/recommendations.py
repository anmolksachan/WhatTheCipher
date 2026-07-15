"""Remediation advice generation.

Turns raw findings (protocols, ciphers, cert, vulnerabilities) into actionable,
referenced recommendations aligned with the Mozilla SSL Configuration Guide and
the relevant RFCs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .grading import SEVERITY_ORDER
from .tls import DEPRECATED_PROTOCOLS

if TYPE_CHECKING:  # pragma: no cover
    from .scanner import ScanResult

MOZILLA = "Mozilla SSL Configuration Guide (ssl-config.mozilla.org)"


@dataclass
class Recommendation:
    title: str
    severity: str
    detail: str
    reference: str = ""

    def sort_key(self) -> int:
        return -SEVERITY_ORDER.get(self.severity, 0)


def generate(result: ScanResult) -> list[Recommendation]:
    recs: list[Recommendation] = []
    protos = {p for p, ok in result.protocols.items() if ok}
    all_ciphers = [c for suites in result.ciphers.values() for c in suites]

    # Deprecated protocols ---------------------------------------------------
    for proto in sorted(protos & DEPRECATED_PROTOCOLS):
        ref = {
            "SSLv2": "RFC 6176",
            "SSLv3": "RFC 7568",
            "TLS1.0": "RFC 8996",
            "TLS1.1": "RFC 8996",
        }.get(proto, "RFC 8996")
        recs.append(
            Recommendation(
                title=f"Disable {proto}",
                severity="high" if proto in {"SSLv2", "SSLv3"} else "medium",
                detail=f"{proto} is deprecated and must be turned off. Serve only "
                f"TLS 1.2 and TLS 1.3.",
                reference=ref,
            )
        )

    if "TLS1.3" not in protos and protos:
        recs.append(
            Recommendation(
                "Enable TLS 1.3",
                "low",
                "TLS 1.3 offers stronger security and lower latency. Add it "
                "alongside TLS 1.2.",
                MOZILLA,
            )
        )

    # Weak ciphers -----------------------------------------------------------
    weak_names = sorted({c.name for c in all_ciphers if c.weaknesses})
    if weak_names:
        preview = ", ".join(weak_names[:6]) + (
            f" (+{len(weak_names) - 6} more)" if len(weak_names) > 6 else ""
        )
        recs.append(
            Recommendation(
                "Remove weak cipher suites",
                "high",
                f"Disable: {preview}. Prefer AEAD suites with forward secrecy such "
                f"as TLS_AES_256_GCM_SHA384 and "
                f"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.",
                MOZILLA,
            )
        )

    if all_ciphers and not any(c.forward_secret for c in all_ciphers):
        recs.append(
            Recommendation(
                "Enable forward secrecy",
                "high",
                "No ECDHE/DHE suites were offered. Enable ECDHE key exchange so "
                "past sessions stay protected if the private key leaks.",
                MOZILLA,
            )
        )

    if any(c.cbc for c in all_ciphers):
        recs.append(
            Recommendation(
                "Prefer AEAD over CBC",
                "low",
                "CBC-mode suites are exposed to a family of padding-oracle attacks. "
                "Prefer GCM/CHACHA20-POLY1305 AEAD suites.",
                MOZILLA,
            )
        )

    # Certificate ------------------------------------------------------------
    cert = result.certificate
    if cert:
        if cert.expired:
            recs.append(
                Recommendation(
                    "Replace expired certificate",
                    "critical",
                    "The leaf certificate has expired. Reissue and deploy a valid "
                    "certificate immediately.",
                    "",
                )
            )
        elif cert.days_until_expiry is not None and cert.days_until_expiry < 30:
            recs.append(
                Recommendation(
                    "Renew certificate soon",
                    "medium",
                    f"Certificate expires in {cert.days_until_expiry} days. Automate "
                    f"renewal (e.g. ACME) to avoid an outage.",
                    "",
                )
            )
        if cert.uses_sha1:
            recs.append(
                Recommendation(
                    "Replace SHA-1 signed certificate",
                    "high",
                    "SHA-1 is collision-broken. Reissue with SHA-256 or better.",
                    "RFC 9155",
                )
            )
        if cert.self_signed:
            recs.append(
                Recommendation(
                    "Use a CA-issued certificate",
                    "high",
                    "The certificate is self-signed and will not be trusted by "
                    "clients. Obtain one from a trusted CA.",
                    "",
                )
            )
        if cert.hostname_mismatch:
            recs.append(
                Recommendation(
                    "Fix hostname mismatch",
                    "high",
                    "The certificate does not cover the scanned hostname. Add it to "
                    "the SAN list.",
                    "",
                )
            )
        if cert.public_key_type == "RSA" and cert.public_key_bits < 2048:
            recs.append(
                Recommendation(
                    "Increase RSA key size",
                    "high",
                    f"RSA key is {cert.public_key_bits}-bit. Use at least 2048-bit "
                    f"RSA or a P-256 EC key.",
                    MOZILLA,
                )
            )

    # HSTS -------------------------------------------------------------------
    if result.features.get("hsts") is False:
        recs.append(
            Recommendation(
                "Enable HSTS",
                "medium",
                "Send Strict-Transport-Security with a long max-age to force HTTPS "
                "and prevent downgrade attacks.",
                "RFC 6797",
            )
        )

    # From detected vulnerabilities -----------------------------------------
    for vuln in result.vulnerabilities:
        if vuln.present and vuln.severity in {"critical", "high"}:
            recs.append(
                Recommendation(
                    f"Mitigate {vuln.name}", vuln.severity, vuln.detail, vuln.reference
                )
            )

    # De-dup by title, keep highest severity, sort by severity
    seen: dict[str, Recommendation] = {}
    for rec in recs:
        cur = seen.get(rec.title)
        if cur is None or rec.sort_key() < cur.sort_key():
            seen[rec.title] = rec
    return sorted(seen.values(), key=lambda r: r.sort_key())
