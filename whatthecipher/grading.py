"""Scoring engine and passive vulnerability detection.

The grade is an SSL Labs-inspired synthesis of protocol support, cipher
strength, key exchange, forward secrecy and certificate health. It is a
heuristic guide, not a byte-for-byte reproduction of the SSL Labs rating guide.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .tls import DEPRECATED_PROTOCOLS, CipherInfo

if TYPE_CHECKING:  # pragma: no cover
    from .scanner import ScanResult


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Vulnerability:
    id: str
    name: str
    severity: str  # critical | high | medium | low | info
    present: bool
    detail: str = ""
    reference: str = ""


@dataclass
class Grade:
    letter: str  # A+, A, B, C, D, E, F, T (cert), M (mismatch)
    score: int  # 0-100 composite
    caps: list[str] = field(default_factory=list)
    breakdown: dict[str, int] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Vulnerability detection (passive — derived from the scan data)
# --------------------------------------------------------------------------- #


def detect_vulnerabilities(result: ScanResult) -> list[Vulnerability]:
    protos = {p for p, ok in result.protocols.items() if ok}
    all_ciphers: list[CipherInfo] = [
        c for suites in result.ciphers.values() for c in suites
    ]

    def has(weakness: str) -> bool:
        return any(weakness in c.weaknesses for c in all_ciphers)

    def has_cbc_in(proto: str) -> bool:
        return any(c.cbc for c in result.ciphers.get(proto, []))

    feats = result.features
    vulns: list[Vulnerability] = []

    def add(vid, name, sev, present, detail="", ref=""):
        vulns.append(Vulnerability(vid, name, sev, present, detail, ref))

    add(
        "DROWN",
        "DROWN (SSLv2)",
        "critical",
        "SSLv2" in protos,
        "SSLv2 is enabled." if "SSLv2" in protos else "SSLv2 not offered.",
        "CVE-2016-0800",
    )
    add(
        "POODLE",
        "POODLE (SSLv3)",
        "high",
        "SSLv3" in protos,
        "SSLv3 is enabled." if "SSLv3" in protos else "SSLv3 not offered.",
        "CVE-2014-3566",
    )
    add(
        "BEAST",
        "BEAST",
        "low",
        "TLS1.0" in protos and has_cbc_in("TLS1.0"),
        "TLS 1.0 with CBC suites is offered (client-side mitigations exist).",
        "CVE-2011-3389",
    )
    add(
        "SWEET32",
        "Sweet32 (64-bit block)",
        "medium",
        has("3DES"),
        "3DES / 64-bit block ciphers are offered.",
        "CVE-2016-2183",
    )
    add(
        "FREAK",
        "FREAK",
        "high",
        has("EXPORT")
        and any("RSA" in c.kx for c in all_ciphers if "EXPORT" in c.weaknesses),
        "Export-grade RSA suites are offered.",
        "CVE-2015-0204",
    )
    add(
        "LOGJAM",
        "Logjam (weak DH)",
        "high",
        has("EXPORT")
        and any("DHE" in c.kx for c in all_ciphers if "EXPORT" in c.weaknesses),
        "Export-grade DHE suites are offered.",
        "CVE-2015-4000",
    )
    add(
        "LUCKY13",
        "Lucky13",
        "low",
        any(c.cbc for c in all_ciphers),
        "CBC-mode suites are offered.",
        "CVE-2013-0169",
    )
    add(
        "RC4",
        "RC4",
        "medium",
        has("RC4"),
        "RC4 suites are offered.",
        "CVE-2013-2566 / CVE-2015-2808",
    )
    add(
        "NULL",
        "NULL cipher",
        "critical",
        has("NULL"),
        "NULL-encryption suites are offered.",
        "",
    )
    add(
        "ANON",
        "Anonymous key exchange",
        "critical",
        has("ANON"),
        "Anonymous (unauthenticated) suites are offered.",
        "",
    )
    add(
        "ROBOT",
        "ROBOT (RSA PKCS#1 oracle)",
        "high",
        any(c.kx == "RSA" for c in all_ciphers),
        "Static-RSA key exchange offered; confirm with an active ROBOT test.",
        "CVE-2017-13099",
    )

    # Feature-derived (best effort; absent feature => reported as info/unknown)
    comp = feats.get("compression")
    add(
        "CRIME",
        "CRIME (TLS compression)",
        "medium",
        bool(comp),
        "TLS-level compression is enabled." if comp else "No TLS compression.",
        "CVE-2012-4929",
    )
    reneg = feats.get("secure_renegotiation")
    add(
        "RENEG",
        "Insecure renegotiation",
        "medium",
        reneg is False,
        (
            "Secure renegotiation not advertised."
            if reneg is False
            else "Secure renegotiation supported."
        ),
        "CVE-2009-3555",
    )

    hb = feats.get("heartbleed")
    if hb is not None:
        add(
            "HEARTBLEED",
            "Heartbleed",
            "critical",
            bool(hb),
            "Server leaked heartbeat memory." if hb else "Not vulnerable.",
            "CVE-2014-0160",
        )

    no_pfs = all_ciphers and not any(c.forward_secret for c in all_ciphers)
    add(
        "NOPFS",
        "No forward secrecy",
        "medium",
        bool(no_pfs),
        "No ECDHE/DHE suites offered." if no_pfs else "Forward secrecy available.",
        "",
    )

    return vulns


# --------------------------------------------------------------------------- #
# Grading
# --------------------------------------------------------------------------- #


def grade(result: ScanResult) -> Grade:
    protos = {p for p, ok in result.protocols.items() if ok}
    all_ciphers: list[CipherInfo] = [
        c for suites in result.ciphers.values() for c in suites
    ]
    caps: list[str] = []
    cert = result.certificate

    # Certificate trust gates -----------------------------------------------
    if cert is not None:
        if cert.expired:
            return Grade("T", 0, ["certificate expired"], {"certificate": 0})
        if cert.not_yet_valid:
            return Grade("T", 0, ["certificate not yet valid"], {"certificate": 0})
        if cert.hostname_mismatch:
            caps.append("hostname mismatch -> capped at M")
        if cert.self_signed:
            caps.append("self-signed certificate -> capped at T")

    # Hard failures ----------------------------------------------------------
    insecure = {"NULL", "ANON", "EXPORT", "RC4", "DES", "MD5"}
    if any(set(c.weaknesses) & insecure for c in all_ciphers):
        return Grade("F", 20, ["insecure cipher suites offered"], {"cipher": 0})
    if "SSLv2" in protos:
        return Grade("F", 15, ["SSLv2 supported"], {"protocol": 0})

    # Component scores (0-100) ----------------------------------------------
    proto_score = _protocol_score(protos, caps)
    kx_score = _kx_score(all_ciphers, cert)
    cipher_score = _cipher_score(all_ciphers, caps)

    composite = round(0.30 * proto_score + 0.30 * kx_score + 0.40 * cipher_score)
    breakdown = {
        "protocol": proto_score,
        "key_exchange": kx_score,
        "cipher": cipher_score,
    }

    letter = _score_to_letter(composite)

    # Caps -------------------------------------------------------------------
    if "SSLv3" in protos:
        letter = _cap(letter, "C")
        caps.append("SSLv3 supported -> capped at C")
    if protos & {"TLS1.0", "TLS1.1"}:
        letter = _cap(letter, "B")
        caps.append("TLS 1.0/1.1 supported -> capped at B")
    if all_ciphers and not any(c.forward_secret for c in all_ciphers):
        letter = _cap(letter, "B")
        caps.append("no forward secrecy -> capped at B")
    if any(c.cbc for c in all_ciphers) and "TLS1.3" not in protos:
        letter = _cap(letter, "A")

    # A+ upgrade: modern-only, all AEAD+PFS, HSTS present, healthy cert -------
    hsts = result.features.get("hsts")
    modern_only = protos and protos <= {"TLS1.2", "TLS1.3"}
    all_aead_pfs = all_ciphers and all(c.aead and c.forward_secret for c in all_ciphers)
    cert_ok = cert is not None and not (
        cert.expired or cert.self_signed or cert.hostname_mismatch or cert.uses_sha1
    )
    if letter == "A" and modern_only and all_aead_pfs and hsts and cert_ok:
        letter = "A+"

    if cert is not None:
        if cert.hostname_mismatch:
            letter = "M"
        elif cert.self_signed:
            letter = "T"

    return Grade(letter, composite, caps, breakdown)


def _protocol_score(protos: set[str], caps: list[str]) -> int:
    if not protos:
        return 0
    if "TLS1.3" in protos and not (protos & DEPRECATED_PROTOCOLS):
        return 100
    if "TLS1.2" in protos and not (protos & DEPRECATED_PROTOCOLS):
        return 95
    if protos & {"TLS1.0", "TLS1.1"}:
        return 70
    if "SSLv3" in protos:
        return 40
    return 80


def _kx_score(ciphers: list[CipherInfo], cert) -> int:
    if not ciphers:
        return 0
    bits = cert.public_key_bits if cert else 0
    ktype = (cert.public_key_type if cert else "").upper()
    if "EC" in ktype and bits >= 256:
        base = 100
    elif bits >= 4096:
        base = 95
    elif bits >= 2048:
        base = 90
    elif bits >= 1024:
        base = 50
    else:
        base = 100 if not cert else 40
    if not any(c.forward_secret for c in ciphers):
        base = min(base, 60)
    return base


def _cipher_score(ciphers: list[CipherInfo], caps: list[str]) -> int:
    if not ciphers:
        return 0
    strengths = [c.strength for c in ciphers]
    if any(s in {"insecure"} for s in strengths):
        return 20
    if any(s == "weak" for s in strengths):
        return 60
    if all(s == "recommended" for s in strengths):
        return 100
    return 85


_LETTERS = ["F", "E", "D", "C", "B", "A"]


def _score_to_letter(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    if score >= 35:
        return "E"
    return "F"


def _cap(letter: str, ceiling: str) -> str:
    order = ["F", "E", "D", "C", "B", "A", "A+"]
    if letter not in order or ceiling not in order:
        return letter
    return letter if order.index(letter) <= order.index(ceiling) else ceiling
