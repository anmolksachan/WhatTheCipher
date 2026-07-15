"""Reusable builders for synthetic scan results (no network)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from whatthecipher import grading, recommendations, tls
from whatthecipher.parser import Target
from whatthecipher.scanner import ScanResult


def make_result(
    host="example.com",
    port=443,
    protocols=None,
    ciphers=None,
    cert=None,
    features=None,
) -> ScanResult:
    r = ScanResult(target=Target(host, port))
    r.reachable = True
    r.ip = "203.0.113.10"
    r.protocols = protocols or {
        "SSLv3": False,
        "TLS1.0": False,
        "TLS1.1": False,
        "TLS1.2": True,
        "TLS1.3": True,
    }
    r.ciphers = (
        ciphers
        if ciphers is not None
        else {
            "TLS1.2": [tls.classify_cipher(0xC030, "TLS1.2")],
            "TLS1.3": [tls.classify_cipher(0x1302, "TLS1.3")],
        }
    )
    r.certificate = cert
    r.features = features or {"hsts": True, "alpn": "h2", "http2": True}
    r.vulnerabilities = grading.detect_vulnerabilities(r)
    r.grade = grading.grade(r)
    r.recommendations = recommendations.generate(r)
    return r


def make_self_signed_der(host="test.local", days=90, key_bits=2048, sha1=False) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
    )
    algo = hashes.SHA1() if sha1 else hashes.SHA256()
    return builder.sign(key, algo).public_bytes(
        __import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]
        ).Encoding.DER
    )
