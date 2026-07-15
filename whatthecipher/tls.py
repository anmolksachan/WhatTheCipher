"""Native TLS probing engine.

Constructs raw ``ClientHello`` messages at the socket level and inspects the
``ServerHello`` reply. Doing the handshake by hand (rather than via the local
``ssl`` module) lets WhatTheCipher test legacy protocols and individual cipher
suites even when the host OpenSSL has them compiled out — the same approach used
by SSLyze and testssl.sh.

Nothing in here scrapes HTML. Cipher metadata is derived from the IANA suite
name plus the bundled ``data/cipher_suites.json`` table.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import ssl
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from typing import cast

try:
    from cryptography.hazmat.primitives.asymmetric import x25519

    _HAVE_CRYPTO_KEX = True
except Exception:  # pragma: no cover - optional at import time
    _HAVE_CRYPTO_KEX = False


# --------------------------------------------------------------------------- #
# Protocol constants
# --------------------------------------------------------------------------- #

# Human name -> (record_version, hello_version, is_tls13)
PROTOCOLS: dict[str, tuple[int, int, bool]] = {
    "SSLv3": (0x0300, 0x0300, False),
    "TLS1.0": (0x0301, 0x0301, False),
    "TLS1.1": (0x0301, 0x0302, False),
    "TLS1.2": (0x0301, 0x0303, False),
    "TLS1.3": (0x0301, 0x0303, True),
}

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLS1.0", "TLS1.1"}

# Record content types
_CT_CHANGE_CIPHER_SPEC = 20
_CT_ALERT = 21
_CT_HANDSHAKE = 22

# Handshake types
_HS_CLIENT_HELLO = 1
_HS_SERVER_HELLO = 2

# TLS 1.3-only suites (used when probing TLS1.3)
_TLS13_SUITES = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]


# --------------------------------------------------------------------------- #
# Cipher suite database + classification
# --------------------------------------------------------------------------- #


def _load_suite_names() -> dict[int, str]:
    try:
        with (
            resources.files("whatthecipher.data")
            .joinpath("cipher_suites.json")
            .open("r", encoding="utf-8") as fh
        ):
            raw = json.load(fh)
    except Exception:
        here = os.path.join(os.path.dirname(__file__), "data", "cipher_suites.json")
        with open(here, encoding="utf-8") as fh:
            raw = json.load(fh)
    return {int(code, 16): name for code, name in raw.items() if code.startswith("0x")}


SUITE_NAMES: dict[int, str] = _load_suite_names()


def suite_name(code: int) -> str:
    """Return the IANA name for a suite code, or a synthetic name if unknown."""
    return SUITE_NAMES.get(code, f"TLS_UNKNOWN_0x{code:04x}")


@dataclass
class CipherInfo:
    code: int
    name: str
    protocol: str = ""
    kx: str = ""  # key exchange
    auth: str = ""  # authentication
    enc: str = ""  # bulk encryption
    mac: str = ""  # MAC / PRF
    bits: int = 0  # symmetric key size
    forward_secret: bool = False
    aead: bool = False
    cbc: bool = False
    weaknesses: list[str] = field(default_factory=list)

    @property
    def strength(self) -> str:
        if self.weaknesses:
            return (
                "insecure"
                if any(
                    w in {"NULL", "EXPORT", "ANON", "RC4", "DES", "3DES", "MD5"}
                    for w in self.weaknesses
                )
                else "weak"
            )
        if self.aead and self.forward_secret and self.bits >= 128:
            return "recommended"
        return "secure"


def classify_cipher(code: int, protocol: str = "") -> CipherInfo:
    """Derive full security metadata from a suite code + its IANA name."""
    name = suite_name(code)
    info = CipherInfo(code=code, name=name, protocol=protocol)
    u = name.upper()

    # Key exchange / authentication
    if protocol == "TLS1.3" or code in _TLS13_SUITES:
        info.kx, info.auth = "ECDHE/DHE", "signature"
        info.forward_secret = True
    elif "ECDHE" in u:
        info.kx, info.forward_secret = "ECDHE", True
    elif "DHE" in u:
        info.kx, info.forward_secret = "DHE", True
    elif "ECDH_" in u:
        info.kx = "ECDH"
    elif "_RSA" in u or u.startswith("TLS_RSA"):
        info.kx = "RSA"
    if "ECDSA" in u:
        info.auth = "ECDSA"
    elif "_DSS" in u:
        info.auth = "DSS"
    elif "ANON" in u or "_ANON_" in u:
        info.auth = "anonymous"
        info.weaknesses.append("ANON")
    elif "RSA" in u:
        info.auth = info.auth or "RSA"

    # Bulk encryption + AEAD/CBC + key size
    if "CHACHA20" in u:
        info.enc, info.aead, info.bits = "ChaCha20-Poly1305", True, 256
    elif "AES_256_GCM" in u:
        info.enc, info.aead, info.bits = "AES-256-GCM", True, 256
    elif "AES_128_GCM" in u:
        info.enc, info.aead, info.bits = "AES-128-GCM", True, 128
    elif "AES_128_CCM" in u:
        info.enc, info.aead, info.bits = "AES-128-CCM", True, 128
    elif "AES_256_CBC" in u:
        info.enc, info.cbc, info.bits = "AES-256-CBC", True, 256
    elif "AES_128_CBC" in u:
        info.enc, info.cbc, info.bits = "AES-128-CBC", True, 128
    elif "3DES" in u:
        info.enc, info.cbc, info.bits = "3DES-CBC", True, 112
        info.weaknesses.append("3DES")
    elif "DES_CBC" in u or "DES40" in u:
        info.enc, info.cbc, info.bits = "DES-CBC", True, 56
        info.weaknesses.append("DES")
    elif "RC4" in u:
        info.enc, info.bits = "RC4", 128
        info.weaknesses.append("RC4")
    elif "WITH_NULL" in u or "_NULL_" in u:
        info.enc, info.bits = "NULL", 0
        info.weaknesses.append("NULL")

    # MAC / PRF
    if "SHA384" in u:
        info.mac = "SHA384"
    elif "SHA256" in u:
        info.mac = "SHA256"
    elif "_SHA" in u:
        info.mac = "SHA1"
    elif "_MD5" in u:
        info.mac = "MD5"
        info.weaknesses.append("MD5")
    if info.aead and not info.mac:
        info.mac = "AEAD"

    # Cross-cutting weaknesses
    if "EXPORT" in u:
        info.weaknesses.append("EXPORT")
    if info.cbc and protocol in DEPRECATED_PROTOCOLS:
        info.weaknesses.append("CBC-on-legacy")

    return info


# --------------------------------------------------------------------------- #
# ClientHello construction
# --------------------------------------------------------------------------- #


def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(body)) + body


def _sni_extension(hostname: str) -> bytes:
    host = hostname.encode("idna") if hostname else b""
    entry = b"\x00" + struct.pack(">H", len(host)) + host  # type host_name=0
    return _ext(0x0000, struct.pack(">H", len(entry)) + entry)


def _supported_groups_extension() -> bytes:
    # x25519, secp256r1, secp384r1, secp521r1, ffdhe2048
    groups = [0x001D, 0x0017, 0x0018, 0x0019, 0x0100]
    body = struct.pack(">H", len(groups) * 2) + b"".join(
        struct.pack(">H", g) for g in groups
    )
    return _ext(0x000A, body)


def _ec_point_formats_extension() -> bytes:
    return _ext(0x000B, b"\x01\x00")  # uncompressed


def _sig_algs_extension() -> bytes:
    algs = [
        0x0403,
        0x0503,
        0x0603,  # ecdsa_secp{256,384,521}
        0x0804,
        0x0805,
        0x0806,  # rsa_pss_rsae_*
        0x0401,
        0x0501,
        0x0601,  # rsa_pkcs1_*
        0x0203,
        0x0201,  # legacy ecdsa/rsa sha1
    ]
    body = struct.pack(">H", len(algs) * 2) + b"".join(struct.pack(">H", a) for a in algs)
    return _ext(0x000D, body)


def _supported_versions_extension(hello_version: int, tls13: bool) -> bytes:
    versions = [0x0304, hello_version] if tls13 else [hello_version]
    body = struct.pack(">B", len(versions) * 2) + b"".join(
        struct.pack(">H", v) for v in versions
    )
    return _ext(0x002B, body)


def _key_share_extension() -> bytes:
    if not _HAVE_CRYPTO_KEX:
        # Empty key_share -> triggers HelloRetryRequest but still proves TLS1.3.
        return _ext(0x0033, struct.pack(">H", 0))
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    entry = struct.pack(">HH", 0x001D, len(pub)) + pub  # group x25519
    return _ext(0x0033, struct.pack(">H", len(entry)) + entry)


def build_client_hello(
    hostname: str,
    hello_version: int,
    cipher_codes: list[int],
    record_version: int,
    tls13: bool,
) -> bytes:
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)  # non-empty for TLS1.3 middlebox compatibility

    ciphers = b"".join(struct.pack(">H", c) for c in cipher_codes)
    ciphers += struct.pack(">H", 0x00FF)  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV

    extensions = b"".join(
        [
            _sni_extension(hostname) if hostname else b"",
            _ec_point_formats_extension(),
            _supported_groups_extension(),
            _sig_algs_extension(),
        ]
    )
    if tls13:
        extensions += _supported_versions_extension(hello_version, True)
        extensions += _key_share_extension()

    body = b"".join(
        [
            struct.pack(">H", hello_version),
            random_bytes,
            struct.pack(">B", len(session_id)) + session_id,
            struct.pack(">H", len(ciphers)) + ciphers,
            b"\x01\x00",  # 1 compression method: null
            struct.pack(">H", len(extensions)) + extensions,
        ]
    )

    handshake = struct.pack(">B", _HS_CLIENT_HELLO)
    handshake += struct.pack(">I", len(body))[1:]  # 24-bit length
    handshake += body

    record = struct.pack(">BHH", _CT_HANDSHAKE, record_version, len(handshake))
    return record + handshake


# --------------------------------------------------------------------------- #
# Wire I/O
# --------------------------------------------------------------------------- #


class TLSProbeError(Exception):
    """Raised for network-level failures while probing."""


def _read_record(sock: socket.socket) -> tuple[int, bytes] | None:
    """Read one TLS record; return (content_type, payload) or None on EOF."""
    header = _recv_exact(sock, 5)
    if not header:
        return None
    ctype, _ver, length = struct.unpack(">BHH", header)
    if length == 0 or length > 65535:
        return ctype, b""
    payload = _recv_exact(sock, length)
    return ctype, payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _parse_server_hello_cipher(payload: bytes) -> int | None:
    """Pull the selected cipher suite out of a ServerHello handshake payload."""
    if len(payload) < 4 or payload[0] != _HS_SERVER_HELLO:
        return None
    # skip: hs_type(1) hs_len(3) version(2) random(32)
    pos = 4 + 2 + 32
    if pos >= len(payload):
        return None
    sid_len = payload[pos]
    pos += 1 + sid_len
    if pos + 2 > len(payload):
        return None
    return struct.unpack(">H", payload[pos : pos + 2])[0]


def _connect(host: str, port: int, timeout: float, starttls: str | None) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    if starttls:
        do_starttls(sock, starttls, host, timeout)
    return sock


def _send_hello_read_reply(
    host: str,
    port: int,
    hello: bytes,
    timeout: float,
    starttls: str | None,
) -> tuple[int, bytes] | None:
    """Send a ClientHello, return the first *meaningful* record."""
    sock = None
    try:
        sock = _connect(host, port, timeout, starttls)
        sock.sendall(hello)
        for _ in range(4):  # skip ChangeCipherSpec noise
            rec = _read_record(sock)
            if rec is None:
                return None
            ctype, payload = rec
            if ctype == _CT_CHANGE_CIPHER_SPEC:
                continue
            return ctype, payload
        return None
    finally:
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()


# --------------------------------------------------------------------------- #
# Public probing API
# --------------------------------------------------------------------------- #


def probe_protocol(
    host: str,
    port: int,
    protocol: str,
    timeout: float = 8.0,
    starttls: str | None = None,
) -> bool:
    """Return True if *protocol* is accepted by the host."""
    if protocol not in PROTOCOLS:
        return False
    record_version, hello_version, tls13 = PROTOCOLS[protocol]
    codes = list(_TLS13_SUITES) if tls13 else _candidate_suites()
    hello = build_client_hello(host, hello_version, codes, record_version, tls13)
    reply = _send_hello_read_reply(host, port, hello, timeout, starttls)
    if reply is None:
        return False
    ctype, payload = reply
    if ctype != _CT_HANDSHAKE:
        return False
    return _parse_server_hello_cipher(payload) is not None


def enumerate_ciphers(
    host: str,
    port: int,
    protocol: str,
    timeout: float = 8.0,
    starttls: str | None = None,
    max_rounds: int = 60,
) -> list[CipherInfo]:
    """Enumerate accepted cipher suites for *protocol* (fast pick-and-remove)."""
    record_version, hello_version, tls13 = PROTOCOLS[protocol]
    remaining = list(_TLS13_SUITES) if tls13 else _candidate_suites()
    accepted: list[CipherInfo] = []

    for _ in range(max_rounds):
        if not remaining:
            break
        hello = build_client_hello(host, hello_version, remaining, record_version, tls13)
        reply = _send_hello_read_reply(host, port, hello, timeout, starttls)
        if reply is None:
            break
        ctype, payload = reply
        if ctype != _CT_HANDSHAKE:
            break
        chosen = _parse_server_hello_cipher(payload)
        if chosen is None or chosen not in remaining:
            break
        accepted.append(classify_cipher(chosen, protocol))
        remaining.remove(chosen)

    return accepted


def _candidate_suites() -> list[int]:
    """All non-TLS1.3 suites we know about, strong first (server preference)."""
    codes = [c for c in SUITE_NAMES if c not in _TLS13_SUITES and c != 0x00FF]
    return sorted(codes, reverse=True)


# --------------------------------------------------------------------------- #
# Certificate retrieval + parsing
# --------------------------------------------------------------------------- #


@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    san: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    signature_algorithm: str = ""
    public_key_type: str = ""
    public_key_bits: int = 0
    serial: str = ""
    version: str = ""
    self_signed: bool = False
    expired: bool = False
    not_yet_valid: bool = False
    hostname_mismatch: bool = False
    uses_sha1: bool = False
    ocsp_urls: list[str] = field(default_factory=list)
    crl_urls: list[str] = field(default_factory=list)
    must_staple: bool = False
    errors: list[str] = field(default_factory=list)


def get_certificate(
    host: str,
    port: int,
    timeout: float = 8.0,
    starttls: str | None = None,
) -> CertificateInfo | None:
    """Fetch and parse the leaf certificate. Uses a permissive context so we can
    still inspect expired / self-signed / mismatched certs."""
    der: bytes | None = None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(ValueError, AttributeError):
        ctx.minimum_version = ssl.TLSVersion.TLSv1

    raw = None
    try:
        raw = _connect(host, port, timeout, starttls)
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    except Exception as exc:  # noqa: BLE001 - report, don't crash the scan
        if raw is not None:
            with contextlib.suppress(OSError):
                raw.close()
        return _cert_from_error(exc)

    if not der:
        return None
    return parse_certificate_der(der, host)


def _cert_from_error(exc: Exception) -> CertificateInfo:
    info = CertificateInfo()
    info.errors.append(f"handshake failed: {exc}")
    return info


def parse_certificate_der(der: bytes, expected_host: str = "") -> CertificateInfo:
    info = CertificateInfo()
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
        from cryptography.x509.oid import ExtensionOID, NameOID
    except Exception:
        info.errors.append("python 'cryptography' package required for cert parsing")
        return info

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:  # noqa: BLE001
        info.errors.append(f"could not parse certificate: {exc}")
        return info

    def _name(name) -> str:
        try:
            cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn:
                return cn[0].value
            return name.rfc4514_string()
        except Exception:
            return str(name)

    info.subject = _name(cert.subject)
    info.issuer = _name(cert.issuer)
    info.self_signed = cert.subject == cert.issuer
    info.serial = format(cert.serial_number, "x")
    info.version = cert.version.name

    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        nb = cert.not_valid_before.replace(tzinfo=UTC)
        na = cert.not_valid_after.replace(tzinfo=UTC)
    info.not_before = nb.isoformat()
    info.not_after = na.isoformat()
    now = datetime.now(UTC)
    info.days_until_expiry = (na - now).days
    info.expired = na < now
    info.not_yet_valid = nb > now

    info.signature_algorithm = (
        cert.signature_hash_algorithm.name
        if (cert.signature_hash_algorithm)
        else "unknown"
    )
    info.uses_sha1 = "sha1" in info.signature_algorithm.lower()

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        info.public_key_type, info.public_key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        info.public_key_type, info.public_key_bits = (
            f"EC ({pub.curve.name})",
            pub.curve.key_size,
        )
    elif isinstance(pub, dsa.DSAPublicKey):
        info.public_key_type, info.public_key_bits = "DSA", pub.key_size
    else:
        info.public_key_type = type(pub).__name__

    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san = cast(x509.SubjectAlternativeName, san_ext.value)
        info.san = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    try:
        aia = cast(
            x509.AuthorityInformationAccess,
            cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value,
        )
        for desc in aia:
            if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
                info.ocsp_urls.append(desc.access_location.value)
    except x509.ExtensionNotFound:
        pass

    try:
        cdp = cast(
            x509.CRLDistributionPoints,
            cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            ).value,
        )
        for point in cdp:
            if point.full_name:
                for gn in point.full_name:
                    info.crl_urls.append(gn.value)
    except x509.ExtensionNotFound:
        pass

    try:
        tls_feat = cast(
            x509.TLSFeature,
            cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE).value,
        )
        info.must_staple = any(
            getattr(f, "value", None) == 5 or f == x509.TLSFeatureType.status_request
            for f in tls_feat
        )
    except x509.ExtensionNotFound:
        pass

    if expected_host and (info.san or info.subject):
        info.hostname_mismatch = not _hostname_matches(
            expected_host, info.san or [info.subject]
        )

    return info


def _hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True
    return False


# --------------------------------------------------------------------------- #
# STARTTLS
# --------------------------------------------------------------------------- #


def do_starttls(sock: socket.socket, proto: str, host: str, timeout: float) -> None:
    """Drive a plaintext protocol up to the point TLS begins."""
    proto = proto.lower()

    def recv() -> bytes:
        try:
            return sock.recv(4096)
        except TimeoutError:
            return b""

    def send(line: str) -> None:
        sock.sendall(line.encode() + b"\r\n")

    if proto == "smtp":
        recv()
        send(f"EHLO {host}")
        recv()
        send("STARTTLS")
        recv()
    elif proto == "imap":
        recv()
        send("a1 STARTTLS")
        recv()
    elif proto == "pop3":
        recv()
        send("STLS")
        recv()
    elif proto == "ftp":
        recv()
        send("AUTH TLS")
        recv()
    elif proto == "xmpp":
        send(
            f"<stream:stream xmlns='jabber:client' "
            f"xmlns:stream='http://etherx.jabber.org/streams' to='{host}' "
            f"version='1.0'>"
        )
        recv()
        send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        recv()
    elif proto in {"ldap", "postgres", "mysql", "rdp", "mqtt", "redis"}:
        # These use binary negotiation; full support is a documented TODO.
        raise TLSProbeError(f"STARTTLS for {proto} not yet implemented")
    else:
        raise TLSProbeError(f"unknown STARTTLS protocol: {proto}")


STARTTLS_DEFAULT_PORTS = {
    "smtp": 587,
    "imap": 143,
    "pop3": 110,
    "ftp": 21,
    "xmpp": 5222,
    "ldap": 389,
    "mysql": 3306,
    "postgres": 5432,
}
