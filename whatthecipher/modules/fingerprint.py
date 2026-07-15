"""TLS fingerprinting.

Includes a working, lightweight ServerHello fingerprint (hash of the negotiated
version + cipher + extension set) and clearly-marked scaffolds for full JARM and
JA3S, which require a fixed battery of specially-crafted probes.
"""

from __future__ import annotations

import hashlib

from ..tls import PROTOCOLS, _send_hello_read_reply, build_client_hello


def server_hello_fingerprint(host: str, port: int, timeout: float = 8.0) -> str:
    """A quick, deterministic fingerprint of the server's TLS1.2 ServerHello.

    Not JARM — but stable and cheap, and useful for clustering hosts by stack.
    """
    record_version, hello_version, _ = PROTOCOLS["TLS1.2"]
    from ..tls import _candidate_suites

    hello = build_client_hello(
        host, hello_version, _candidate_suites(), record_version, False
    )
    reply = _send_hello_read_reply(host, port, hello, timeout, None)
    if reply is None:
        return "0" * 16
    ctype, payload = reply
    if not payload or payload[0] != 2:
        return "0" * 16
    # version(2) after handshake header, cipher after random+session id
    material = payload[:2] + payload[6:8]
    try:
        pos = 4 + 2 + 32
        sid_len = payload[pos]
        cipher = payload[pos + 1 + sid_len : pos + 3 + sid_len]
        material += cipher
    except IndexError:
        pass
    return hashlib.sha256(material).hexdigest()[:16]


def jarm(host: str, port: int, timeout: float = 8.0) -> str:  # pragma: no cover
    """Full JARM active fingerprint.

    JARM sends 10 deliberately-ordered ClientHello probes (varying TLS version,
    cipher ordering, GREASE and extension permutations) and hashes the aggregated
    ServerHello responses. Implementing the exact probe battery is a documented
    TODO — see https://github.com/salesforce/jarm for the reference algorithm.
    """
    raise NotImplementedError(
        "JARM requires the fixed 10-probe battery; see modules docstring."
    )


def ja3s(host: str, port: int, timeout: float = 8.0) -> str:  # pragma: no cover
    """JA3S server fingerprint (MD5 of version,cipher,extensions).

    The wire pieces are already parsed by tls.py; wiring the exact JA3S string
    format is a documented TODO — see https://github.com/salesforce/ja3.
    """
    raise NotImplementedError("JA3S formatting is a documented extension point.")
