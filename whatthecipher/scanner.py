"""Scan orchestration.

Runs the full assessment for each target and fans work out across a thread pool.
Each host produces a single :class:`ScanResult` that every exporter consumes.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import grading, recommendations, tls
from .parser import Target
from .utils.logger import get_logger

log = get_logger(__name__)

PROTOCOL_ORDER = ["SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]


@dataclass
class ScanConfig:
    timeout: float = 8.0
    threads: int = 20
    check_certificate: bool = True
    check_features: bool = True
    do_grade: bool = True
    do_recommend: bool = True


@dataclass
class ScanResult:
    target: Target
    ip: str = ""
    reachable: bool = False
    error: str | None = None
    protocols: dict[str, bool] = field(default_factory=dict)
    ciphers: dict[str, list[tls.CipherInfo]] = field(default_factory=dict)
    certificate: tls.CertificateInfo | None = None
    features: dict[str, object] = field(default_factory=dict)
    vulnerabilities: list[grading.Vulnerability] = field(default_factory=list)
    grade: grading.Grade | None = None
    recommendations: list[recommendations.Recommendation] = field(default_factory=list)
    duration: float = 0.0
    timestamp: str = ""

    @property
    def host(self) -> str:
        return self.target.host

    @property
    def port(self) -> int:
        return self.target.port


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


def scan_target(target: Target, config: ScanConfig) -> ScanResult:
    """Run the full assessment against a single target."""
    start = time.perf_counter()
    result = ScanResult(target=target, timestamp=datetime.now(UTC).isoformat())
    result.ip = _resolve(target.host)

    try:
        with socket.create_connection((target.host, target.port), timeout=config.timeout):
            result.reachable = True
    except TimeoutError:
        result.error = "connection timed out"
    except socket.gaierror:
        result.error = "DNS resolution failed"
    except ConnectionRefusedError:
        result.error = "connection refused"
    except OSError as exc:
        result.error = f"connection error: {exc}"

    if not result.reachable:
        result.duration = time.perf_counter() - start
        log.debug("%s unreachable: %s", target, result.error)
        return result

    # Protocols + ciphers ----------------------------------------------------
    for proto in PROTOCOL_ORDER:
        try:
            supported = tls.probe_protocol(
                target.host, target.port, proto, config.timeout, target.starttls
            )
        except tls.TLSProbeError as exc:
            log.debug("%s %s probe error: %s", target, proto, exc)
            supported = False
        result.protocols[proto] = supported
        if supported:
            try:
                result.ciphers[proto] = tls.enumerate_ciphers(
                    target.host,
                    target.port,
                    proto,
                    config.timeout,
                    target.starttls,
                )
            except tls.TLSProbeError as exc:
                log.debug("%s %s cipher enum error: %s", target, proto, exc)
                result.ciphers[proto] = []

    # Certificate ------------------------------------------------------------
    if config.check_certificate:
        try:
            result.certificate = tls.get_certificate(
                target.host, target.port, config.timeout, target.starttls
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("%s cert error: %s", target, exc)

    # Features (ALPN / HTTP2 / HSTS / compression) ---------------------------
    if config.check_features:
        result.features = _detect_features(target, config)

    # Vulnerabilities / grade / recommendations ------------------------------
    result.vulnerabilities = grading.detect_vulnerabilities(result)
    if config.do_grade:
        result.grade = grading.grade(result)
    if config.do_recommend:
        result.recommendations = recommendations.generate(result)

    result.duration = time.perf_counter() - start
    return result


def _detect_features(target: Target, config: ScanConfig) -> dict[str, object]:
    feats: dict[str, object] = {
        "alpn": None,
        "http2": None,
        "compression": None,
        "hsts": None,
        "secure_renegotiation": None,
    }
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(NotImplementedError):
        ctx.set_alpn_protocols(["h2", "http/1.1"])

    raw = None
    try:
        raw = socket.create_connection((target.host, target.port), timeout=config.timeout)
        raw.settimeout(config.timeout)
        if target.starttls:
            tls.do_starttls(raw, target.starttls, target.host, config.timeout)
        with ctx.wrap_socket(raw, server_hostname=target.host) as sock:
            alpn = sock.selected_alpn_protocol()
            feats["alpn"] = alpn
            feats["http2"] = alpn == "h2"
            feats["compression"] = sock.compression()
            if not target.starttls:
                feats["hsts"] = _probe_hsts(sock, target.host)
    except Exception as exc:  # noqa: BLE001
        log.debug("%s feature detection failed: %s", target, exc)
        if raw is not None:
            with contextlib.suppress(OSError):
                raw.close()
    return feats


def _probe_hsts(sock: ssl.SSLSocket, host: str) -> bool | None:
    try:
        req = (
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: WhatTheCipher\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        data = b""
        while len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        return b"strict-transport-security" in data.lower()
    except Exception:  # noqa: BLE001
        return None


def scan_all(
    targets: list[Target],
    config: ScanConfig,
    on_result: Callable[[ScanResult], None] | None = None,
) -> list[ScanResult]:
    """Scan every target in parallel. ``on_result`` fires as each completes."""
    results: list[ScanResult] = []
    if not targets:
        return results

    workers = max(1, min(config.threads, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_target, t, config): t for t in targets}
        for fut in as_completed(futures):
            target = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001
                res = ScanResult(target=target, error=f"scan crashed: {exc}")
            results.append(res)
            if on_result:
                on_result(res)
    # stable order matching input
    order = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.target, 0))
    return results
