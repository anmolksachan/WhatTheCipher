"""Target and nmap-XML parsing.

Expands the many accepted input forms (bare domain, IP, URL, CIDR range, a file
of targets, or stdin) into a flat, de-duplicated list of ``Target`` objects.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    starttls: str | None = None

    def __str__(self) -> str:
        base = f"{self.host}:{self.port}"
        return f"{base} (STARTTLS {self.starttls})" if self.starttls else base


def _parse_one(token: str, default_port: int, starttls: str | None) -> list[Target]:
    token = token.strip()
    if not token or token.startswith("#"):
        return []

    # URL form -> extract host + port + implied protocol
    if "://" in token:
        parsed = urlparse(token)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme in ("https", "") else default_port)
        return [Target(host, port, starttls)] if host else []

    # host:port form (careful with IPv6 in brackets)
    if token.startswith("["):
        host, _, rest = token[1:].partition("]")
        port = int(rest.lstrip(":")) if rest.lstrip(":").isdigit() else default_port
        return [Target(host, port, starttls)]

    # CIDR range
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            return [Target(str(ip), default_port, starttls) for ip in net.hosts()]
        except ValueError:
            pass  # not a network; fall through

    if token.count(":") == 1 and not _looks_like_ipv6(token):
        host, _, port_s = token.partition(":")
        port = int(port_s) if port_s.isdigit() else default_port
        return [Target(host, port, starttls)]

    return [Target(token, default_port, starttls)]


def _looks_like_ipv6(token: str) -> bool:
    try:
        ipaddress.IPv6Address(token)
        return True
    except ValueError:
        return token.count(":") > 1


def parse_targets(
    raw_targets: list[str],
    default_port: int = 443,
    starttls: str | None = None,
    read_stdin: bool = False,
) -> list[Target]:
    """Expand raw CLI tokens into concrete Targets."""
    tokens: list[str] = []

    for item in raw_targets:
        # A path to a file of targets?
        if os.path.isfile(item):
            with open(item, encoding="utf-8") as fh:
                tokens.extend(line for line in fh.read().splitlines())
        else:
            tokens.append(item)

    if read_stdin or (not tokens and not sys.stdin.isatty()):
        tokens.extend(line for line in sys.stdin.read().splitlines())

    targets: list[Target] = []
    seen: set[tuple[str, int]] = set()
    for tok in tokens:
        for tgt in _parse_one(tok, default_port, starttls):
            key = (tgt.host, tgt.port)
            if key not in seen:
                seen.add(key)
                targets.append(tgt)
    return targets


# --------------------------------------------------------------------------- #
# nmap XML (ssl-enum-ciphers) ingestion
# --------------------------------------------------------------------------- #


def parse_nmap_xml(path: str) -> dict[str, dict]:
    """Parse an ``nmap -oX`` file produced with the ssl-enum-ciphers script.

    Returns ``{"host:port": {"protocols": [...], "ciphers": {proto: [names]}}}``.
    Provided for interoperability with existing nmap-based workflows.
    """
    tree = ElementTree.parse(path)
    root = tree.getroot()
    out: dict[str, dict] = {}

    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        for port in host.findall(".//port"):
            portid = port.get("portid")
            key = f"{addr}:{portid}"
            record: dict[str, Any] = {"protocols": [], "ciphers": {}}
            for script in port.findall("script"):
                if script.get("id") != "ssl-enum-ciphers":
                    continue
                for table in script.findall("table"):
                    proto = table.get("key")
                    if not proto:
                        continue
                    record["protocols"].append(proto)
                    names: list[str] = []
                    for ct in table.findall(".//table"):
                        for elem in ct.findall("elem"):
                            if elem.get("key") == "name":
                                names.append((elem.text or "").strip())
                    record["ciphers"][proto] = names
            if record["protocols"]:
                out[key] = record
    return out
