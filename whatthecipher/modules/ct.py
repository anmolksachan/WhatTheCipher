"""Certificate Transparency lookup via crt.sh (implemented).

Pulls historical/issued certificates for a domain from the public crt.sh CT log
mirror. Useful for subdomain discovery and spotting rogue issuance. Uses only
the standard library so it adds no dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


@dataclass
class CTEntry:
    common_name: str
    name_value: str
    issuer: str
    not_before: str
    not_after: str


def search(
    domain: str, timeout: float = 15.0, include_expired: bool = True
) -> list[CTEntry]:
    """Query crt.sh for certificates covering *domain* (and subdomains)."""
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    url = f"https://crt.sh/?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": "WhatTheCipher"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"crt.sh request failed: {exc}") from exc

    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("crt.sh returned unparseable data") from exc

    return [
        CTEntry(
            common_name=r.get("common_name", ""),
            name_value=r.get("name_value", ""),
            issuer=r.get("issuer_name", ""),
            not_before=r.get("not_before", ""),
            not_after=r.get("not_after", ""),
        )
        for r in rows
    ]


def unique_subdomains(domain: str, timeout: float = 15.0) -> list[str]:
    """Return the sorted set of unique names seen in CT for *domain*."""
    names: set[str] = set()
    for entry in search(domain, timeout):
        for name in entry.name_value.splitlines():
            name = name.strip().lower()
            if name and "*" not in name:
                names.add(name)
    return sorted(names)
