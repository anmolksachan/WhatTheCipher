"""Third-party enrichment integrations (documented extension points).

Each function has a stable signature and a clear contract so the CLI/scanner can
wire them in without churn. They raise ``NotImplementedError`` until an API key
+ client is supplied — deliberately keeping network calls and credentials out of
the default fast path.
"""

from __future__ import annotations


def ssl_labs_lookup(
    host: str, api_base: str = "https://api.ssllabs.com/api/v3"
) -> dict:  # pragma: no cover
    """Fetch a cached Qualys SSL Labs assessment for *host*.

    Contract: return the parsed JSON 'endpoints' block. Respect SSL Labs' rate
    limits and 'startNew=off' caching guidance. Implement with urllib + polling
    on status == READY.
    """
    raise NotImplementedError("SSL Labs API polling is an extension point.")


def shodan_lookup(ip: str, api_key: str) -> dict:  # pragma: no cover
    """Return Shodan's host record for *ip* (open ports, banners, SSL info).

    Contract: GET https://api.shodan.io/shodan/host/{ip}?key=API_KEY.
    """
    raise NotImplementedError("Provide a Shodan API key + client to enable.")


def censys_lookup(ip: str, api_id: str, api_secret: str) -> dict:  # pragma: no cover
    """Return Censys host data for *ip* (services, certificates)."""
    raise NotImplementedError("Provide Censys credentials to enable.")


def mozilla_compare(result, level: str = "intermediate") -> dict:  # pragma: no cover
    """Compare a ScanResult against a Mozilla SSL config level.

    Contract: load the Mozilla server-side-tls JSON (bundled or fetched), diff
    the offered protocols/ciphers against the chosen level (modern / intermediate
    / old) and return {'missing': [...], 'extra': [...], 'compliant': bool}.
    """
    raise NotImplementedError("Mozilla config comparison is an extension point.")


def dns_caa(domain: str, resolver: str | None = None) -> list[str]:  # pragma: no cover
    """Return CAA records for *domain* (which CAs may issue)."""
    raise NotImplementedError("Wire a DNS resolver (e.g. dnspython) to enable.")
