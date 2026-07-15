"""JSON exporter — machine-readable output for automation/CI pipelines."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ..scanner import ScanResult

TOOL = "WhatTheCipher"


def result_to_dict(result: ScanResult) -> dict:
    """Canonical dict representation reused by every exporter."""
    return {
        "target": result.host,
        "ip": result.ip,
        "port": result.port,
        "starttls": result.target.starttls,
        "reachable": result.reachable,
        "error": result.error,
        "timestamp": result.timestamp,
        "duration_seconds": round(result.duration, 3),
        "grade": (
            {
                "letter": result.grade.letter,
                "score": result.grade.score,
                "caps": result.grade.caps,
                "breakdown": result.grade.breakdown,
            }
            if result.grade
            else None
        ),
        "protocols": {
            proto: {
                "supported": supported,
                "ciphers": [
                    {
                        "code": f"0x{c.code:04x}",
                        "name": c.name,
                        "kx": c.kx,
                        "auth": c.auth,
                        "encryption": c.enc,
                        "mac": c.mac,
                        "bits": c.bits,
                        "forward_secret": c.forward_secret,
                        "aead": c.aead,
                        "cbc": c.cbc,
                        "strength": c.strength,
                        "weaknesses": c.weaknesses,
                    }
                    for c in result.ciphers.get(proto, [])
                ],
            }
            for proto, supported in result.protocols.items()
        },
        "certificate": asdict(result.certificate) if result.certificate else None,
        "features": result.features,
        "vulnerabilities": [
            {
                "id": v.id,
                "name": v.name,
                "severity": v.severity,
                "present": v.present,
                "detail": v.detail,
                "reference": v.reference,
            }
            for v in result.vulnerabilities
        ],
        "recommendations": [
            {
                "title": r.title,
                "severity": r.severity,
                "detail": r.detail,
                "reference": r.reference,
            }
            for r in result.recommendations
        ],
    }


def export(results: list[ScanResult], tool_version: str = "") -> str:
    payload = {
        "tool": TOOL,
        "version": tool_version,
        "count": len(results),
        "results": [result_to_dict(r) for r in results],
    }
    return json.dumps(payload, indent=2, default=str)


def write(results: list[ScanResult], path: str, tool_version: str = "") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(export(results, tool_version))
