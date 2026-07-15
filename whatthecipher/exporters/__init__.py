"""Output exporters: html, json, markdown, csv."""

from __future__ import annotations

from types import ModuleType
from typing import TYPE_CHECKING

from . import csv, html, json, markdown

if TYPE_CHECKING:  # pragma: no cover
    from ..scanner import ScanResult

EXPORTERS: dict[str, ModuleType] = {
    "html": html,
    "json": json,
    "markdown": markdown,
    "md": markdown,
    "csv": csv,
}

EXTENSIONS: dict[str, str] = {
    "html": "html",
    "json": "json",
    "markdown": "md",
    "md": "md",
    "csv": "csv",
}


def extension(fmt: str) -> str:
    """File extension to use for an output format."""
    return EXTENSIONS[fmt]


def write(
    fmt: str,
    results: list[ScanResult],
    path: str,
    tool_version: str = "",
) -> None:
    """Write *results* to *path* in the given format."""
    EXPORTERS[fmt].write(results, path, tool_version)


__all__ = [
    "EXPORTERS",
    "EXTENSIONS",
    "csv",
    "extension",
    "html",
    "json",
    "markdown",
    "write",
]
