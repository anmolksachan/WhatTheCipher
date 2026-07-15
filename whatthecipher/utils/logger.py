"""Centralised logging.

Uses Rich's handler for pretty console logs when available and supports an
optional log file. Call :func:`configure` once from the CLI; everything else
just calls :func:`get_logger`.
"""

from __future__ import annotations

import logging

_CONFIGURED = False


def configure(
    verbose: bool = False, quiet: bool = False, log_file: str | None = None
) -> None:
    global _CONFIGURED
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)

    handlers: list[logging.Handler] = []
    try:
        from rich.logging import RichHandler

        handlers.append(
            RichHandler(rich_tracebacks=True, show_path=verbose, show_time=verbose)
        )
    except Exception:  # pragma: no cover
        handlers.append(logging.StreamHandler())

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        fh.setLevel(logging.DEBUG)
        handlers.append(fh)

    root = logging.getLogger("whatthecipher")
    root.handlers.clear()
    for h in handlers:
        root.addHandler(h)
    root.setLevel(logging.DEBUG if log_file else level)
    for h in root.handlers:
        if not isinstance(h, logging.FileHandler):
            h.setLevel(level)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    if not _CONFIGURED:
        logging.getLogger("whatthecipher").addHandler(logging.NullHandler())
    return logging.getLogger(
        name if name.startswith("whatthecipher") else f"whatthecipher.{name}"
    )
