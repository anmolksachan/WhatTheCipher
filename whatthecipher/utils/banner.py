"""The WhatTheCipher ASCII banner."""

from __future__ import annotations

from .. import __version__

BANNER = r"""
        _    _ _           _   _____ _          ____ _       _
       | |  | | |         | | |_   _| |        / ___(_)_ __ | |_  ___ _ _
       | |  | | |__   __ _| |_  | | | |__   ___| |   | | '_ \| '_ \/ -_) '_|
       | |/\| | '_ \ / _` | __| | | | '_ \ / _ \ |   | | |_) | | | \___|_|
       \  /\  / | | | (_| | |_  | | | | | |  __/ |___| | .__/| | | |
        \/  \/|_| |_|\__,_|\__| \_/ |_| |_|\___|\____|_|_|   |_| |_|
"""

TAGLINE = "  Modern TLS/SSL assessment framework"


def render(version: str = __version__, use_color: bool = True) -> str:
    author = "  by Anmol K Sachan (@FR13ND0x7F)"
    meta = f"{TAGLINE}  ·  v{version}\n{author}"
    if not use_color:
        return f"{BANNER}\n{meta}\n"
    try:
        from rich.console import Console
        from rich.text import Text

        console = Console(record=True, width=80)
        text = Text(BANNER, style="bold cyan")
        text.append(f"\n{TAGLINE}", style="bold white")
        text.append(f"  ·  v{version}\n", style="dim")
        text.append(author, style="magenta")
        console.print(text)
        return console.export_text(styles=True)
    except Exception:
        return f"{BANNER}\n{meta}\n"


def print_banner(version: str = __version__) -> None:
    try:
        from rich.console import Console
        from rich.text import Text

        console = Console()
        text = Text(BANNER, style="bold cyan")
        text.append(f"{TAGLINE}", style="bold white")
        text.append(f"  ·  v{version}\n", style="dim")
        text.append("  by Anmol K Sachan (@FR13ND0x7F)", style="magenta")
        console.print(text)
    except Exception:
        print(BANNER)
        print(f"{TAGLINE}  ·  v{version}")
        print("  by Anmol K Sachan (@FR13ND0x7F)")
