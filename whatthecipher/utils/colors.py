"""Shared severity / grade colour vocabulary.

One source of truth so the terminal UI and the HTML report agree on what red
means. Rich style names on the left, hex values (for HTML) on the right.
"""

from __future__ import annotations

# Rich style per severity
SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

SEVERITY_HEX = {
    "critical": "#e5484d",
    "high": "#f76808",
    "medium": "#f5d90a",
    "low": "#46a758",
    "info": "#8b8d98",
}

# Grade -> (rich style, hex)
GRADE_STYLE = {
    "A+": "bold green",
    "A": "green",
    "B": "yellow",
    "C": "yellow",
    "D": "red",
    "E": "red",
    "F": "bold red",
    "T": "bold red",
    "M": "bold red",
}

GRADE_HEX = {
    "A+": "#30a46c",
    "A": "#46a758",
    "B": "#f5d90a",
    "C": "#ffb224",
    "D": "#f76808",
    "E": "#e5484d",
    "F": "#e5484d",
    "T": "#e5484d",
    "M": "#e5484d",
}

STRENGTH_STYLE = {
    "recommended": "green",
    "secure": "cyan",
    "weak": "yellow",
    "insecure": "bold red",
}

STRENGTH_HEX = {
    "recommended": "#30a46c",
    "secure": "#3e9dd6",
    "weak": "#f5d90a",
    "insecure": "#e5484d",
}


def grade_style(letter: str) -> str:
    return GRADE_STYLE.get(letter, "white")


def grade_hex(letter: str) -> str:
    return GRADE_HEX.get(letter, "#8b8d98")
