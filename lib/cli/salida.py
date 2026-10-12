"""Salida por consola: colores y mensajes de fase."""

from __future__ import annotations

import os
import sys

from netspy_env import IS_WINDOWS, is_interactive


class C:
    """Paleta ANSI. Se apaga sola si el terminal no la soporta."""

    _enabled = True

    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    NC = "\033[0m"

    @classmethod
    def off(cls) -> None:
        cls._enabled = False
        for name in ("RED", "GREEN", "YELLOW", "CYAN", "BOLD", "DIM", "NC"):
            setattr(cls, name, "")

def _c(text: str) -> str:
    return text if C._enabled else text

def say(msg: str = "") -> None:
    print(msg)

def phase_info(number: str, title: str) -> None:
    say(f"\n{_c(C.CYAN)}[+]{_c(C.NC)} Fase {number}: {title}")

def phase_ok(msg: str) -> None:
    say(f"  {_c(C.GREEN)}[ok]{_c(C.NC)} {msg}")

def phase_fail(msg: str) -> None:
    say(f"  {_c(C.RED)}[fail]{_c(C.NC)} {msg}")

def warn(msg: str) -> None:
    say(f"  {_c(C.YELLOW)}[!]{_c(C.NC)} {msg}")


# --------------------------------------------------------------------------
# i18n
# --------------------------------------------------------------------------

def clear_screen() -> None:
    # Only worth doing on a real terminal; piping the menu somewhere would
    # otherwise fill the log with raw escape sequences.
    if not is_interactive():
        return
    os.system("cls" if IS_WINDOWS else "clear")


# --------------------------------------------------------------------------
# phase runner
# --------------------------------------------------------------------------
