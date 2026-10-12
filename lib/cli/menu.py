"""Menu interactivo."""

from __future__ import annotations

import os

from cli.comandos import cmd_audit, cmd_clean, cmd_doctor, cmd_license, cmd_report, cmd_recon, cmd_scan, cmd_scan_full, cmd_selfcheck
from cli.idioma import tr
from cli.salida import C, _c, clear_screen, say, warn
from netspy_env import IS_WINDOWS, is_interactive
from cli.sigilo import apply_stealth, cleanup_stealth, spoof_mac
from config import config_path


BANNER = r"""
 ___      ___                  ____
 `MM\     `M'                 6MMMMb\
  MMM\     M           /     6M'    `
  M\MM\    M   ____   /M     MM      __ ____  ____    ___
  M \MM\   M  6MMMMb /MMMMM  YM.     `M6MMMMb `MM(    )M'
  M  \MM\  M 6M'  `Mb MM      YMMMMb  MM'  `Mb `Mb    d'
  M   \MM\ M MM    MM MM          `Mb MM    MM   YM.  ,P
  M    \MM\M MMMMMMMM MM           MM MM    MM   MM  M
  M     \MMM MM       MM           MM MM    MM   `Mbd'
  M      \MM YM    d9 YM.  , L    ,M9 MM.  ,M9    YMP
 _M_      \M  YMMMM9   YMMM9 MYMMMM9  MMYMMM9      M
"""


def show_banner() -> None:
    say(f"{_c(C.BOLD)}{BANNER}{_c(C.NC)}")
    say(f"  {_c(C.DIM)}Creator: BloodMoney605{_c(C.NC)}")
    say()

# --------------------------------------------------------------------------
# phase runner
# --------------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    try:
        value = input(prompt).strip()
    except EOFError:
        return default
    return value or default

def show_stealth_menu() -> bool:
    say(f"\n  {_c(C.BOLD)}{tr('stealth_title')}{_c(C.NC)}")
    say(f"  {_c(C.DIM)}{tr('stealth_sub')}{_c(C.NC)}")
    for i, key in enumerate(("s1", "s2", "s3", "s4"), start=1):
        say(f"    {_c(C.YELLOW)}{i}{_c(C.NC)}) {tr(key)}")
    choice = _ask(f"\n  {_c(C.BOLD)}{tr('choice')}{_c(C.NC)} [1-4]: ")
    apply_stealth(choice)
    return True

def interactive_menu() -> int:
    cfg = str(config_path())

    while True:
        global STEALTH_DESC
        STEALTH_DESC = "none"

        show_stealth_menu()

        while True:
            clear_screen()
            show_banner()
            say(f"  {_c(C.BOLD)}{tr('main_title')}{_c(C.NC)}")
            for i, key in enumerate(("opt_1", "opt_2", "opt_3", "opt_4", "opt_5", "opt_6", "opt_7"), start=1):
                say(f"    {_c(C.YELLOW)}{i}{_c(C.NC)}) {tr(key)}")
            say(f"    {_c(C.YELLOW)}q{_c(C.NC)}) {tr('opt_q')}")
            desc = tr("none") if STEALTH_DESC == "none" else STEALTH_DESC
            say(f"\n  {_c(C.DIM)}{tr('stealth')}: {desc}{_c(C.NC)}")

            choice = _ask(f"\n  {_c(C.BOLD)}{tr('choice')}{_c(C.NC)} [1-7]: ")
            if choice.lower() == "q":
                say(f"\n{_c(C.DIM)}{tr('byes')}{_c(C.NC)}")
                return 0
            if choice not in ("1", "2", "3", "4", "5", "6", "7"):
                continue

            if choice in ("1", "2", "3", "4", "5") and STEALTH_DESC.startswith("MAC spoof"):
                spoof_mac()

            try:
                if choice == "6":
                    cmd_doctor()
                elif choice == "7":
                    cmd_license()
                elif choice == "5":
                    directory = _ask(f"  {_c(C.BOLD)}{tr('directory')}{_c(C.NC)}: ")
                    if directory:
                        say(f"\n  {_c(C.CYAN)}{tr('running')}{_c(C.NC)}")
                        cmd_report(directory, cfg)
                elif choice == "4":
                    target = _ask(f"  {_c(C.BOLD)}{tr('target')}{_c(C.NC)}: ")
                    threads = _ask(f"  {_c(C.BOLD)}{tr('threads')}{_c(C.NC)} (enter=default): ")
                    if not target:
                        continue
                    say(f"\n  {_c(C.CYAN)}{tr('running')}{_c(C.NC)}")
                    cmd_scan(target, cfg, None, threads or None)
                else:
                    domain = _ask(f"  {_c(C.BOLD)}{tr('domain')}{_c(C.NC)}: ")
                    if not domain:
                        continue
                    threads = _ask(f"  {_c(C.BOLD)}{tr('threads')}{_c(C.NC)} (enter=default): ")
                    say(f"\n  {_c(C.CYAN)}{tr('running')}{_c(C.NC)}")
                    if choice == "1":
                        cmd_audit(domain, cfg, None, threads or None)
                    elif choice == "2":
                        cmd_scan_full(domain, cfg, None, threads or None)
                    elif choice == "3":
                        cmd_recon(domain, cfg, None, threads or None)
            except KeyboardInterrupt:
                say("")
                warn("interrumpido")
                continue

            _ask(f"\n  {_c(C.DIM)}{tr('back')}{_c(C.NC)} ")


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------
