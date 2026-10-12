#!/usr/bin/env python3
"""NetSpy: punto de entrada.

Solo arma el parser y despacha. La logica vive en lib/cli/, las fases en
lib/*.py y el matching de CVEs en lib/cve/.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

from cli.args import build_parser  # noqa: E402
from cli.comandos import (  # noqa: E402
    cmd_audit,
    cmd_clean,
    cmd_doctor,
    cmd_license,
    cmd_recon,
    cmd_report,
    cmd_scan,
    cmd_scan_full,
    cmd_selfcheck,
)
from cli.menu import interactive_menu  # noqa: E402
from cli.salida import C, phase_fail, say, warn  # noqa: E402
from cli.sigilo import cleanup_stealth  # noqa: E402
from config import ruta_activa  # noqa: E402
from netspy_env import colors_enabled, enable_virtual_terminal, utf8_output  # noqa: E402
from version import VERSION  # noqa: E402


def despachar(args) -> int:
    cfg = getattr(args, "config", None) or ruta_activa()
    salida = getattr(args, "output", None)
    hilos = getattr(args, "threads", None)
    objetivo = getattr(args, "domain", None) or getattr(args, "target", None)

    if args.command == "audit":
        if not objetivo:
            phase_fail("falta --domain")
            return 1
        return cmd_audit(objetivo, cfg, salida, hilos)

    if args.command == "scan":
        if not objetivo:
            phase_fail("falta --domain")
            return 1
        return cmd_scan_full(objetivo, cfg, salida, hilos)

    if args.command == "recon":
        if not objetivo:
            phase_fail("falta --domain")
            return 1
        return cmd_recon(objetivo, cfg, salida, hilos)

    if args.command == "portscan":
        if not objetivo:
            phase_fail("falta --target")
            return 1
        return cmd_scan(objetivo, cfg, salida, hilos)

    if args.command == "report":
        return cmd_report(args.dir, cfg)

    if args.command == "doctor":
        return cmd_doctor()

    if args.command == "selfcheck":
        return cmd_selfcheck()

    if args.command == "clean":
        return cmd_clean()

    if args.command == "license":
        return cmd_license()

    if args.command == "version":
        say(f"NetSpy v{VERSION}")
        return 0

    if args.command == "help":
        build_parser().print_help()
        return 0

    # sin subcomando: menu interactivo
    return interactive_menu()


def main(argv: list[str] | None = None) -> int:
    # Si la consola no soporta ANSI, se apagan los colores: si no, las
    # secuencias de escape se imprimen literalmente.
    if not enable_virtual_terminal() or not colors_enabled():
        C.off()

    utf8_output()

    args = build_parser().parse_args(argv)

    try:
        return despachar(args)
    except KeyboardInterrupt:
        say("")
        warn("interrumpido")
        return 130
    finally:
        cleanup_stealth()


if __name__ == "__main__":
    sys.exit(main())