"""Definicion de la linea de comandos."""

from __future__ import annotations

import argparse

from version import VERSION


HELP_EPILOG = """\
Variables de entorno:
  NETSPY_CONFIG        config a usar
  NETSPY_HOME          mueve el directorio de datos
  NETSPY_LANG=es       salida en espanol
  NETSPY_STEALTH=0|1|2  nivel de sigilo
  NETSPY_VERBOSE=1     salida verbosa
  NETSPY_DEBUG=1       muestra tambien los errores que se suelen callar
  NO_COLOR             saca los colores

Ejemplos:
  netspy audit --domain ejemplo.com
  netspy recon --domain ejemplo.com --threads 50
  netspy portscan --target 192.168.1.0/24 --output ./resultados
  netspy report --dir ./output/ejemplo.com
"""

class Ayuda(argparse.ArgumentParser):
    """Traduce los rotulos que argparse escribe en ingles."""

    def format_help(self):
        texto = super().format_help()
        for ingles, espanol in [
            ("usage:", "uso:"),
            ("positional arguments:", "comandos:"),
            ("optional arguments:", "opciones:"),
            ("options:", "opciones:"),
            ("show this help message and exit", "muestra esta ayuda y sale"),
            ("show program's version number and exit", "muestra la version y sale"),
        ]:
            texto = texto.replace(ingles, espanol)
        return texto

    def error(self, mensaje):
        self.print_usage()
        print(f"\nerror: {mensaje}")
        self.exit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = Ayuda(
        prog="netspy",
        description="NetSpy: reconocimiento y busqueda de vulnerabilidades",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"NetSpy v{VERSION}")

    sub = parser.add_subparsers(dest="command")

    def add_target_args(p, domain_flag="--domain", target_flag="--target"):
        p.add_argument(domain_flag, help="dominio objetivo (ej: ejemplo.com)")
        p.add_argument(target_flag, help="IP o rango CIDR")
        p.add_argument("--config", help="otro archivo de configuracion")
        p.add_argument("--output", help="carpeta de salida")
        p.add_argument("--threads", type=int, help="cantidad de hilos")

    add_target_args(sub.add_parser("audit", help="pipeline completo (fases 1-5)"))
    add_target_args(sub.add_parser("scan", help="dominio completo (fases 1-4, sin reporte)"))
    add_target_args(sub.add_parser("recon", help="fase 1: solo subdominios y DNS"))
    add_target_args(sub.add_parser("portscan", help="fase 2: solo escaneo de puertos"))

    rp = sub.add_parser("report", help="arma el reporte de datos existentes")
    rp.add_argument("--dir", required=True, help="carpeta con datos previos")
    rp.add_argument("--config", help="otro archivo de configuracion")

    sub.add_parser("doctor", help="revisa e instala lo que falte")
    sub.add_parser("selfcheck", help="diagnostica la maquina")
    sub.add_parser("clean", help="borra la cache y los temporales")
    sub.add_parser("license", help="muestra la licencia")
    sub.add_parser("version", help="muestra la version")
    sub.add_parser("help", help="muestra esta ayuda")
    return parser
