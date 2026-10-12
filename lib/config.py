"""Resolucion de la configuracion activa."""

from __future__ import annotations

import os

from netspy_env import ROOT, config_path

__all__ = ["config_path", "cargar", "ruta_activa"]


def ruta_activa() -> str:
    """La configuracion que se usa en esta corrida."""
    return str(config_path())


def cargar(ruta: str | None = None) -> dict:
    """Carga el YAML. Si falta PyYAML avisa en vez de fallar callado."""
    destino = ruta or ruta_activa()

    try:
        import yaml
    except ImportError:
        print(
            "Falta PyYAML. Instalalo con:\n"
            "    python -m pip install pyyaml\n"
            "    (o: netspy doctor)",
            file=os.sys.stderr,
        )
        return {}

    if not os.path.exists(destino):
        por_defecto = ROOT / "config" / "default.yaml"
        if por_defecto.exists():
            destino = str(por_defecto)

    try:
        with open(destino, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except OSError as exc:
        print(f"No se pudo leer {destino}: {exc}", file=os.sys.stderr)
        return {}
    except Exception as exc:
        print(f"YAML invalido en {destino}: {exc}", file=os.sys.stderr)
        return {}
