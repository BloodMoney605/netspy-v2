"""Escaneo con plantillas de nuclei.

nuclei es opcional y come memoria: solo corre si vuln.enable_nuclei esta en
true. Las plantillas se descargan aparte con 'nuclei -update-templates'.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from common import t
from netspy_env import expand_config_path, have, run, tmp_dir

BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"

# Nuclei corre en paralelo y levanta varios workers: con poca RAM conviene
# bajar el limite.
RIESGO_MEMORIA = 2 * 1024 * 1024 * 1024


def _memoria_libre() -> int | None:
    """Bytes disponibles. None si la plataforma no lo dice."""
    try:
        import os as _os

        return _os.sysconf("SC_AVPHYS_PAGES") * _os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        pass
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def advertencias(memory: bool = True) -> list[str]:
    """Avisos antes de escanear con nuclei."""
    avisos: list[str] = []
    if not have("nuclei"):
        avisos.append("nuclei no esta instalado (go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)")
        return avisos

    if memory:
        libre = _memoria_libre()
        if libre is not None and libre < RIESGO_MEMORIA:
            avisos.append(
                f"quedan {libre // (1024 * 1024)}MB de RAM; nuclei puede quedar sin memoria"
            )
    return avisos


def run_nuclei(
    targets_file: str,
    templates_path: str | None = None,
    severity_min: str = "medium",
    timeout: int = 600,
) -> list[dict[str, Any]]:
    if not os.path.exists(targets_file):
        return []

    if not have("nuclei"):
        print(f"    {t('nuclei_not_found_short')}")
        return []

    destino = str(tmp_dir())
    output_file = os.path.join(destino, f"nuclei_{int(time.time())}.jsonl")

    cmd = [
        "nuclei",
        "-l", targets_file,
        "-j",
        "-silent",
        "-s", severity_min,
        "-rl", "20",
        "-c", "3",
        "-timeout", "5",
        "-retries", "1",
        "-jle", output_file,
    ]

    if templates_path:
        plantillas = expand_config_path(templates_path)
        if plantillas.exists():
            cmd.extend(["-templates", str(plantillas)])
        else:
            print(f"    {DIM}plantillas no encontradas en {plantillas}; se usan las de nuclei{NC}")

    print(f"    {t('nuclei_scanning')}...", end=" ", flush=True)
    resultado = run(cmd, timeout=timeout)

    if resultado is None:
        print(t("nuclei_timeout"))
        return []

    print(t("nuclei_done"))

    hallazgos: list[dict[str, Any]] = []
    if os.path.exists(output_file):
        with open(output_file, encoding="utf-8", errors="replace") as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    hallazgos.append(json.loads(linea))
                except json.JSONDecodeError:
                    continue
        try:
            os.remove(output_file)
        except OSError:
            pass

    return hallazgos
