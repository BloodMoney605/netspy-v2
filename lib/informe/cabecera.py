"""Cabecera y resumen."""

from __future__ import annotations


def seccion(sep: str, domain: str, timestamp: str, resumen: dict) -> list[str]:
    out: list[str] = []
    out.append(sep)
    out.append("  REPORTE DE NETSPY")
    out.append(sep)
    out.append("")
    out.append(f"  Objetivo:   {domain}")
    out.append(f"  Hecho:      {timestamp}")
    out.append("")
    out.append(sep)
    out.append("  RESUMEN")
    out.append(sep)
    out.append("")
    out.append(f"  Critico:    {resumen.get('critical', 0)}")
    out.append(f"  Alto:       {resumen.get('high', 0)}")
    out.append(f"  Medio:      {resumen.get('medium', 0)}")
    out.append(f"  Bajo:       {resumen.get('low', 0)}")
    out.append(f"  Info:       {resumen.get('info', 0)}")
    out.append(f"  Total:      {resumen.get('total', 0)}")

    return out
