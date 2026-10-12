"""Tecnologias y versiones."""

from __future__ import annotations


def seccion(tech: dict, sep: str) -> list[str]:
    out: list[str] = []
    out.append("")
    out.append(sep)
    out.append("  FASE 3: FINGERPRINT")
    out.append(sep)

    alive = tech.get("alive_hosts", [])
    if alive:
        out.append("")
        out.append(f"  Hosts web activos ({len(alive)}):")
        out.append("")
        out.append(f"  {'URL':<50s} {'Status':<7s} {'Title':<40s} {'Server'}")
        out.append("  " + "-" * 120)
        for host_entry in alive[:50]:
            url = host_entry.get("url", "")[:50]
            status = str(host_entry.get("status", "?"))
            title = (host_entry.get("title", "") or "")[:40]
            server = host_entry.get("server", "")
            out.append(f"  {url:<50s} {status:<7s} {title:<40s} {server}")
        if len(alive) > 50:
            out.append(f"  ... y {len(alive) - 50} more")

    techs = tech.get("technologies", [])
    if techs:
        out.append("")
        out.append(f"  Tecnologias ({len(techs)}):")
        out.append("  " + "-" * 50)
        for tech_entry in techs:
            name = tech_entry.get("name", "")
            ver = tech_entry.get("version", "")
            if ver:
                out.append(f"    {name}  {ver}")
            else:
                out.append(f"    {name}")

    versions = tech.get("versions", [])
    if versions:
        out.append("")
        out.append(f"  Cadenas de version ({len(versions)}):")
        out.append("")
        out.append(f"  {'Producto':<25s} {'Version':<12s} {'Origen'}")
        out.append("  " + "-" * 80)
        for ver_entry in versions:
            prod = ver_entry.get("product", "")[:25]
            ver = ver_entry.get("version", "")
            src = ver_entry.get("source", "")
            out.append(f"  {prod:<25s} {ver:<12s} {src}")

    return out
