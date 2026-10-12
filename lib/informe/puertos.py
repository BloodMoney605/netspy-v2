"""Puertos abiertos y servicios."""

from __future__ import annotations


def seccion(scan: dict, sep: str) -> list[str]:
    out: list[str] = []
    out.append("")
    out.append(sep)
    out.append("  FASE 2: ESCANEO DE PUERTOS")
    out.append(sep)

    total = scan.get("total_open_ports", 0)
    hosts = len(scan.get("hosts", []))
    out.append("")
    out.append(f"  Puertos abiertos: {total}  |  Hosts: {hosts}")
    out.append("")

    services = scan.get("services", [])
    out.append(f"  {'IP':<18s} {'Puerto':<7s} {'Proto':<6s} {'Servicio':<14s} {'Producto':<20s} {'Version'}")
    out.append("  " + "-" * 95)
    for svc_entry in services[:100]:
        ip = svc_entry.get("ip", "")
        port = str(svc_entry.get("port", ""))
        proto = svc_entry.get("protocol", "")
        svc = svc_entry.get("service", "")
        prod = svc_entry.get("product", "")
        ver = svc_entry.get("version", "")
        out.append(f"  {ip:<18s} {port:<7s} {proto:<6s} {svc:<14s} {prod:<20s} {ver}")
    if len(services) > 100:
        out.append(f"  ... y {len(services) - 100} more")

    return out
