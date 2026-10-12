"""Subdominios, IPs, DNS y WHOIS."""

from __future__ import annotations


def seccion(recon: dict, sep: str) -> list[str]:
    out: list[str] = []
    out.append("")
    out.append(sep)
    out.append("  FASE 1: RECONOCIMIENTO")
    out.append(sep)

    subs = recon.get("subdomains", [])
    out.append("")
    out.append(f"  Subdominios ({len(subs)}):")
    out.append("  " + "-" * 50)
    for sub in subs[:50]:
        out.append(f"    {sub}")
    if len(subs) > 50:
        out.append(f"    ... y {len(subs) - 50} more")

    ips = recon.get("ips", [])
    out.append("")
    out.append(f"  Direcciones IP ({len(ips)}):")
    out.append("  " + "-" * 50)
    for ip in ips[:20]:
        out.append(f"    {ip}")
    if len(ips) > 20:
        out.append(f"    ... y {len(ips) - 20} more")

    dns = recon.get("dns", {})
    if dns:
        out.append("")
        out.append("  Registros DNS:")
        out.append("  " + "-" * 50)
        for rtype, values in dns.items():
            val_str = ", ".join(values[:5])
            out.append(f"    {rtype.upper():6s}  {val_str}")

    whois = recon.get("whois", {})
    if whois:
        out.append("")
        out.append("  WHOIS:")
        out.append("  " + "-" * 50)
        for key, val in whois.items():
            if key != "raw":
                label = key.replace("_", " ").title()
                out.append(f"    {label:20s}  {val}")

    return out
