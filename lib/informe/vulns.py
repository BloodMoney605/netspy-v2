"""Hallazgos por severidad."""

from __future__ import annotations


def seccion(findings: list, sep: str) -> list[str]:
    out: list[str] = []
    out.append("")
    out.append(sep)
    out.append(f"  FASE 4: VULNERABILIDADES ({len(findings)})")
    out.append(sep)

    for finding_entry in findings:
        sev = finding_entry.get("severity", "UNKNOWN").upper()
        fid = finding_entry.get("id", finding_entry.get("name", "?"))
        prod = finding_entry.get("product", "")
        ver = finding_entry.get("version", "")
        detail = (finding_entry.get("summary", "") or finding_entry.get("detail", "") or "")[:120]

        label = f"{prod} {ver}".strip() if prod else ""
        # NVD no siempre dice que versiones afectan: se marca en vez
        # de presentarlo como confirmado.
        unverified = (
            finding_entry.get("type") == "cve"
            and finding_entry.get("version_verified") is False
        )
        marker = "  (? UNVERIFIED)" if unverified else ""

        out.append("")
        if sev == "CRITICAL":
            out.append(f"  [CRIT] {fid}{marker}")
        elif sev == "HIGH":
            out.append(f"  [HIGH] {fid}{marker}")
        elif sev == "MEDIUM":
            out.append(f"  [MED ] {fid}{marker}")
        elif sev == "LOW":
            out.append(f"  [LOW ] {fid}{marker}")
        else:
            out.append(f"  [INFO] {fid}{marker}")
        if label:
            out.append(f"         {label}")
        if detail:
            out.append(f"         {detail}")

    out.append("")
    out.append(sep)
    out.append("  Hecho con NetSpy")
    out.append(sep)

    return out
