"""Fase 4: vulnerabilidades.

Orquesta las comprobaciones y arma findings.json. La logica de CVEs vive en
el paquete cve/ y las comprobaciones en checks/.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from checks.misconfig import check_misconfigs
from checks.nuclei import advertencias as avisos_nuclei, run_nuclei
from checks.ssl import ssl_audit
from common import apply_thread_override, t
from config import cargar as load_config
from cve import match_cves
from cve.nvd import con_api_key, init_cve_db
from netspy_env import expand_config_path, tmp_dir

BOLD = "\033[1m"
ORDEN_SEVERIDAD = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
YELLOW = "\033[0;33m"
DIM = "\033[2m"
NC = "\033[0m"


def run_vuln(input_dir: str, config: dict, output: str) -> dict[str, Any]:
    all_findings: list[dict[str, Any]] = []

    tech_path = os.path.join(input_dir, "tech.json")
    ports_path = os.path.join(input_dir, "ports.json")

    tech_data: dict = {}
    ports_data: dict = {}

    if os.path.exists(tech_path):
        with open(tech_path, encoding="utf-8", errors="replace") as tech_file:
            try:
                tech_data = json.load(tech_file)
            except Exception:
                pass

    if os.path.exists(ports_path):
        with open(ports_path, encoding="utf-8", errors="replace") as ports_file:
            try:
                ports_data = json.load(ports_file)
            except Exception:
                pass

    versions = tech_data.get("versions", [])

    print(f"  {t('products_versions')}: {len(versions)}")
    print(f"  {t('alive_hosts')}:        {tech_data.get('alive_count', 0)}")
    print()

    if versions:
        print(f"  [CVE matching] {t('cve_matching_query')}...")
        configured = config.get("vuln", {}).get("cve_db_path") or "${NETSPY_HOME}/cve.db"
        db_path = str(expand_config_path(configured))
        db = init_cve_db(db_path)

        # Windows no deja borrar un archivo con un handle abierto:
        # sin cerrar, netspy clean falla.
        try:
            cve_findings = match_cves(versions, db)
            all_findings.extend(cve_findings)

            for finding_entry in cve_findings:
                try:
                    db.execute(
                        "INSERT OR REPLACE INTO cve_index (id, product, version_range, severity, summary) VALUES (?, ?, ?, ?, ?)",
                        (finding_entry["id"], finding_entry["product"], finding_entry["version"], finding_entry["severity"], finding_entry["summary"]),
                    )
                except Exception:
                    pass
            db.commit()
        finally:
            try:
                db.close()
            except Exception:
                pass

    print()

    print(f"  [misconfig] {t('misconfig_checking')}...")
    misconfig_findings = check_misconfigs(tech_data)
    all_findings.extend(misconfig_findings)
    print(f"    {len(misconfig_findings)} {t('misconfig_found')}")
    print()

    services = ports_data.get("services", [])
    ssl_targets = [f"{svc['ip']}:{svc['port']}" for svc in services
                   if svc.get("port") in (443, 8443, 993, 465, 995)]
    if ssl_targets:
        print(f"  [ssl audit] {t('ssl_checking')} ({len(ssl_targets)})...")
        ssl_findings = ssl_audit(ssl_targets)
        all_findings.extend(ssl_findings)
        print(f"    {len(ssl_findings)} {t('ssl_findings')}")
    print()

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}

    for finding_entry in all_findings:
        sev = finding_entry.get("severity", "UNKNOWN")
        if isinstance(sev, list):
            sev = sev[0] if sev else "UNKNOWN"
        if not isinstance(sev, str):
            sev = "UNKNOWN"
        finding_entry["severity"] = sev.upper()

    # severity_min descarta lo mas bajo. Va antes del resumen para que lo que
    # se imprime y lo que se guarda sean lo mismo.
    minimo = (config.get("vuln", {}).get("severity_min") or "medium").upper()
    if minimo in ORDEN_SEVERIDAD:
        limite = ORDEN_SEVERIDAD[minimo]
        all_findings = [
            fe for fe in all_findings
            if ORDEN_SEVERIDAD.get(fe.get("severity", "INFO").upper(), 99) >= limite
        ]

    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "UNKNOWN"), 99))

    by_severity: dict[str, int] = {}
    for finding_entry in all_findings:
        sev = finding_entry.get("severity", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    result: dict[str, Any] = {
        "summary": {
            "total_findings": len(all_findings),
            "critical": by_severity.get("CRITICAL", 0),
            "high": by_severity.get("HIGH", 0),
            "medium": by_severity.get("MEDIUM", 0),
            "low": by_severity.get("LOW", 0),
            "info": by_severity.get("INFO", 0),
        },
        "findings": all_findings,
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    findings_path = os.path.join(output, "findings.json")

    with open(findings_path, "w", encoding="utf-8") as findings_file:
        json.dump(result, findings_file, indent=2, default=str)

    if config.get("vuln", {}).get("enable_nuclei", False):
        urls_path = os.path.join(input_dir, "urls.txt")
        for aviso in avisos_nuclei():
            print(f"    {YELLOW}[!]{NC} {aviso}")
        if os.path.exists(urls_path) and os.path.getsize(urls_path) > 0:
            print(f"  [nuclei] {t('nuclei_running')}...")
            nuclei_findings = run_nuclei(
                urls_path,
                templates_path=config.get("vuln", {}).get("nuclei_templates"),
                severity_min=config.get("vuln", {}).get("severity_min", "medium"),
            )
            print(f"    {len(nuclei_findings)} {t('nuclei_findings')}")

            if nuclei_findings:
                for nuclei_entry in nuclei_findings:
                    all_findings.append({
                        "type": "nuclei",
                        "id": nuclei_entry.get("template-id", ""),
                        "name": nuclei_entry.get("info", {}).get("name", ""),
                        "severity": nuclei_entry.get("info", {}).get("severity", "UNKNOWN"),
                        "url": nuclei_entry.get("matched-at", ""),
                        "detail": nuclei_entry.get("info", {}).get("description", ""),
                        "source": "nuclei",
                    })

                result["findings"] = all_findings
                result["summary"]["total_findings"] = len(all_findings)
                for severity_label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    result["summary"][severity_label.lower()] = sum(1 for fe in all_findings if fe.get("severity") == severity_label)
                with open(findings_path, "w", encoding="utf-8") as findings_file:
                    json.dump(result, findings_file, indent=2, default=str)

    SEV_COLORS = {
        "CRITICAL": "\033[1;31m",
        "HIGH":     "\033[0;31m",
        "MEDIUM":   "\033[0;33m",
        "LOW":      "\033[0;36m",
        "INFO":     "\033[0;37m",
    }
    NC = "\033[0m"

    print()
    print(f"  {BOLD}{t('vuln_summary_title')}{NC}")
    print(f"  {BOLD}{'─' * 40}{NC}")
    print(f"  {t('total')}:    {BOLD}{result['summary']['total_findings']}{NC}")
    summary_data = result['summary']
    if summary_data['critical']:
        print(f"  {SEV_COLORS['CRITICAL']}{t('critical')}: {summary_data['critical']}{NC}")
    if summary_data['high']:
        print(f"  {SEV_COLORS['HIGH']}{t('high')}:     {summary_data['high']}{NC}")
    if summary_data['medium']:
        print(f"  {SEV_COLORS['MEDIUM']}{t('medium')}:   {summary_data['medium']}{NC}")
    if summary_data['low']:
        print(f"  {SEV_COLORS['LOW']}{t('low')}:      {summary_data['low']}{NC}")
    if summary_data['info']:
        print(f"  {SEV_COLORS['INFO']}{t('info')}:     {summary_data['info']}{NC}")
    print()

    if all_findings:
        print(f"  {BOLD}{t('findings_title')}{NC}")
        print(f"  {BOLD}{'─' * 60}{NC}")
        for finding_entry in all_findings:
            sev = finding_entry.get("severity", "?")
            fid = finding_entry.get("id", finding_entry.get("name", "?"))
            prod = finding_entry.get("product", "")
            ver = finding_entry.get("version", "")
            detail = (finding_entry.get("summary") or finding_entry.get("detail", ""))[:100]
            color = SEV_COLORS.get(sev, "")
            badge = f"{color}[{sev}]{NC}"
            # Flag CVEs whose affected version could not be confirmed, so they
            # are not read as established vulnerabilities.
            unverified = (
                finding_entry.get("type") == "cve"
                and finding_entry.get("version_verified") is False
            )
            suffix = f" {YELLOW}(? unverified){NC}" if unverified else ""
            if prod and ver:
                print(f"  {badge} {fid}{suffix} | {prod} {ver}")
            else:
                print(f"  {badge} {fid}{suffix}")
            if detail:
                print(f"         {DIM}{detail}{NC}")
        if len(all_findings) > 20:
            print(f"  {DIM}{t('and_more').format(len(all_findings) - 20)}{NC}")


    print(f"\n  {t('output')}: {findings_path}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Fase 4: busqueda de vulnerabilidades")
    parser.add_argument("--input", required=True, help="carpeta con los datos de la fase 3")
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    config = apply_thread_override(config, args.threads)
    os.makedirs(args.output, exist_ok=True)

    try:
        run_vuln(args.input, config, args.output)
    except KeyboardInterrupt:
        print("\n  [!] interrumpido")
        sys.exit(130)

if __name__ == "__main__":
    main()
