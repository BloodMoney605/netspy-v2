from __future__ import annotations
import os
import random
import sys
import time
from typing import Any


_LANG = os.environ.get("NETSPY_LANG", "en")
_STEALTH_LEVEL = int(os.environ.get("NETSPY_STEALTH", "0"))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
]


def get_stealth_ua() -> str:
    if _STEALTH_LEVEL >= 2:
        return random.choice(USER_AGENTS)
    return "Mozilla/5.0"


def get_stealth_delay() -> float:
    if _STEALTH_LEVEL == 1:
        return random.uniform(1.0, 3.0)
    if _STEALTH_LEVEL == 2:
        return random.uniform(0.5, 2.0)
    return 0.0


def stealth_sleep():
    delay = get_stealth_delay()
    if delay > 0:
        time.sleep(delay)

STRINGS = {
    "es": {
        "domain": "dominio",
        "subdomain_sources": "fuentes de subdominios",
        "enumerating_subdomains": "enumerando subdominios",
        "found": "encontrados",
        "crtsh_failed": "[!] crt.sh fallo o devolvio vacio, usando wordlist...",
        "wordlist_brute": "fuerza bruta con wordlist",
        "resolving": "resolviendo subdominios",
        "alive": "vivos",
        "whois_lookup": "busqueda whois",
        "done": "listo",
        "recon_summary": "Resumen de Recon",
        "subdomains": "Subdominios",
        "resolved": "Resueltos",
        "unique_ips": "IPs unicas",
        "top_ips": "Top IPs",
        "more": "y {} mas",
        "recon_saved": "datos de recon guardados en",
        "targets": "objetivos",
        "ports_to_check": "puertos a verificar",
        "custom_scan": "escaneo TCP connect",
        "nmap_scan": "escaneo completo de puertos y servicios",
        "nmap_version": "deteccion de versiones con nmap",
        "services_detected": "Servicios detectados",
        "scan_saved": "datos de escaneo guardados en",
        "urls_to_probe": "URLs a sondear",
        "httpx_probing": "sondeo con httpx",
        "whatweb_scan": "escaneo profundo con whatweb",
        "scanned": "escaneados",
        "tech_found": "Tecnologias encontradas",
        "version_strings": "Versiones detectadas",
        "fingerprint_saved": "datos de fingerprint guardados en",
        "products_versions": "productos con versiones",
        "alive_hosts": "hosts web activos",
        "cve_matching": "busqueda de CVEs en bases de datos",
        "cve_rate_limited": "NVD limito las peticiones: algunos CVEs pudieron quedar fuera (reintentá en unos minutos)",
        "unique_versions": "entradas de versiones unicas",
        "cached": "en cache",
        "misconfig_check": "verificando configuraciones comunes",
        "misconfig_found": "configuraciones incorrectas encontradas",
        "ssl_audit": "verificando endpoints SSL",
        "ssl_findings": "hallazgos SSL",
        "vuln_summary": "Resumen de Vulnerabilidades",
        "total": "Total",
        "findings": "Hallazgos",
        "vuln_saved": "datos de vulnerabilidades guardados en",
        "report_saved": "reporte guardado en",
        "audit_complete": "Auditoria completa",
        "scan_complete": "Escaneo completo",
        "report": "Reporte",
        "data": "Datos",
        "output_files": "archivos de salida",
        "phase": "Fase",
        "output": "salida",
        "no_urls_fingerprint": "[!] no hay URLs para fingerprinting",
        "httpx_not_found": "[!] httpx no encontrado. instalar: go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "httpx_probing_dots": "sondeo con httpx",
        "whatweb_deep_scan": "escaneo profundo con whatweb",
        "products_with_versions": "productos con versiones",
        "alive_web_hosts": "hosts web activos",
        "cve_matching_query": "buscando CVEs en bases de datos",
        "unique_version_entries": "entradas de versiones unicas",
        "cves_cached": "CVEs (en cache)",
        "misconfig_checking": "verificando configuraciones comunes",
        "misconfig_found_count": "configuraciones incorrectas encontradas",
        "ssl_checking": "verificando endpoints SSL",
        "ssl_findings_count": "hallazgos SSL",
        "vuln_summary_title": "Resumen de Vulnerabilidades",
        "critical": "Critico",
        "high": "Alto",
        "medium": "Medio",
        "low": "Bajo",
        "info": "Info",
        "findings_title": "Hallazgos",
        "and_more": "... y {} mas",
        "nuclei_not_found": "[!] nuclei no encontrado. instalar: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "nuclei_running": "ejecutando templates de vulnerabilidades",
        "nuclei_findings": "hallazgos de nuclei",
        "nuclei_scanning": "escaneando (timeout 120s)",
        "nuclei_done": "listo",
        "nuclei_timeout": "timeout (120s)",
        "nuclei_not_found_short": "no encontrado",
        "nuclei_error": "error",
        "from": "de",
        "subdomain_sources_detail": "crt.sh + alienvault + wayback + wordlist",
        "cve_timeout_phase": "[!] timeout de fase CVE (5 min), se omiten productos restantes",
        "recon_phase_progress": "reconocimiento",
    },
}

DEFAULT = {
    "cve_rate_limited": "NVD limito las peticiones: puede que falten CVEs (reintenta en unos minutos)",
    "domain": "domain",
    "subdomain_sources": "subdomain sources",
    "enumerating_subdomains": "enumerating subdomains",
    "found": "found",
    "crtsh_failed": "[!] crt.sh fallo o vino vacio, se usa la wordlist...",
    "wordlist_brute": "wordlist brute-force",
    "resolving": "resolving subdomains",
    "alive": "alive",
    "whois_lookup": "whois lookup",
    "done": "done",
    "recon_summary": "Resumen del recon",
    "subdomains": "Subdominios",
    "resolved": "Resueltos",
    "unique_ips": "IPs unicas",
    "top_ips": "Top IPs",
    "more": "y {} mas",
    "recon_saved": "datos de recon guardados en",
    "targets": "targets",
    "ports_to_check": "puertos a verificar",
    "custom_scan": "escaneo TCP connect",
    "nmap_scan": "escaneo completo con nmap",
    "nmap_version": "deteccion de versiones con nmap",
    "services_detected": "Servicios detectados",
    "scan_saved": "datos de escaneo guardados en",
    "urls_to_probe": "URLs to probe",
    "httpx_probing": "sondeando con httpx",
    "whatweb_scan": "escaneo profundo con whatweb",
    "scanned": "scanned",
    "tech_found": "Tecnologias encontradas",
    "version_strings": "Cadenas de version",
    "fingerprint_saved": "datos de fingerprint guardados en",
    "products_versions": "productos con versiones",
    "alive_hosts": "hosts web activos",
    "cve_matching": "querying vulnerability databases",
    "unique_versions": "entradas de versiones unicas",
    "cached": "cached",
    "misconfig_check": "revisando problemas comunes",
    "misconfig_found": "misconfiguraciones encontradas",
    "ssl_audit": "revisando endpoints SSL",
    "ssl_findings": "hallazgos SSL",
    "vuln_summary": "Resumen de vulnerabilidades",
    "total": "Total",
    "findings": "Hallazgos",
    "vuln_saved": "datos de vulnerabilidades guardados en",
    "report_saved": "reporte guardado en",
    "audit_complete": "Auditoria terminada",
    "scan_complete": "Escaneo completo",
    "report": "Reporte",
    "data": "Datos",
    "output_files": "archivos de salida",
    "phase": "Fase",
    "output": "salida",
    "no_urls_fingerprint": "[!] no hay URLs para analizar",
    "httpx_not_found": "[!] httpx no esta. instalar: go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "httpx_probing_dots": "sondeando con httpx",
    "whatweb_deep_scan": "escaneo profundo con whatweb",
    "products_with_versions": "productos con versiones",
    "alive_web_hosts": "hosts web activos",
    "cve_matching_query": "consultando bases de vulnerabilidades",
    "unique_version_entries": "entradas de versiones unicas",
    "cves_cached": "CVEs (en cache)",
    "misconfig_checking": "revisando problemas comunes",
    "misconfig_found_count": "misconfiguraciones encontradas",
    "ssl_checking": "revisando endpoints SSL",
    "ssl_findings_count": "hallazgos SSL",
    "vuln_summary_title": "Resumen de vulnerabilidades",
    "critical": "Critico",
    "high": "Alto",
    "medium": "Medio",
    "low": "Bajo",
    "info": "Info",
    "findings_title": "Hallazgos",
    "and_more": "... y {} mas",
    "nuclei_not_found": "[!] nuclei no esta. instalar: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "nuclei_running": "corriendo plantillas",
    "nuclei_findings": "hallazgos de nuclei",
    "nuclei_scanning": "escaneando (timeout 120s)",
    "nuclei_done": "listo",
    "nuclei_timeout": "se paso el tiempo (120s)",
    "nuclei_not_found_short": "no esta",
    "nuclei_error": "error",
    "from": "de",
    "cve_timeout_phase": "[!] timeout en la fase de CVEs (5 min), se omiten los productos restantes",
    "recon_phase_progress": "reconocimiento",
}


def t(key: str) -> str:
    if _LANG == "es":
        return STRINGS.get("es", {}).get(key, DEFAULT.get(key, key))
    return DEFAULT.get(key, key)


def apply_thread_override(config: dict, threads: int | None) -> dict[str, Any]:
    if threads is not None and threads > 0:
        if "target" not in config:
            config["target"] = {}
        config["target"]["threads"] = threads
    return config
