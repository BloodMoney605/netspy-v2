"""Cliente de la API de NVD.

Se consulta por CPE (virtualMatchString) para que NVD resuelva los rangos de
version. Sin API key NVD limita a 5 peticiones cada 30 segundos; con key, 50.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from cve.catalog import _build_cpe
from common import t
from cve.version import _cpe_version_verdict, _version_in_range

API_KEY_ENV = "NETSPY_NVD_KEY"
LIMITE_SIN_KEY = 6.0
LIMITE_CON_KEY = 1.2


def api_key() -> str:
    return os.environ.get(API_KEY_ENV, "").strip()


def con_api_key() -> bool:
    return bool(api_key())


def espera_entre_peticiones() -> float:
    return LIMITE_CON_KEY if con_api_key() else LIMITE_SIN_KEY


def _request(url: str):
    """Agrega el header de autenticacion cuando hay API key."""
    key = api_key()
    if not key:
        return url
    return Request(url, headers={"apiKey": key})


def init_cve_db(db_path: str) -> sqlite3.Connection:
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            key TEXT PRIMARY KEY,
            data TEXT,
            fetched_at INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_index (
            id TEXT PRIMARY KEY,
            product TEXT,
            version_range TEXT,
            severity TEXT,
            summary TEXT
        )
    """)
    conn.commit()
    return conn

def query_nvd(product: str, version: str) -> list[dict[str, Any]]:
    """Pregunta a NVD que CVEs afectan esta version.

    Con CPE (virtualMatchString) NVD resuelve los rangos. Con keywordSearch
    devuelve ordenados por ID y sin paginar, asi que solo se leian los mas
    viejos.
    """
    cpe = _build_cpe(product, version)
    if cpe:
        results = _query_nvd_paged(
            f"virtualMatchString={quote(cpe)}", product, version, cpe_query=True
        )
        if results:
            # NVD ya resolvio el rango para este CPE.
            for entry in results:
                entry["version_verified"] = True
            return results

    # Sin CPE no hay forma de confirmar la version: se marca como no verificado.
    version_parts = version.strip().split(".")
    major_version = ".".join(version_parts[:2]) if len(version_parts) >= 2 else version_parts[0]
    keyword = f"{product} {major_version}"
    results = _query_nvd_paged(
        f"keywordSearch={quote(keyword)}", product, version, max_results=200
    )
    for entry in results:
        entry.setdefault("version_verified", False)
    return results

def _query_nvd_paged(
    query: str,
    product: str,
    version: str,
    max_results: int = 1000,
    page_size: int = 2000,
    cpe_query: bool = False,
) -> list[dict[str, Any]]:
    """Consulta paginada. Reintenta ante 429 y avisa si se queda corta."""
    collected: list[dict[str, Any]] = []
    start = 0
    rate_limited = False

    while start < max_results:
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?{query}&resultsPerPage={page_size}&startIndex={start}"
        )
        data = None
        espera = espera_entre_peticiones()
        for attempt in range(3):
            try:
                with urlopen(_request(url), timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                break
            except Exception as exc:
                if "429" in str(exc):
                    if attempt < 2:
                        time.sleep(espera * (attempt + 1))
                        continue
                    rate_limited = True
                    break
                return _filter_nvd_results(
        product, version, {"vulnerabilities": collected}, cpe_query
    )

        if data is None:
            break

        collected.extend(data.get("vulnerabilities", []))
        total = data.get("totalResults", 0)
        start += page_size
        if start >= total or not data.get("vulnerabilities"):
            break

    if not collected:
        return []

    if rate_limited:
        print(f"    {t('cve_rate_limited')}")

    return _filter_nvd_results(
        product, version, {"vulnerabilities": collected}, cpe_query
    )

def _filter_nvd_results(
    product: str,
    version: str,
    data: dict,
    cpe_query: bool = False,
) -> list[dict[str, Any]]:
    """Filtra lo que no corresponde a este producto/version.

    Con cpe_query la peticion fue virtualMatchString: NVD ya resolvio los
    rangos, así que no se vuelven a verificar.
    """
    product_lower = product.lower()
    clean_version = version.strip()
    results = []

    for vuln_entry in data.get("vulnerabilities", []):
        cve_data = vuln_entry.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        severity, score = _extract_nvd_severity(cve_data.get("metrics", {}))
        summary = _get_english_summary(cve_data.get("descriptions", [])[:300])
        if not summary:
            continue

        summary_lower = summary.lower()

        if not cpe_query:
            # Filtros de texto: solo aplican a keywordSearch. Con CPE NVD ya
            # confirmo producto y version, y exigir el nombre en el summary
            # descartaba CVEs reales.
            if not _product_in_summary(product_lower, summary_lower):
                continue

            if _is_false_positive(product_lower, summary_lower):
                continue

        if cpe_query:
            # NVD ya resolvio los rangos para este CPE.
            results.append({
                "id": cve_id,
                "severity": severity.upper(),
                "score": score,
                "summary": summary,
                "source": "nvd",
                "version_verified": True,
            })
            continue

        version_range = _version_in_range(clean_version, summary_lower)

        # Los datos estructurados de NVD mandan sobre el texto. Cuando hay
        # veredicto, el de arriba se descarta.
        cpe_verdict = _cpe_version_verdict(cve_data, clean_version, product)
        if cpe_verdict is not None:
            version_range = cpe_verdict
        version_verified = version_range is True

        if version_range is False:
            continue

        if version_range is True:
            results.append({
                "id": cve_id,
                "severity": severity.upper(),
                "score": score,
                "summary": summary,
                "source": "nvd",
            })
            continue

        version_in_summary = (
            clean_version in summary
            or f"before {clean_version}" in summary_lower
            or f"through {clean_version}" in summary_lower
            or f"up to {clean_version}" in summary_lower
            or f"prior to {clean_version}" in summary_lower
        )

        if not version_in_summary:
            mentioned_versions = re.findall(
                r"\b(\d+\.\d+(?:\.\d+)*)\b", summary_lower
            )
            if not mentioned_versions:
                continue

            our_major = clean_version.split(".")[0]
            compatible_version = False
            for mv in mentioned_versions:
                if mv.split(".")[0] == our_major:
                    compatible_version = True
                    break

            if not compatible_version:
                continue

        results.append({
            "id": cve_id,
            "severity": severity.upper(),
            "score": score,
            "summary": summary,
            "source": "nvd",
            "version_verified": version_verified,
        })

    return results

def _extract_nvd_severity(metrics: dict) -> tuple[str, float]:
    severity = "UNKNOWN"
    score = 0.0

    cvss_types = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for cvss_type in cvss_types:
        if cvss_type not in metrics:
            continue

        cvss_data = metrics[cvss_type][0].get("cvssData", {})
        severity = cvss_data.get("baseSeverity", "")
        score = cvss_data.get("baseScore", 0)

        if not severity and score > 0:
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        if severity:
            break

    return severity.upper(), score

def _get_english_summary(descriptions: list) -> str:
    for entry in descriptions:
        if entry.get("lang") == "en":
            return entry.get("value", "")[:300]
    return ""

def _product_in_summary(product: str, summary: str) -> bool:
    first_part = summary[:150]
    product_words = product.split()

    # Producto de varias palabras: se busca el bigrama en el summary
    if len(product_words) >= 2:
        for idx in range(len(product_words) - 1):
            bigram = f"{product_words[idx]} {product_words[idx + 1]}"
            if bigram in first_part:
                return True
        return False

    # Palabra suelta de menos de 4 letras: con limites de palabra
    if len(product) < 4:
        word_boundary = r'\b' + re.escape(product) + r'\b'
        return bool(re.search(word_boundary, first_part))

    # Caso general: subcadena simple
    return product in first_part

def _is_false_positive(product: str, summary: str) -> bool:
    # El nombre aparece dentro de otra palabra sin relacion
    # Example: "ed" inside "privileged", "acl" inside "aclcheck"
    short_name_compounds = {
        "ed": ["privileged", "privilege", "needed", "embedded", "extended", "redirected"],
        "acl": [],
        "dash": ["dashmachine"],
    }

    for short_name, compounds in short_name_compounds.items():
        if product != short_name:
            continue
        for compound in compounds:
            if short_name in compound and compound in summary:
                return True

    # "dash" also matches DASH 7 IoT protocol (not the shell)
    if product == "dash":
        if "alliance" in summary or "protocol" in summary or "iot" in summary:
            return True

    # Windows-specific components (WinNT MPM, etc.)
    if "winnt" in summary:
        return True

    # CVEs about other runtimes (PHP, Python, etc.)
    other_runtimes = ["php", "python", "perl"]
    for runtime in other_runtimes:
        if runtime in summary and runtime not in product:
            version_pattern = runtime + r"\s+(before|through|up to)\s+\d+\.\d+"
            if re.search(version_pattern, summary):
                return True

    return False
