"""Orquestacion: cache, hilos y deduplicacion de hallazgos."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from common import t
from cve.catalog import ALIAS_PRODUCTOS, SKIP_PRODUCTOS
from cve.catalog import LINUX_DISTRO_ECOSYSTEMS, OSV_ECOSYSTEMS, CPE_PRODUCTS
from cve.nvd import query_nvd
from cve.osv import _is_distro_package, query_osv
from cve.version import _is_plausible_version


def _nota(mensaje: str) -> None:
    """Solo se ve con NETSPY_DEBUG=1."""
    if os.environ.get("NETSPY_DEBUG") in ("1", "true", "yes"):
        print(f"      [debug] {mensaje}", file=sys.stderr)

def _fetch_cves(product: str, version: str, db: sqlite3.Connection,
                cache_lock: threading.Lock) -> tuple[str, list[dict[str, Any]]]:
    cache_key = f"{product}|{version}"
    # La escritura de abajo usa cache_lock; esta lectura tambien, o puede caer
    # dentro de la transaccion de otro hilo.
    with cache_lock:
        cursor = db.execute("SELECT data FROM cve_cache WHERE key = ?", (cache_key,))
        cached = cursor.fetchone()
    if cached:
        return cache_key, json.loads(cached[0])

    all_cves: list[dict[str, Any]] = []

    try:
        all_cves.extend(query_nvd(product, version))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _nota(f"nvd {product} {version}: {exc}")

    product_lower = product.lower()
    if product_lower in OSV_ECOSYSTEMS:
        for eco in OSV_ECOSYSTEMS[product_lower]:
            try:
                all_cves.extend(query_osv(eco, product, version))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                _nota(f"osv {eco} {product}: {exc}")

    if _is_distro_package(product):
        for eco in LINUX_DISTRO_ECOSYSTEMS:
            try:
                all_cves.extend(query_osv(eco, product, version))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                _nota(f"osv {eco} {product}: {exc}")

    seen_ids: set[str] = set()
    cves_by_id: dict[str, dict[str, Any]] = {}
    for cve_entry in all_cves:
        cve_id = cve_entry.get("id", "")
        if not cve_id:
            continue

        if cve_id not in cves_by_id:
            cves_by_id[cve_id] = cve_entry
        else:
            existing = cves_by_id[cve_id]
            if cve_entry.get("source") == "nvd" and existing.get("source") != "nvd":
                cves_by_id[cve_id] = cve_entry
            elif cve_entry.get("severity", "UNKNOWN") != "UNKNOWN" and existing.get("severity", "UNKNOWN") == "UNKNOWN":
                cves_by_id[cve_id] = cve_entry
            elif cve_entry.get("score", 0) > existing.get("score", 0):
                cves_by_id[cve_id] = cve_entry

    cves = list(cves_by_id.values())

    try:
        with cache_lock:
            db.execute(
                "INSERT OR REPLACE INTO cve_cache (key, data, fetched_at) VALUES (?, ?, ?)",
                (cache_key, json.dumps(cves), int(time.time())),
            )
            db.commit()
    except (sqlite3.Error, OSError, ValueError) as exc:
        # La cache es una aceleracion: si falla, se sigue sin ella.
        _nota(f"cache {cache_key}: {exc}")

    return cache_key, cves


def match_cves(versions: list[dict[str, str]], db: sqlite3.Connection) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_cves: set[tuple[str, str]] = set()

    seen_versions: set[str] = set()
    unique_versions: list[tuple[str, str]] = []

    for version_entry in versions:
        product = version_entry["product"]
        version = version_entry["version"]
        if len(version) > 15 or not any(c.isdigit() for c in version):
            continue
        product = re.sub(r"[^a-zA-Z0-9\s._-]+$", "", product).strip()
        if not product:
            continue
        product_lower = product.lower().strip()
        normalized = ALIAS_PRODUCTOS.get(product_lower, product)
        if normalized.lower() in SKIP_PRODUCTOS:
            continue
        if not _is_plausible_version(normalized, version):
            continue
        key = f"{normalized.lower()}|{version}"
        if key not in seen_versions:
            seen_versions.add(key)
            unique_versions.append((normalized, version))


    print(f"    {t('unique_version_entries')}: {len(unique_versions)} "
          f"({t('from')} {len(versions)} {t('total')})")
    print()

    cache_lock = threading.Lock()
    worker_count = min(2, len(unique_versions))
    phase_deadline = time.time() + 300

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        future_map = {
            pool.submit(_fetch_cves, prod, ver, db, cache_lock): (idx, prod, ver)
            for idx, (prod, ver) in enumerate(unique_versions, 1)
        }

        results_by_idx: dict[int, tuple[str, list[dict[str, Any]]]] = {}
        for future in as_completed(future_map):
            if time.time() > phase_deadline:
                print(f"    {t('cve_timeout_phase')}")
                pool.shutdown(wait=False, cancel_futures=True)
                break
            idx, product, version = future_map[future]
            try:
                cache_key, cves = future.result()
                results_by_idx[idx] = (product, version, cves)
            except Exception:
                results_by_idx[idx] = (product, version, [])

    for idx in range(1, len(unique_versions) + 1):
        product, version, cves = results_by_idx.get(idx, ("", "", []))
        print(f"    [{idx}/{len(unique_versions)}] {product} {version}... ", end="", flush=True)
        if cves:
            sources = set()
            for cve_entry in cves:
                src = cve_entry.get("source", "osv")
                if isinstance(src, str):
                    sources.add(src)
            print(f"{len(cves)} CVEs (sources: {', '.join(sorted(sources))})")
        else:
            print("0 CVEs")

        for cve_entry in cves:
            cve_id = cve_entry.get("id", "")
            if not isinstance(cve_id, str) or not cve_id:
                continue
            # Deduplicar por (CVE, version): un CVE suele afectar varias
            # versiones detectadas.
            dedup_key = (cve_id, version)
            if dedup_key in seen_cves:
                continue
            seen_cves.add(dedup_key)

            findings.append({
                "type": "cve",
                "id": cve_id,
                "product": product,
                "version": version,
                "severity": cve_entry.get("severity", "UNKNOWN"),
                "score": cve_entry.get("score", 0),
                "summary": cve_entry.get("summary", "")[:300],
                "source": cve_entry.get("source", "osv") if isinstance(cve_entry.get("source"), str) else "osv",
                # Por defecto sin verificar: lo no confirmado es candidato.
                "version_verified": cve_entry.get("version_verified", False),
            })

    return findings
