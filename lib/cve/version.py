"""Comparacion de versiones de software.

Un CVE dice que versiones estan afectadas de tres formas: rangos en la
configuracion CPE de NVD, frases en el summary, o nada. Solo la primera es
fiable; el summary se redacta distinto cada vez que alguien lo actualiza.
"""

from __future__ import annotations

import re


def _parse_version(version_str: str) -> tuple[int, ...]:
    parts = []
    for segment in version_str.strip().split("."):
        match = re.match(r"(\d+)", segment)
        if match:
            parts.append(int(match.group(1)))
        else:
            parts.append(0)
    return tuple(parts) if parts else (0,)

def _cpe_matches_product(cpe_product: str, queried: str) -> bool:
    """Compara el campo product de un CPE con el nombre buscado."""
    def norm(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.lower())

    cpe_norm = norm(cpe_product)
    query_norm = norm(queried)
    if not cpe_norm or not query_norm:
        return False
    return cpe_norm in query_norm or query_norm in cpe_norm

def _cpe_version_verdict(cve_data: dict, our_ver: str, product: str) -> bool | None:
    """Versiones afectadas segun la configuracion CPE de NVD.

    Cubre rangos y tambien CPEs de version exacta, que es como NVD registra
    los CVE viejos. True/False si se puede decidir, None si no dice nada.
    """
    our = _parse_version(our_ver)
    saw_product = False
    saw_explicit = False

    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                if not criteria.startswith("cpe:2.3:"):
                    continue

                fields = criteria.split("cpe:2.3:", 1)[1].split(":")
                if len(fields) < 4:
                    continue
                cpe_vendor, cpe_product, cpe_version = fields[1], fields[2], fields[3]

                if not _cpe_matches_product(cpe_product, product):
                    continue
                saw_product = True

                # Explicit range bounds win when present.
                start = match.get("versionStartIncluding") or match.get(
                    "versionStartExcluding"
                )
                end = match.get("versionEndIncluding") or match.get("versionEndExcluding")

                if start is not None or end is not None:
                    saw_explicit = True
                    low = _parse_version(start) if start else None
                    high = _parse_version(end) if end else None

                    if low is not None:
                        if match.get("versionStartExcluding") and our <= low:
                            continue
                        if not match.get("versionStartExcluding") and our < low:
                            continue
                    if high is not None:
                        if match.get("versionEndExcluding") and our >= high:
                            continue
                        if not match.get("versionEndExcluding") and our > high:
                            continue
                    if low is not None or high is not None:
                        return True
                    continue

                # Plain per-version CPE.
                if cpe_version and cpe_version != "*" and cpe_version != "-":
                    saw_explicit = True
                    if _parse_version(cpe_version) == our:
                        return True

    if not saw_product:
        return None
    if saw_explicit:
        # NVD enumerated the affected versions for this product and none of
        # them is ours, so this version is not affected.
        return False
    # Every CPE was a wildcard version: the CVE affects all versions, so the
    # installed one counts as affected.
    return True

def _version_in_range(our_ver: str, summary_lower: str) -> bool | None:
    our = _parse_version(our_ver)

    version_number = r"(\d+\.\d+(?:\.\d+)*)"
    version_range = version_number + r"\s+(?:to|through)\s+" + version_number

    # Check: "versions X to Y" or "version X to Y"
    match = re.search(r"versions?\s+" + version_range, summary_lower)
    if match:
        return _parse_version(match.group(1)) <= our <= _parse_version(match.group(2))

    # Check: "X to Y" or "X through Y"
    match = re.search(version_range, summary_lower)
    if match:
        return _parse_version(match.group(1)) <= our <= _parse_version(match.group(2))

    # Check: "X and earlier" or "X and prior"
    match = re.search(version_number + r"\s+(?:and earlier|and prior)", summary_lower)
    if match:
        return our <= _parse_version(match.group(1))

    # Check: "before X" or "prior to X"
    match = re.search(r"(?:before|prior to)\s+" + version_number, summary_lower)
    if match:
        return our < _parse_version(match.group(1))

    # Check: "through X" or "up to X"
    match = re.search(r"(?:through|up to)\s+" + version_number, summary_lower)
    if match:
        return our <= _parse_version(match.group(1))

    # Check: "X.x before Y" (e.g. "2.4.x before 2.4.10")
    match = re.search(version_number + r"\.x\s+before\s+" + version_number, summary_lower)
    if match:
        return our < _parse_version(match.group(2))

    # Check: if multiple versions are listed, ours must be one of them
    seen_versions = re.findall(version_number, summary_lower)
    if len(seen_versions) >= 2:
        parsed = [_parse_version(v) for v in seen_versions]
        if our in parsed:
            return True
        if all(our < v for v in parsed):
            return False

    return None

# Rango de version mayor plausible por producto. Sirve para descartar
# basura del fingerprint, no para decidir si hay CVE.
PRODUCT_VERSION_BOUNDS = {
    "wordpress": (0, 6),
    "joomla": (1, 5),
    "drupal": (7, 11),
    "magento": (2, 2),
    "woocommerce": (3, 9),
}


def _is_plausible_version(product: str, version: str) -> bool:
    product_lower = product.lower().strip()
    if product_lower not in PRODUCT_VERSION_BOUNDS:
        return True

    min_major, max_major = PRODUCT_VERSION_BOUNDS[product_lower]
    try:
        major = int(version.split(".")[0])
        return min_major <= major <= max_major
    except (ValueError, IndexError):
        return True
