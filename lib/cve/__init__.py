"""Deteccion de CVEs: NVD (CPE) y OSV (ecosistemas)."""

from cve.match import match_cves
from cve.nvd import con_api_key, init_cve_db, query_nvd
from cve.osv import query_osv

__all__ = [
    "match_cves",
    "con_api_key",
    "init_cve_db",
    "query_nvd",
    "query_osv",
]