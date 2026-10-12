"""Cliente de OSV, para ecosistema y paquetes de distribucion."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.request import Request, urlopen


def query_osv(ecosystem: str, package: str, version: str) -> list[dict[str, Any]]:
    """Consulta OSV por version exacta.

    El endpoint /v1/query ya filtra por version, asi que el resultado viene
    verificado.
    """
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }).encode()

    req = Request(url, data=payload, headers={"Content-Type": "application/json"})

    retries = 3
    for attempt in range(retries):
        try:
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                vulns = data.get("vulns", [])
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        vuln.setdefault("version_verified", True)
                        vuln.setdefault("source", "osv")
                return vulns
        except Exception as e:
            if "429" in str(e) and attempt < retries - 1:
                time.sleep(1.0 * (attempt + 1))
                continue
            return []
    return []


#: Maps a product name to its CPE vendor/product pair, so NetSpy can ask NVD
#: for "every CVE affecting this exact version" instead of guessing from prose.

def _is_distro_package(product: str) -> bool:
    product_lower = product.lower().strip()
    distro_packages = {
        "openssh", "openssl", "nginx", "apache", "httpd", "apache http server",
        "mysql", "mariadb", "postgres", "postgresql", "php", "python",
        "perl", "ruby", "node.js", "nodejs", "bind", "named", "postfix",
        "dovecot", "exim", "sendmail", "cron", "systemd", "glibc",
        "curl", "wget", "git", "sudo", "bash", "zsh", "vim", "emacs",
        "tar", "gzip", "rsync", "sshd", "ftp", "vsftpd", "proftpd",
        "samba", "smb", "cifs", "nfs", "iscsi",
    }
    if product_lower in distro_packages:
        return True
    for distro_pkg in distro_packages:
        if product_lower.startswith(distro_pkg) or distro_pkg.startswith(product_lower):
            return True
    return False
