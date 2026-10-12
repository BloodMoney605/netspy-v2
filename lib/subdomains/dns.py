"""Resolucion DNS."""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from netspy_env import have
from subdomains.fuentes import run_cmd


def _dns_resolve_socket(subdomain: str, record_type: str) -> list[str]:
    """Resolver de respaldo cuando no hay dig.

    Solo cubre A y AAAA, que es lo que necesita el pipeline. Los demas tipos
    de registro quedan vacios sin dig.
    """
    try:
        if record_type == "A":
            infos = socket.getaddrinfo(subdomain, None, socket.AF_INET)
        elif record_type == "AAAA":
            infos = socket.getaddrinfo(subdomain, None, socket.AF_INET6)
        else:
            return []
    except OSError:
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))

def dns_resolve(subdomain: str, record_type: str = "A", resolver: str | None = None) -> list[str]:
    if not have("dig"):
        return _dns_resolve_socket(subdomain, record_type)

    cmd = ["dig", "+short"]
    if resolver:
        cmd.append(f"@{resolver}")
    cmd.extend([record_type, subdomain])
    result = run_cmd(cmd)
    if not result:
        # dig may be installed but blocked by policy or a restricted resolver.
        return _dns_resolve_socket(subdomain, record_type)
    lines = [line.strip() for line in result.split("\n") if line.strip()]
    if record_type == "A":
        ipv4_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        return [line for line in lines if ipv4_re.match(line)]
    return lines

def dns_enum(domain: str, resolver: str | None = None) -> dict[str, Any]:
    records: dict[str, Any] = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        values = dns_resolve(domain, rtype, resolver)
        if values:
            records[rtype.lower()] = values
    return records

def resolve_all(subdomains: list[str], threads: int = 20) -> dict[str, list[str]]:
    resolved: dict[str, list[str]] = {}

    def resolve_one(subdomain: str, resolver: str | None = None) -> tuple[str, list[str]]:
        ips = dns_resolve(subdomain, "A", resolver)
        return subdomain, ips

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(resolve_one, subdomain): subdomain for subdomain in subdomains}
        for future in as_completed(futures):
            subdomain, ips = future.result()
            if ips:
                resolved[subdomain] = ips

    return resolved

def collect_unique_ips(resolved: dict[str, list[str]]) -> list[str]:
    seen: set[str] = set()
    ips: list[str] = []
    for ip_list in resolved.values():
        for ip_address in ip_list:
            if ip_address not in seen:
                seen.add(ip_address)
                ips.append(ip_address)
    return ips

def detect_wildcard_dns(domain: str, resolver: str | None = None) -> list[str]:
    import uuid
    wildcard_ips: list[str] = []
    for _ in range(3):
        fake = f"{uuid.uuid4().hex[:12]}.{domain}"
        ips = dns_resolve(fake, "A", resolver)
        if ips:
            for ip_address in ips:
                if ip_address not in wildcard_ips:
                    wildcard_ips.append(ip_address)
    return wildcard_ips
