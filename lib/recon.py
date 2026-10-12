"""Fase 1: reconocimiento de subdominios, DNS y WHOIS.

Las fuentes pasivas, el DNS, el WHOIS y la fuerza bruta viven en subdomains/.
Aqui solo se orquestan.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from typing import Any

from common import apply_thread_override, t
from config import cargar as load_config
from netspy_env import is_interactive, have
from subdomains.brute import brute_subdomains, load_wordlist
from subdomains.dns import collect_unique_ips, dns_enum, resolve_all
from subdomains.fuentes import (
    alienvault_subdomains,
    certspotter_subdomains,
    crtsh_subdomains,
    dnsdumpster_subdomains,
    rapiddns_subdomains,
    threatcrowd_subdomains,
    wayback_subdomains,
)
from subdomains.whois import asn_lookup, whois_lookup

BOLD = "\033[1m"
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
YELLOW = "\033[0;33m"
DIM = "\033[2m"
NC = "\033[0m"

def normalize_domain(domain: str) -> str:
    """Deja solo el dominio raiz: sin esquema, puerto ni www."""
    domain = domain.strip().rstrip("/")
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    if "/" in domain:
        domain = domain.split("/", 1)[0]
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    domain = domain.rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    partes = domain.split(".")
    if len(partes) >= 2:
        return ".".join(partes[-2:])
    return domain


def run_recon(domain: str, config: dict, output: str) -> dict[str, Any]:
    base_domain = normalize_domain(domain)
    resolver = config.get("recon", {}).get("subdomains", {}).get("resolver") or None

    print(f"  {t('domain')}:              {base_domain}")
    print()

    all_subs: set[str] = set()

    disponibles = [
        ("crt.sh", lambda: crtsh_subdomains(base_domain)),
        ("certspotter", lambda: certspotter_subdomains(base_domain)),
        ("alienvault", lambda: alienvault_subdomains(base_domain)),
        ("threatcrowd", lambda: threatcrowd_subdomains(base_domain)),
        ("dnsdumpster", lambda: dnsdumpster_subdomains(base_domain)),
        ("rapiddns", lambda: rapiddns_subdomains(base_domain)),
        ("wayback", lambda: wayback_subdomains(base_domain)),
    ]

    # sources en la config acota cuales se consultan; sin la clave, todas.
    pedidas = config.get("recon", {}).get("subdomains", {}).get("sources")
    if isinstance(pedidas, list) and pedidas:
        elegidas = {str(x).lower() for x in pedidas}
        sources = [
            (nombre, fn) for nombre, fn in disponibles
            if nombre.lower() in elegidas or nombre.lower().replace(".sh", "").replace("-", "") in elegidas
        ]
        if not sources:
            sources = disponibles
    else:
        sources = disponibles

    total_sources = len(sources)
    bar_len = 30

    def _run_progress_bar(label: str, work_fn, total_steps: int):
        current_step = 0
        done = False
        interactive = is_interactive()

        def _animate():
            step = 0
            max_steps = total_steps * 10
            while not done and step < max_steps:
                time.sleep(0.15)
                step += 1
                pct = min(int((step / max_steps) * 100), 99)
                filled = int(bar_len * pct // 100)
                bar = "#" * filled + "-" * (bar_len - filled)
                if interactive:
                    print(f"\r  [{bar}] {pct}% {label}", end="", flush=True)

        anim = threading.Thread(target=_animate, daemon=True)
        anim.start()

        for step_idx in range(total_steps):
            work_fn(step_idx)
            current_step = step_idx + 1

        done = True
        anim.join(timeout=1)
        if interactive:
            print(f"\r  {'#' * bar_len} 100% {label}", flush=True)

    source_idx = 0
    source_results: list[tuple[str, list[str]]] = []

    def _fetch_source(idx: int):
        nonlocal source_idx
        name, fetch_fn = sources[idx]
        new_subs = fetch_fn()
        all_subs.update(new_subs)
        source_results.append((name, new_subs))
        source_idx = idx + 1

    _run_progress_bar(t('enumerating_subdomains'), _fetch_source, total_sources)

    subs = sorted(all_subs)

    if len(subs) < 10:
        print(f"  {t('wordlist_brute')}...", end=" ", flush=True)
        brute = brute_subdomains(
            base_domain,
            threads=config.get("target", {}).get("threads", 20),
            words=load_wordlist(config),
            resolver=resolver,
        )
        all_subs.update(brute)
        subs = sorted(all_subs)
        print(f"{len(brute)} {t('found')}")

    if base_domain not in all_subs:
        subs.insert(0, base_domain)
        all_subs.add(base_domain)

    subs = sorted(all_subs)

    print(f"\n  {BOLD}{t('subdomains')} ({len(subs)}){NC}")
    for sub in subs:
        print(f"  {GREEN}{sub}{NC}")

    resolved: dict[str, list[str]] = {}
    whois: dict[str, str] = {}

    print(f"  {t('resolving')} {len(subs)}...", end=" ", flush=True)
    resolved = resolve_all(subs, threads=config.get("target", {}).get("threads", 20))
    print(f"{len(resolved)} {t('alive')}")

    print(f"  {t('whois_lookup')}...", end=" ", flush=True)
    whois = whois_lookup(base_domain)
    print(t('done'))

    ips = collect_unique_ips(resolved)
    dns_records = dns_enum(base_domain, resolver)

    asn_results: list[dict[str, Any]] = []
    for ip_address in ips[:5]:
        info = asn_lookup(ip_address)
        if info:
            info["ip"] = ip_address
            asn_results.append(info)

    result: dict[str, Any] = {
        "domain": base_domain,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subdomains": subs,
        "subdomains_count": len(subs),
        "resolved": resolved,
        "resolved_count": len(resolved),
        "ips": ips,
        "ips_count": len(ips),
        "dns": dns_records,
        "whois": whois,
        "asn": asn_results,
    }

    recon_path = os.path.join(output, "recon.json")
    with open(recon_path, "w", encoding="utf-8") as recon_file:
        json.dump(result, recon_file, indent=2, default=str)

    ips_path = os.path.join(output, "ips.txt")
    with open(ips_path, "w", encoding="utf-8") as ips_file:
        for ip_address in ips:
            ips_file.write(ip_address + "\n")

    subs_path = os.path.join(output, "subdomains.txt")
    with open(subs_path, "w", encoding="utf-8") as subs_file:
        for subdomain in resolved:
            subs_file.write(subdomain + "\n")

    print(f"\n  {BOLD}{t('recon_summary')}{NC}")
    print(f"  {BOLD}{'─' * 40}{NC}")
    print(f"  {t('subdomains')}: {GREEN}{len(subs)}{NC}")
    print(f"  {t('resolved')}:   {GREEN}{len(resolved)}{NC}")
    print(f"  {t('unique_ips')}: {CYAN}{len(ips)}{NC}")
    if ips:
        print(f"\n  {BOLD}{t('top_ips')}{NC}")
        for ip_address in ips[:10]:
            print(f"  {GREEN}{ip_address}{NC}")
        if len(ips) > 10:
            print(f"  {DIM}{t('more').format(len(ips) - 10)}{NC}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Fase 1: reconocimiento")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    config = apply_thread_override(config, args.threads)
    os.makedirs(args.output, exist_ok=True)

    try:
        run_recon(args.domain, config, args.output)
    except KeyboardInterrupt:
        print("\n  [!] interrumpido")
        sys.exit(130)


if __name__ == "__main__":
    main()
