"""Fuerza bruta de subdominios con wordlist."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from netspy_env import ROOT, data_dir, expand_config_path
from subdomains.dns import detect_wildcard_dns, dns_resolve

BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"

COMMON_SUBS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "dns", "ns1", "ns2", "ns3", "ns4", "mx", "mx1", "mx2", "mx3",
    "cpanel", "whm", "autodiscover", "admin", "login", "api",
    "app", "dev", "staging", "test", "beta", "qa", "uat", "prod",
    "blog", "shop", "store", "cdn", "static", "assets",
    "media", "images", "files", "portal", "dashboard",
    "support", "help", "docs", "vpn", "remote", "cloud",
    "db", "database", "git", "jenkins", "monitor", "status",
    "mail2", "web", "sso", "auth", "oauth", "saml",
    "ldap", "ad", "internal", "intranet", "extranet",
    "backup", "archive", "logs", "metrics", "grafana",
    "kibana", "elastic", "redis", "cache", "proxy",
    "lb", "loadbalancer", "firewall", "waf", "bastion",
    "docker", "k8s", "kubernetes", "registry", "harbor",
    "jira", "confluence", "wiki", "gitlab", "github",
    "bitbucket", "nexus", "artifactory", "maven", "npm",
    "pypi", "dockerhub", "sonar", "sonarqube", "sentry",
    "prometheus", "alertmanager", "consul", "vault",
    "terraform", "ansible", "puppet", "chef",
    "exchange", "owa", "lync", "skype",
    "teams", "meet", "zoom", "webinar", "conference",
    "calendar", "contacts", "directory", "phonebook",
    "crm", "erp", "hr", "finance", "accounting",
    "billing", "payments", "checkout", "cart", "orders",
    "inventory", "warehouse", "shipping", "tracking",
    "analytics", "pixel", "tag", "beacon",
    "sandbox", "demo", "preview", "example", "sample",
    "training", "learn", "education", "course", "lms",
    "forum", "community", "social", "chat", "irc",
    "discord", "slack", "mattermost", "rocket",
    "news", "press", "pr", "marketing",
    "seo", "sem", "ads", "campaign", "promo",
    "affiliate", "partner", "reseller", "vendor",
    "supplier", "customer", "client", "user",
    "member", "subscriber", "newsletter", "digest",
    "rss", "atom", "feed", "sitemap", "robots",
    "health", "healthcheck", "ping", "heartbeat",
    "uptime", "downtime", "maintenance", "deploy",
    "release", "version", "changelog", "roadmap",
    "server", "host", "node", "cluster", "master", "slave",
    "primary", "secondary", "replica", "mirror",
    "origin", "edge", "gateway", "router", "switch",
    "wifi", "wireless", "guest", "corp", "office",
    "home", "lab", "devops", "ci", "cd", "pipeline",
    "build", "artifact", "package", "release",
    "debug", "trace", "log", "audit", "compliance",
    "security", "pentest", "bugbounty", "vuln",
    "scan", "nmap", "nessus", "qualys", "openvas",
    "siem", "soc", "ids", "ips", "honeypot",
    "ticket", "helpdesk", "servicedesk", "itsm",
    "payroll", "benefits", "recruiting", "onboarding",
    "legal", "privacy", "gdpr", "compliance",
    "investor", "ir", "shareholder", "board",
    "events", "webcast", "livestream", "broadcast",
    "survey", "feedback", "review", "rating",
    "download", "upload", "transfer", "sync",
    "api2", "api-v2", "api3", "api-v3", "graphql",
    "ws", "websocket", "socket", "stream",
    "m", "mobile", "mapi", "madmin",
    "old", "legacy", "v1", "v2", "v3", "new",
    "temp", "tmp", "scratch", "playground",
    "research", "rnd", "innovation", "ideas",
    "data", "datalake", "warehouse", "etl",
    "ai", "ml", "model", "training-data",
    "backup2", "dr", "disaster-recovery", "failover",
]


def load_wordlist(config: dict) -> list[str]:
    """Busca la wordlist que indica la config.

    Orden: ruta absoluta o relativa al cwd, al directorio de datos, junto al
    config, o la raiz del repo. Si no aparece, usa la lista interna.
    """
    from netspy_env import expand_config_path

    configured = (
        config.get("recon", {})
        .get("subdomains", {})
        .get("wordlist", "")
    )
    if not configured:
        return list(COMMON_SUBS)

    candidates = [
        Path(configured),
        expand_config_path(configured),
        data_dir() / configured,
        ROOT / "config" / Path(configured).name,
        ROOT / Path(configured).name,
    ]

    for candidate in candidates:
        try:
            if candidate.is_file():
                words = [
                    line.strip().lower()
                    for line in candidate.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                ]
                words = [
                    w for w in words
                    if w and not w.startswith("#") and "." not in w
                ]
                if words:
                    return sorted(set(words))
        except OSError:
            continue

    print(f"  {DIM}no se encontro la wordlist ({configured}), se usa la lista interna{NC}")
    return list(COMMON_SUBS)

def brute_subdomains(domain: str, threads: int = 20, words: list[str] | None = None, resolver: str | None = None) -> list[str]:
    found: list[str] = []
    candidates = words if words else list(COMMON_SUBS)

    wildcard_ips = detect_wildcard_dns(domain, resolver)
    if wildcard_ips:
        print(f"  {DIM}wildcard DNS detected, filtering fake subs{NC}")

    def check(subdomain: str) -> str | None:
        full = f"{subdomain}.{domain}"
        ips = dns_resolve(full, "A", resolver)
        if not ips:
            return None
        if wildcard_ips and any(ip_address in wildcard_ips for ip_address in ips):
            return None
        return full

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(check, sub): sub for sub in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found)
