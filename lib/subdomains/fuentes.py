"""Fuentes pasivas de subdominios."""

from __future__ import annotations

import json
import re
import time
from urllib.request import Request, urlopen

from common import get_stealth_ua, stealth_sleep
from netspy_env import run_capture


def crtsh_subdomains(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()
    failed = True

    for attempt in range(3):
        try:
            stealth_sleep()
            with urlopen(req, timeout=8) as resp:
                raw = resp.read().decode()
                data = json.loads(raw)
                if not isinstance(data, list):
                    raise ValueError("crt.sh returned non-list response")
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and "*" not in sub:
                            subdomains.add(sub)
                failed = False
                break
        except Exception:
            if attempt < 2:
                time.sleep(1)
            continue

    if failed:
        pass

    return sorted(subdomains)

def certspotter_subdomains(domain: str) -> list[str]:
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()

    try:
        stealth_sleep()
        with urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
            for entry in data:
                for dns_name in entry.get("dns_names", []):
                    name = dns_name.lstrip("*.")
                    if name.endswith(f".{domain}") and name != domain:
                        subdomains.add(name.lower())
    except Exception:
        pass

    return sorted(subdomains)

def alienvault_subdomains(domain: str) -> list[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()

    try:
        stealth_sleep()
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                if hostname and hostname.endswith(f".{domain}") and "*" not in hostname:
                    subdomains.add(hostname.lower())
    except Exception:
        pass

    return sorted(subdomains)

def threatcrowd_subdomains(domain: str) -> list[str]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()

    try:
        stealth_sleep()
        with urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
            for sub in data.get("subdomains", []):
                if sub.endswith(f".{domain}") and "*" not in sub:
                    subdomains.add(sub.lower())
    except Exception:
        pass

    return sorted(subdomains)

def dnsdumpster_subdomains(domain: str) -> list[str]:
    url = "https://dnsdumpster.com/"
    subdomains: set[str] = set()

    try:
        import ssl
        ctx = ssl.create_default_context()
        conn = __import__("http.client").HTTPSConnection("dnsdumpster.com", timeout=12, context=ctx)
        stealth_sleep()
        conn.request("GET", "/", headers={"User-Agent": get_stealth_ua()})
        resp = conn.getresponse()
        csrf_token = ""
        for header in resp.getheaders():
            if header[0].lower() == "set-cookie":
                cookie_val = header[1]
                if "csrftoken" in cookie_val:
                    csrf_token = cookie_val.split("csrftoken=")[1].split(";")[0]
                    break

        if not csrf_token:
            return []

        conn.request("POST", "/",
                     body=f"csrfmiddlewaretoken={csrf_token}&targetip={domain}",
                     headers={
                         "Content-Type": "application/x-www-form-urlencoded",
                         "Referer": "https://dnsdumpster.com/",
                         "Cookie": f"csrftoken={csrf_token}",
                         "User-Agent": get_stealth_ua(),
                     })
        resp = conn.getresponse()
        html = resp.read().decode()

        hrefs = re.findall(r'href="https?://([^"]+)"', html)
        for href in hrefs:
            host = href.split("/")[0]
            if host.endswith(f".{domain}") and "*" not in host:
                subdomains.add(host.lower())

        conn.close()
    except Exception:
        pass

    return sorted(subdomains)

def rapiddns_subdomains(domain: str) -> list[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()

    try:
        stealth_sleep()
        with urlopen(req, timeout=15) as resp:
            html = resp.read().decode()
            hrefs = re.findall(r'href="https?://([^"]+)"', html)
            for href in hrefs:
                host = href.split("/")[0]
                if host.endswith(f".{domain}") and "*" not in host:
                    subdomains.add(host.lower())
    except Exception:
        pass

    return sorted(subdomains)

def wayback_subdomains(domain: str) -> list[str]:
    subdomains: set[str] = set()

    try:
        import ssl
        ctx = ssl.create_default_context()
        conn = __import__("http.client").HTTPSConnection("web.archive.org", timeout=10, context=ctx)
        conn.request("GET", f"/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=2000",
                     headers={"User-Agent": "Mozilla/5.0"})
        resp = conn.getresponse()
        line_count = 0
        while line_count < 2000:
            line = resp.readline()
            if not line:
                break
            line_count += 1
            raw = line.decode().strip()
            if not raw:
                continue
            try:
                parsed = __import__("urllib.parse").urlparse(raw)
                hostname = parsed.hostname
                if hostname and hostname.endswith(f".{domain}"):
                    subdomains.add(hostname.lower())
            except Exception:
                pass
        conn.close()
    except Exception:
        pass

    return sorted(subdomains)

def run_cmd(cmd: list[str], timeout: int = 15) -> str | None:
    """Ejecuta un comando y devuelve stdout, o None si fallo."""
    return run_capture(cmd, timeout=timeout)
