"""WHOIS por binario o por socket (puerto 43)."""

from __future__ import annotations

import re
import socket
from typing import Any

from netspy_env import have
from subdomains.fuentes import run_cmd


def _whois_socket(target: str, server: str = "whois.iana.org", timeout: int = 10) -> str:
    """Consulta un servidor WHOIS por el puerto 43.

    Se usa cuando no esta el binario `whois`, que en Windows nunca esta.
    """
    try:
        with socket.create_connection((server, 43), timeout=timeout) as conn:
            conn.sendall(f"{target}\r\n".encode("utf-8", errors="replace"))
            chunks = []
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except OSError:
        return ""

def _whois_query(target: str) -> str:
    """Usa el binario si existe; si no, sockets."""
    if have("whois"):
        output = run_cmd(["whois", target])
        if output:
            return output

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    server = "whois.arin.net" if is_ip else "whois.iana.org"
    output = _whois_socket(target, server)

    # For domains IANA returns a "refer:" line pointing at the registry WHOIS
    # server; follow it to get the useful registrar/creation-date data.
    if output and not is_ip:
        for line in output.splitlines():
            if line.lower().startswith("refer:"):
                referral = line.split(":", 1)[1].strip()
                if referral:
                    detailed = _whois_socket(target, referral)
                    if detailed:
                        return detailed
                break
    return output

def whois_lookup(domain: str) -> dict[str, str]:
    output = _whois_query(domain)
    if not output:
        return {"raw": ""}

    fields: dict[str, str] = {"raw": output[:2000]}
    patterns = [
        "Registrar", "Creation Date", "Registry Expiry Date",
        "Name Server", "Registrant Organization", "Registrant Country",
        "Admin Organization", "Tech Organization",
        "OrgName", "NetRange", "CIDR",
    ]

    for line in output.split("\n"):
        for pattern in patterns:
            if line.lower().startswith(pattern.lower()) and ":" in line:
                key = pattern.lower().replace(" ", "_")
                val = line.split(":", 1)[1].strip()
                if val and val != "REDACTED FOR PRIVACY":
                    fields[key] = val

    return fields

def asn_lookup(ip_address: str) -> dict[str, Any]:
    output = _whois_query(ip_address)
    if not output:
        return {}

    result: dict[str, Any] = {}
    for line in output.split("\n"):
        for prefix in ["OriginAS", "ASNumber", "ASN"]:
            if line.lower().startswith(prefix.lower()) and ":" in line:
                result["asn"] = line.split(":", 1)[1].strip()
        if "OrgName" in line and ":" in line:
            result["org"] = line.split(":", 1)[1].strip()
        if "CIDR" in line and ":" in line:
            result["cidr"] = line.split(":", 1)[1].strip()
        if "Country" in line and ":" in line and "org" not in result:
            result["country"] = line.split(":", 1)[1].strip()

    return result
