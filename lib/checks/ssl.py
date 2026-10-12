"""Auditoria SSL: expiracion de certificado y protocolos habilitados."""

from __future__ import annotations

import os
from typing import Any

from netspy_env import run


def ssl_audit(targets: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()

    for target in targets:
        if ":" not in target:
            continue

        host, port = target.split(":")
        if not port.isdigit():
            continue

        if int(port) not in (443, 8443, 465, 993, 995):
            continue

        host_key = f"{host}:{port}"
        if host_key in seen_hosts:
            continue
        seen_hosts.add(host_key)

        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-connect_timeout", "5",
        ]

        try:
            result = run(cmd, timeout=10, input_extra="QUIT\n")
            if result is None:
                continue
            output = (result.stdout or "") + (result.stderr or "")

            for line in output.split("\n"):
                if "notAfter" in line:
                    expiry = line.split("=")[-1].strip()
                    findings.append({
                        "type": "ssl-cert",
                        "host": host_key,
                        "issue": "certificate_expiry",
                        "detail": f"certificate expires: {expiry}",
                        "severity": "INFO",
                    })

            for proto in ["-ssl3", "-tls1", "-tls1_1"]:
                check = run(
                    ["openssl", "s_client", proto, "-connect", f"{host}:{port}",
                     "-servername", host, "-connect_timeout", "3"],
                    timeout=8, input_extra="QUIT\n",
                )
                if check is None:
                    continue
                if "CONNECTED" in (check.stdout or "") + (check.stderr or "") and "alert" not in ((check.stdout or "") + (check.stderr or "")).lower():
                    proto_name = proto.lstrip("-").upper()
                    findings.append({
                        "type": "ssl-proto",
                        "host": host_key,
                        "issue": f"weak_protocol_{proto_name}",
                        "detail": f"{proto_name} is enabled (deprecated)",
                        "severity": "MEDIUM",
                    })

        except (OSError, ValueError) as exc:
            if os.environ.get("NETSPY_DEBUG") in ("1", "true", "yes"):
                print(f"      [debug] ssl {host}:{port}: {exc}")

    return findings
