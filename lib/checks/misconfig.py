"""Configuraciones inseguras frecuentes en landings por defecto."""

from __future__ import annotations

from typing import Any

from common import t


def check_misconfigs(tech_data: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for host_entry in tech_data.get("alive_hosts", []):
        server = host_entry.get("server", "").lower()
        url = host_entry.get("url", "")

        if "apache" in server or "nginx" in server or "iis" in server:
            pass

        title = host_entry.get("title", "")
        default_titles = ["index of /", "apache2 ubuntu default page",
                          "welcome to nginx", "iis windows server",
                          "tomcat", "jboss", "websphere"]

        for default_title in default_titles:
            if default_title in title.lower():
                is_sensitive = any(sensitive in title.lower() for sensitive in [
                    "admin", "backup", "config", "database", "db", "etc",
                    "passwd", "shadow", "secret", "key", "credential",
                    "env", "git", "svn", "htpasswd", "wp-config",
                ])
                findings.append({
                    "type": "misconfig",
                    "host": url,
                    "issue": "default_landing_page",
                    "detail": f"default/landing page detected: '{title}'",
                    "severity": "HIGH" if is_sensitive else "LOW",
                })

    return findings
