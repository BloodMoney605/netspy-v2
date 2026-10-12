#!/usr/bin/env python3
"""Instalacion de herramientas externas.

``netspy doctor`` pasa por aca. Ninguna es obligatoria: cada fase degrada
sola, asi que un fallo de instalacion no corta el comando.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

from netspy_env import IS_WINDOWS, have


@dataclass
class Tool:
    name: str
    required: bool = False
    # package name per detected package manager
    apt: str = ""
    dnf: str = ""
    pacman: str = ""
    zypper: str = ""
    apk: str = ""
    brew: str = ""
    winget: str = ""
    choco: str = ""
    gem: str = ""
    go_install: str = ""
    notes: str = field(default_factory=str)


TOOLS: list[Tool] = [
    Tool(
        name="nmap",
        required=True,
        apt="nmap",
        dnf="nmap",
        pacman="nmap",
        zypper="nmap",
        apk="nmap",
        brew="nmap",
        winget="Insecure.Nmap",
        choco="nmap",
    ),
    Tool(
        name="openssl",
        required=True,
        apt="openssl",
        dnf="openssl",
        pacman="openssl",
        zypper="openssl",
        apk="openssl-cmp",
        brew="openssl@3",
        winget="ShiningLight.OpenSSL",
        choco="openssl",
    ),
    Tool(
        name="dig",
        required=False,
        apt="dnsutils",
        dnf="bind-utils",
        pacman="bind",
        zypper="bind-utils",
        apk="bind-tools",
        brew="bind",
        choco="bind-toolsonly",
        notes="para registros TXT y CNAME en la fase de recon",
    ),
    Tool(
        name="whois",
        required=False,
        apt="whois",
        dnf="whois",
        pacman="whois",
        apk="whois",
        brew="whois",
        notes="no hay paquete para Windows; el WHOIS se saltea",
    ),
    Tool(
        name="whatweb",
        required=False,
        brew="whatweb",
        winget="whatweb",
        choco="whatweb",
        notes="fingerprint profundo; con brew o desde el repo de mitsuhiko",
    ),
    Tool(
        name="httpx",
        required=False,
        brew="httpx",
        go_install="github.com/projectdiscovery/httpx/cmd/httpx@latest",
        notes="sondeo HTTP",
    ),
    Tool(
        name="nuclei",
        required=False,
        brew="nuclei",
        go_install="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        notes="plantillas de escaneo, usa mucha memoria",
    ),
]


# --------------------------------------------------------------------------
# package manager detection
# --------------------------------------------------------------------------


def detect_manager() -> str | None:
    """Gestor de paquetes disponible, o None."""
    if IS_WINDOWS:
        for candidate in ("winget", "choco", "scoop"):
            if have(candidate):
                return candidate
        return None

    if have("brew"):
        return "brew"
    if have("apt-get"):
        return "apt"
    if have("dnf"):
        return "dnf"
    if have("microdnf"):
        return "dnf"
    if have("yum"):
        return "dnf"
    if have("pacman"):
        return "pacman"
    if have("zypper"):
        return "zypper"
    if have("apk"):
        return "apk"
    return None


def _sudo_prefix() -> list[str]:
    """Agrega sudo si no somos root. En Windows no aplica."""
    if IS_WINDOWS:
        return []
    import os

    try:
        uid = os.geteuid()
    except AttributeError:
        return []
    return [] if uid == 0 else ["sudo"]


def _run_install(cmd: list[str]) -> bool:
    print(f"    $ {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return proc.returncode == 0
    except Exception as exc:  # pragma: no cover - environment dependent
        print(f"    [!] fallo: {exc}")
        return False


def install_with_manager(manager: str, packages: list[str]) -> bool:
    if not packages:
        return True

    sudo = _sudo_prefix()

    if manager == "apt":
        _run_install(sudo + ["apt-get", "update", "-qq"])
        return all(_run_install(sudo + ["apt-get", "install", "-y", "-qq", p]) for p in packages)
    if manager == "dnf":
        return all(_run_install(sudo + ["dnf", "install", "-y", p]) for p in packages)
    if manager == "pacman":
        # --needed avoids failing on already-installed packages.
        return all(_run_install(sudo + ["pacman", "-S", "--needed", "--noconfirm", p]) for p in packages)
    if manager == "zypper":
        return all(_run_install(sudo + ["zypper", "install", "-y", p]) for p in packages)
    if manager == "apk":
        return all(_run_install(sudo + ["apk", "add", p]) for p in packages)
    if manager == "brew":
        return all(_run_install(["brew", "install", p]) for p in packages)
    if manager == "winget":
        return all(
            _run_install(
                [
                    "winget", "install", "--id", p,
                    "-e", "--accept-source-agreements",
                    "--accept-package-agreements", "--silent",
                ]
            )
            for p in packages
        )
    if manager == "choco":
        return all(_run_install(["choco", "install", p, "-y"]) for p in packages)
    if manager == "scoop":
        return all(_run_install(["scoop", "install", p]) for p in packages)

    return False


# --------------------------------------------------------------------------
# Ruby tools
# --------------------------------------------------------------------------


def install_ruby_tools(tools: list["Tool"]) -> None:
    """Instala herramientas que se distribuyen como gemas (whatweb)."""
    gems = [t.gem for t in tools if t.gem]
    if not gems:
        return
    if not have("gem"):
        print("    [!] no se encontro RubyGems, se salta whatweb.")
        print("        Instala Ruby desde https://ruby-lang.org/ y corre 'netspy doctor' de nuevo.")
        return
    for name in gems:
        print(f"    gem install {name}")
        _run_install(["gem", "install", name, "--no-document"])


# --------------------------------------------------------------------------
# Go tools
# --------------------------------------------------------------------------


def install_go_tools(tools: list[Tool]) -> None:
    go_targets = [t.go_install for t in tools if t.go_install]
    if not go_targets:
        return

    if not have("go"):
        print("    [!] no se encontro Go, se saltan httpx y nuclei.")
        print("        Instala Go desde https://go.dev/dl/ y corre 'netspy doctor' de nuevo.")
        return

    for target in go_targets:
        print(f"    go install {target}")
        _run_install(["go", "install", target])


# --------------------------------------------------------------------------
# python deps
# --------------------------------------------------------------------------


def install_python_deps() -> None:
    import sys

    print("    instalando PyYAML")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "pyyaml"],
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except Exception as exc:  # pragma: no cover
        print(f"    [!] pip fallo: {exc}")


# --------------------------------------------------------------------------
# entrypoint
# --------------------------------------------------------------------------


TOOL_BY_NAME: dict[str, Tool] = {t.name: t for t in TOOLS}


def missing_tools() -> list[Tool]:
    return [t for t in TOOLS if not have(t.name)]


def report_status() -> tuple[list[Tool], list[Tool]]:
    """Separa las que faltan en (obligatorias, opcionales)."""
    missing = missing_tools()
    required = [t for t in missing if t.required]
    optional = [t for t in missing if not t.required]
    return required, optional


def install_all() -> None:
    manager = detect_manager()
    missing = missing_tools()

    if manager is None:
        from netspy_env import platform_label

        print(f"    [!] no se encontro un gestor de paquetes en este sistema ({platform_label()}).")
        print("        Instala a mano: nmap, openssl, y opcionalmente")
        print("        dig, whois, whatweb, httpx y nuclei.")
        print("        En Windows tambien sirve: winget install Insecure.Nmap")
    else:
        print(f"    package manager: {manager}")

    packages: list[str] = []
    for tool in missing:
        pkg = getattr(tool, manager, "") if manager else ""
        if pkg:
            packages.append(pkg)

    if packages:
        print(f"    installing: {', '.join(packages)}")
        install_with_manager(manager, packages)
    elif manager:
        print("    no hay paquetes del sistema para instalar")

    install_ruby_tools(missing)
    install_go_tools(missing)
    install_python_deps()