#!/usr/bin/env python3
"""Cross-platform NetSpy installer.

Works on Linux, macOS and Windows with the standard interpreters:

    python3 install.py        # Linux / macOS
    py install.py             # Windows
    python install.py         # any platform that has python on PATH

Installing the external tools is delegated to ``netspy doctor``, which picks
the right package manager for the host (apt, dnf, pacman, zypper, apk, brew,
winget, choco or scoop).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "lib"))

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"

GREEN = "\033[0;32m" if not IS_WINDOWS else ""
YELLOW = "\033[0;33m" if not IS_WINDOWS else ""
NC = "\033[0m" if not IS_WINDOWS else ""

MIN_PYTHON = (3, 10)


def ok(msg: str) -> None:
    print(f"{GREEN}[+]{NC} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[!]{NC} {msg}")


def fail(msg: str) -> None:
    print(f"[x] {msg}")


def check_python() -> bool:
    if sys.version_info < MIN_PYTHON:
        fail(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ se necesita, "
            f"found {sys.version_info.major}.{sys.version_info.minor}"
        )
        return False
    ok(f"Python {sys.version.split()[0]}")
    return True


def install_python_deps() -> None:
    print("[*] installing Python packages...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "pyyaml"],
            check=False,
        )
        ok("PyYAML instalado")
    except Exception as exc:
        warn(f"no se pudo instalar PyYAML automaticamente: {exc}")
        print(f"    run manually: {sys.executable} -m pip install pyyaml")


def create_data_dir() -> None:
    from netspy_env import ensure_data_dir, tmp_dir

    data = ensure_data_dir()
    tmp = tmp_dir()
    ok(f"directorio de datos: {data}")
    ok(f"directorio temporal: {tmp}")


def link_launcher() -> None:
    """Pone netspy en el PATH para poder llamarlo de cualquier lado."""
    if IS_WINDOWS:
        ok("correlo con: python netspy.py   (o agrega el repo al PATH)")
        return

    target_dirs = []
    user_bin = Path.home() / ".local" / "bin"
    try:
        target_dirs.append(user_bin)
    except Exception:
        pass
    target_dirs += [Path("/usr/local/bin"), Path.home() / "bin"]

    src = ROOT / "netspy.py"
    for directory in target_dirs:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            dest = directory / "netspy"
            if dest.exists() or dest.is_symlink():
                dest.unlink()
            dest.symlink_to(src)
            if not any(directory == Path(p) for p in os.environ.get("PATH", "").split(os.pathsep)):
                warn(f"{directory} no esta en el PATH, agregalo a mano")
            ok(f"linked {dest}")
            return
        except (OSError, PermissionError):
            continue

    warn("no se pudo enlazar el lanzador; correlo directo con: python netspy.py")


def install_tools() -> None:
    print("[*] revisando herramientas externas (nmap, openssl, ...)...")
    try:
        from installer import install_all
        from netspy_env import platform_label

        print(f"    system: {platform_label()}")
        install_all()
    except Exception as exc:
        warn(f"instalacion automatica no disponible: {exc}")
        print("    despues con: netspy doctor")


def main() -> int:
    parser = argparse.ArgumentParser(description="Instala NetSpy")
    parser.add_argument("--no-tools", action="store_true", help="skip external tool installation")
    parser.add_argument("--no-link", action="store_true", help="no tocar el PATH")
    args = parser.parse_args()

    print("[*] NetSpy installer")
    try:
        from netspy_env import platform_label

        target = platform_label()
    except Exception:
        # platform_label() already avoids os.uname(), which does not exist on
        # Windows, so this fallback must too.
        target = sys.platform
    print(f"    sistema: {target}")
    print()

    if not check_python():
        return 1

    create_data_dir()
    install_python_deps()

    if not args.no_tools:
        install_tools()

    if not args.no_link:
        link_launcher()

    print()
    ok("installation complete.")
    print()
    print("Next steps:")
    print("    netspy doctor              verify dependencies")
    print("    netspy audit --domain ejemplo.com")
    print("    netspy                      interactive menu")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)