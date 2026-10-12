"""Cambio de direccion MAC.

Solo en Linux y macOS. En Windows hacen falta utilidades del driver, asi que
se avisa y se sigue.
"""

from __future__ import annotations

import os

from pathlib import Path

from cli.salida import C, phase_ok, say, warn
from netspy_env import IS_MACOS, IS_WINDOWS, run

# MAC original, para restaurar si se cambia.
_original_mac: str | None = None
_spoofed_iface: str | None = None


STEALTH_LEVEL = 0

def apply_stealth(choice: str) -> None:
    global STEALTH_LEVEL, STEALTH_DESC
    mapping = {
        "1": (1, "MAC spoof + randomized delays + fake user-agent"),
        "2": (2, "Randomized delays + fake user-agent"),
        "3": (0, "cambio de MAC"),
    }
    STEALTH_LEVEL, STEALTH_DESC = mapping.get(choice, (0, "none"))
    os.environ["NETSPY_STEALTH"] = str(STEALTH_LEVEL)

def default_interface() -> str | None:
    """Busca la interfaz de la ruta por defecto."""
    if IS_WINDOWS:
        # `route print` parsing is locale-dependent; PowerShell is not always
        # available either, so fall back to asking the socket subsystem.
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            name = None
            try:
                import psutil  # type: ignore
            except ImportError:
                psutil = None
            if psutil:
                for net_if, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET and addr.address == s.getsockname()[0]:
                            name = net_if
            s.close()
            return name
        except Exception:
            return None

    if IS_MACOS:
        result = run(["route", "-n", "get", "default"], timeout=10)
        if result and result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("interface:"):
                    return line.split(":", 1)[1].strip()
        return None

    result = run(["ip", "route", "show", "default"], timeout=10)
    if result and result.returncode == 0:
        parts = result.stdout.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return None

def read_mac(iface: str) -> str | None:
    if not IS_WINDOWS:
        path = Path("/sys/class/net") / iface / "address"
        if path.exists():
            try:
                return path.read_text(encoding="utf-8").strip()
            except OSError:
                pass

    result = run(["ipconfig", "getifaddr", iface] if IS_MACOS else ["ip", "link", "show", iface], timeout=10)
    if result and result.returncode == 0:
        out = result.stdout
        if IS_MACOS:
            return out.strip() or None
        marker = "link/ether "
        if marker in out:
            return out.split(marker, 1)[1].split()[0]
    return None

def set_mac(iface: str, mac: str) -> bool:
    """Cambia la MAC con la herramienta que tenga el sistema."""
    try:
        if IS_MACOS:
            down = run(["sudo", "ifconfig", iface, "down"], timeout=15)
            if down is None or down.returncode != 0:
                return False
            up = run(["sudo", "ifconfig", iface, "ether", mac, "up"], timeout=15)
            return up is not None and up.returncode == 0

        if IS_WINDOWS:
            # Changing the MAC on Windows needs a driver-specific tool
            # (nircmd, macshift, or a vendor NIC utility). Not bundled.
            return False

        down = run(["sudo", "ip", "link", "set", "dev", iface, "down"], timeout=15)
        if down is None or down.returncode != 0:
            return False
        setr = run(["sudo", "ip", "link", "set", "dev", iface, "address", mac], timeout=15)
        up = run(["sudo", "ip", "link", "set", "dev", iface, "up"], timeout=15)
        ok = setr is not None and setr.returncode == 0 and up is not None and up.returncode == 0
        return ok
    except KeyboardInterrupt:
        raise
    except Exception:
        return False

def spoof_mac() -> None:
    global _original_mac, _spoofed_iface

    if IS_WINDOWS:
        warn("En Windows el cambio de MAC no es automatico, se salta")
        return

    iface = default_interface()
    if not iface:
        warn("no se encontro interfaz de red, se salta el cambio de MAC")
        return

    original = read_mac(iface)
    if not original:
        warn(f"no se pudo leer la MAC de {iface}, skipping")
        return

    import secrets

    new_mac = "02:" + ":".join(
        f"{secrets.randbelow(256):02x}" for _ in range(5)
    )

    warn(f"cambiando la MAC en {iface}: {original} -> {new_mac}")
    if set_mac(iface, new_mac):
        _original_mac, _spoofed_iface = original, iface
        phase_ok("MAC cambiada")
    else:
        warn("no se pudo cambiar la MAC (hace falta administrador o sudo)")

def cleanup_stealth() -> None:
    global _original_mac, _spoofed_iface
    if _original_mac and _spoofed_iface:
        warn(f"restoring MAC on {_spoofed_iface}")
        if set_mac(_spoofed_iface, _original_mac):
            phase_ok("MAC restaurada")
        else:
            warn("no se pudo restaurar la MAC")
        _original_mac = None
        _spoofed_iface = None


# --------------------------------------------------------------------------
# interactive menu
# --------------------------------------------------------------------------
