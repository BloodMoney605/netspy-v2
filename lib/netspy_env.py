#!/usr/bin/env python3
"""Lo que cambia segun el sistema operativo.

Directorios de datos, busqueda de binarios, subprocesos que no fallan por la
codificacion y deteccion de terminal.

Se llama netspy_env y no platform porque lib/ esta en el sys.path de los
entrypoints, y ahi un modulo platform taparia el de la biblioteca estandar.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# --------------------------------------------------------------------------
# root discovery
# --------------------------------------------------------------------------

#: Repository root (the directory that contains lib/, config/ and LICENSE).
ROOT = Path(__file__).resolve().parent.parent

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


# --------------------------------------------------------------------------
# data directories
# --------------------------------------------------------------------------


def data_dir() -> Path:
    """Directorio de datos del usuario.

    Se respeta $NETSPY_HOME, si no la ruta nativa del sistema, y como ultimo
    recurso ~/.netspy de versiones viejas.
    """
    override = os.environ.get("NETSPY_HOME")
    if override:
        return Path(override).expanduser()

    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "netspy"
    elif IS_MACOS:
        return Path.home() / "Library" / "Application Support" / "netspy"

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "netspy"

    home_netspy = Path.home() / ".netspy"
    if home_netspy.exists():
        # Preserve data from previous versions of NetSpy.
        return home_netspy
    return Path.home() / ".local" / "share" / "netspy"


def ensure_data_dir() -> Path:
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


def tmp_dir() -> Path:
    """Carpeta temporal para los archivos de entrada de las herramientas."""
    override = os.environ.get("NETSPY_TMP")
    path = Path(override).expanduser() if override else data_dir() / "tmp"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cve_db_path() -> Path:
    return data_dir() / "cve.db"


def config_path() -> Path:
    """Config activa: $NETSPY_CONFIG, luego la del usuario, luego la del repo."""
    override = os.environ.get("NETSPY_CONFIG")
    if override:
        return Path(override).expanduser()

    user_cfg = data_dir() / "config.yaml"
    if user_cfg.exists():
        return user_cfg

    return ROOT / "config" / "default.yaml"


def output_dir(name: str) -> Path:
    """Carpeta de resultados.

    Va primero <repo>/output, despues el directorio actual y al final el temp
    del sistema, que siempre se puede escribir. Sin ese ultimo, una
    instalacion de solo lectura en C:\\Program Files fallaria con un
    PermissionError seco.
    """
    candidates = [ROOT / "output", Path.cwd() / "output"]

    for base in candidates:
        try:
            base.mkdir(parents=True, exist_ok=True)
            if os.access(base, os.W_OK):
                return base / name
        except OSError:
            continue

    # Last resort: the OS temp dir is writable by definition.
    return Path(tempfile.gettempdir()) / "netspy-output" / name


def expand_config_path(value: str) -> Path:
    """Expande una ruta escrita en el YAML: ~, $VAR y ${NETSPY_HOME}."""
    value = os.path.expandvars(value.replace("${NETSPY_HOME}", str(data_dir())))
    return Path(value).expanduser()


# --------------------------------------------------------------------------
# external tool lookup
# --------------------------------------------------------------------------


def which(tool: str) -> str | None:
    """Busca un binario extendiendo PATH con las carpetas de usuario.

    ``go install`` y pipx instalan en ~/go/bin y ~/.local/bin, que no siempre
    estan en el PATH de un proceso abierto desde el escritorio.
    """
    found = shutil.which(tool)
    if found:
        return found

    extra_dirs = [
        data_dir() / "bin",
        Path.home() / ".local" / "bin",
        Path.home() / "go" / "bin",
        Path.home() / "sdk" / "go" / "bin",
        Path.home() / "bin",
    ]
    if IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA")
        if local:
            extra_dirs.insert(0, Path(local) / "Microsoft" / "WindowsApps")
        extra_dirs.append(Path.home() / "scoop" / "shims")
        extra_dirs.append(Path.home() / ".gem" / "ruby" / "3.2.0" / "bin")
    else:
        # RubyGems user install dir, where `gem install whatweb` lands.
        try:
            import configparser

            cfg = configparser.ConfigParser()
            cfg.read(str(Path.home() / ".gemrc"))
            if cfg.has_option("gem", "user-install") and cfg.get("gem", "user-install"):
                extra_dirs.append(Path(cfg.get("gem", "user-install")) / "bin")
        except Exception:
            pass

    names = [tool, f"{tool}.exe", f"{tool}.cmd", f"{tool}.bat"] if IS_WINDOWS else [tool]

    for directory in extra_dirs:
        for name in names:
            candidate = directory / name
            if candidate.exists():
                return str(candidate)
    return None


def have(tool: str) -> bool:
    return which(tool) is not None


def python_exe() -> str:
    """Interprete con el que se lanzan las fases."""
    return sys.executable or "python3"


# --------------------------------------------------------------------------
# subprocess
# --------------------------------------------------------------------------


def resolve_cmd(cmd: list[str]) -> list[str]:
    """Cambia el nombre pelado por la ruta completa si no esta en PATH.

    which() ya busca en ~/go/bin y similares, pero subprocess solo mira PATH:
    sin esto, una herramienta de go install pasaba el chequeo y despues
    fallaba al ejecutarse.
    """
    if not cmd:
        return cmd
    resolved = which(cmd[0])
    if resolved:
        return [resolved, *cmd[1:]]
    return cmd


def run(
    cmd: list[str],
    timeout: int | None = 30,
    capture: bool = True,
    input_extra: str | None = None,
) -> subprocess.CompletedProcess | None:
    """Ejecuta un comando con la codificacion que funciona en todos lados.

    La consola de Windows usa cp1252 por defecto y text=True tira
    UnicodeDecodeError con casi cualquier salida. Fijar UTF-8 con
    errors="replace" mantiene vivo el pipeline.

    Devuelve None si el binario no existe o expira el timeout, asi cada
    herramienta externa se puede tratar como opcional.
    """
    cmd = resolve_cmd(cmd)
    try:
        return subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            input=input_extra,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return None


def popen(
    cmd: list[str],
    **kwargs,
) -> subprocess.Popen | None:
    """Como run() pero con salida en vivo."""
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.DEVNULL)
    kwargs.setdefault("text", True)
    kwargs.setdefault("encoding", "utf-8")
    kwargs.setdefault("errors", "replace")
    cmd = resolve_cmd(cmd)
    try:
        return subprocess.Popen(cmd, **kwargs)
    except (FileNotFoundError, OSError):
        return None


def run_capture(cmd: list[str], timeout: int = 15) -> str | None:
    """stdout de un comando exitoso, o None.

    Mantiene la firma de la vieja recon.run_cmd.
    """
    result = run(cmd, timeout=timeout)
    if result is None or result.returncode != 0:
        return None
    out = (result.stdout or "").strip()
    return out or None


# --------------------------------------------------------------------------
# terminal capabilities
# --------------------------------------------------------------------------


def enable_virtual_terminal() -> bool:
    """Activa el procesamiento de secuencias ANSI en consolas viejas de Windows.

    True si se pueden emitir colores: siempre en macOS y Linux, y en Windows
    solo si la consola efectivamente lo habilito. Si no se puede, el que llama
    tiene que apagar los colores: si no, se imprime [0;32m como texto.
    """
    if not IS_WINDOWS:
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle in (0, -1, None):
            return False
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        if kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING):
            return True
        return False
    except Exception:
        return False


def colors_enabled(stream=None) -> bool:
    """True when ANSI colours should be emitted."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("NETSPY_NO_COLOR") or os.environ.get("NETSPY_COLOR") == "0":
        return False
    stream = stream or sys.stdout
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if IS_WINDOWS:
        return os.environ.get("TERM") != "dumb"
    return True


def is_interactive(stream=None) -> bool:
    """True si stdout es un terminal de verdad.

    Las barras se repintan con \\r, y al redirigir a un archivo eso deja una
    pared de lineas repetidas. Con esto se desactivan.
    """
    stream = stream or sys.stdout
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def utf8_output() -> None:
    """Force UTF-8 stdout/stderr so box art survives a cp1252 console."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------


#: Device names Windows refuses to use as a file or directory name, even with
#: an extension (``CON.txt`` is still invalid).
WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def objetivo_valido(valor: str) -> bool:
    """True si el valor es un nombre de host o una IP, y nada mas.

    Los objetivos llegan desde la linea de comandos hasta argumentos de nmap y
    httpx. Como los subprocesos se lanzan con lista de argumentos no hay
    inyeccion de shell, pero un valor que empieza con "-" lo toma la herramienta
    como opcion: ``--target -oG`` haria que nmap escriba su salida en un
    archivo. Por eso se rechaza cualquier cosa que no sea un host o una IP.
    """
    v = valor.strip()
    if not v or len(v) > 253:
        return False
    if v.startswith("-"):
        return False

    # IPv4 o IPv6
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        pass

    # Nombre de host: etiquetas alfanumericas separadas por puntos.
    if v.endswith("."):
        v = v[:-1]
    etiqueta = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    if not re.fullmatch(rf"{etiqueta}(?:\.{etiqueta})*", v):
        return False
    return True


def sanitize_domain(domain: str) -> str:
    """Deja un dominio limpio que se pueda usar como carpeta."""
    d = domain.strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0]
    d = d.split(":", 1)[0]
    if d.lower().startswith("www."):
        d = d[4:]

    # The result becomes a directory name, so it must be valid on Windows too.
    # Trailing dots and spaces are stripped there as well.
    d = d.rstrip(". ")
    if not d:
        return "target"
    if d.split(".")[0].lower() in WINDOWS_RESERVED or d.lower() in WINDOWS_RESERVED:
        return f"{d}-target"
    # Reject anything still illegal in a Windows path.
    if re.search(r'[<>:"\\|?*\x00-\x1f]', d):
        return "target"
    return d


def platform_label() -> str:
    """Human-readable OS/arch string used by ``netspy doctor``."""
    import platform as _platform

    system = _platform.system() or sys.platform
    machine = _platform.machine() or "unknown"
    if IS_MACOS:
        system = "macOS"
    return f"{system} {machine}"