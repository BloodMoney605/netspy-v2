"""Cada subcomando de la CLI."""

from __future__ import annotations

import shutil
from pathlib import Path

from cli.procesos import run_phase
from cli.salida import C, phase_fail, phase_info, phase_ok, say, warn
from config import cargar as load_config
import sys

from cli.idioma import tr
from cli.salida import _c
from netspy_env import (
    IS_WINDOWS,
    cve_db_path,
    config_path,
    have,
    is_interactive,
    output_dir,
    sanitize_domain,
    tmp_dir,
    which,
)


def _common_args(cfg: str, out: str, threads: str | None) -> list[str]:
    args = ["--config", cfg, "--output", out]
    if threads:
        args += ["--threads", str(threads)]
    return args


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def check_deps(needed: tuple[str, ...] = ()) -> bool:
    """Avisa de las herramientas que faltan.

    Nada es obligatorio: recon tiene resolver y whois por socket, y el
    escaneo de puertos tiene el escaner TCP propio. Por eso las faltantes se
    informan como avisos y no como errores.
    """
    from installer import TOOL_BY_NAME, TOOLS

    blocking = [TOOL_BY_NAME[n] for n in needed if n in TOOL_BY_NAME and not have(n)]
    for tool in blocking:
        phase_fail(f"falta: {tool.name}")

    if blocking:
        say(f"\n{_c(C.RED)}[!] {_c(tr('run_doctor'))}{_c(C.NC)}")
        return False

    for tool in TOOLS:
        if tool.name in needed or have(tool.name):
            continue
        detalle = tool.notes or "se omite esa parte"
        warn(f"falta la herramienta opcional {tool.name} ({detalle})")

    return True

def _resolve_output(domain: str, output: str | None) -> str:
    out = output or str(output_dir(sanitize_domain(domain)))
    Path(out).mkdir(parents=True, exist_ok=True)
    return out

def cmd_recon(domain: str, cfg: str, output: str | None, threads: str | None) -> int:
    # Recon only needs DNS/WHOIS, both of which have pure-Python fallbacks.
    if not check_deps(needed=()):
        return 1
    out = _resolve_output(domain, output)
    recon_json = Path(out) / "recon.json"
    if recon_json.exists():
        recon_json.unlink()

    rc = run_phase("recon.py", "--domain", domain, *_common_args(cfg, out, threads))

    if rc != 0 or not recon_json.exists():
        phase_fail("la fase de recon fallo o no produjo salida")
        return rc or 1

    phase_ok(f"datos de recon en {recon_json}")
    return 0

def _pipeline(domain: str, cfg: str, output: str | None, threads: str | None, title: str) -> int:
    """Fases 1-4: recon, puertos, fingerprint y CVEs."""
    if not check_deps():
        return 1

    out = _resolve_output(domain, output)
    common = _common_args(cfg, out, threads)

    say(f"{_c(C.CYAN)}{'=' * 40}{_c(C.NC)}")
    say(f"{_c(C.CYAN)} NetSpy — {title}{_c(C.NC)}")
    say(f"{_c(C.CYAN)} Objetivo: {domain}{_c(C.NC)}")
    say(f"{_c(C.CYAN)} Salida: {out}{_c(C.NC)}")
    say(f"{_c(C.CYAN)} Hilos: {threads or 'el de la config'}{_c(C.NC)}")
    say(f"{_c(C.CYAN)}{'=' * 40}{_c(C.NC)}")

    phase_info("1", "Reconocimiento (subdominios, DNS, WHOIS)")
    recon_json = Path(out) / "recon.json"
    if recon_json.exists():
        # Un recon.json viejo no debe validar la comprobacion.
        recon_json.unlink()
    if run_phase("recon.py", "--domain", domain, *common) != 0 or not recon_json.exists():
        phase_fail("la fase de recon no produjo salida")
        return 1
    phase_ok(f"datos de recon en {Path(out) / 'recon.json'}")

    targets = Path(out) / "targets.txt"
    ips = Path(out) / "ips.txt"
    if ips.exists():
        targets.write_text(ips.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        targets.write_text(domain + "\n", encoding="utf-8")

    phase_info("2", "Escaneo de puertos y servicios")
    run_phase("scan.py", "--targets", str(targets), *common)
    phase_ok(f"datos de escaneo en {Path(out) / 'ports.json'}")

    phase_info("3", "Technology fingerprinting")
    run_phase("fingerprint.py", "--input", out, *common)
    phase_ok(f"datos de fingerprint en {Path(out) / 'tech.json'}")

    phase_info("4", "Busqueda de vulnerabilidades (CVE + nuclei)")
    run_phase("vuln.py", "--input", out, *common)
    phase_ok(f"datos de vulnerabilidades en {Path(out) / 'findings.json'}")

    return 0

def cmd_audit(domain: str, cfg: str, output: str | None, threads: str | None) -> int:
    rc = _pipeline(domain, cfg, output, threads, "Audit")
    if rc != 0:
        return rc

    out = _resolve_output(domain, output)
    phase_info("5", "Armado del reporte")
    run_phase("report.py", "--input", out, "--config", cfg, "--output", out)
    phase_ok(f"reporte guardado en {Path(out) / 'report.txt'}")

    say(f"\n{_c(C.GREEN)}[+] Auditoria terminada.{_c(C.NC)}")
    say(f"  Reporte: {_c(C.CYAN)}{Path(out) / 'report.txt'}{_c(C.NC)}")
    say(f"  Datos: {_c(C.CYAN)}{out}/{_c(C.NC)}")
    return 0

def cmd_scan_full(domain: str, cfg: str, output: str | None, threads: str | None) -> int:
    rc = _pipeline(domain, cfg, output, threads, "Escaneo (sin reporte)")
    if rc != 0:
        return rc
    say(f"\n{_c(C.GREEN)}[+] Escaneo terminado.{_c(C.NC)}")
    say(f"  Datos: {_c(C.CYAN)}{_resolve_output(domain, output)}/{_c(C.NC)}")
    return 0

def cmd_scan(targets: str, cfg: str, output: str | None, threads: str | None) -> int:
    if not check_deps():
        return 1

    out = output or str(output_dir("target"))
    Path(out).mkdir(parents=True, exist_ok=True)

    archivo = Path(out) / "targets.txt"
    archivo.write_text(targets + "\n", encoding="utf-8")

    run_phase("scan.py", "--targets", str(archivo), *_common_args(cfg, out, threads))
    phase_ok(f"datos de escaneo en {Path(out) / 'ports.json'}")
    return 0


def cmd_report(directory: str, cfg: str | None = None) -> int:
    args = ["--input", directory, "--output", directory]
    if cfg:
        args += ["--config", cfg]
    run_phase("report.py", *args)
    phase_ok(f"reporte guardado en {Path(directory) / 'report.txt'}")
    return 0

def cmd_doctor() -> int:
    from installer import TOOLS, install_all, report_status

    from netspy_env import platform_label

    say(f"NetSpy doctor — {platform_label()}")
    say("")

    missing_required, missing_optional = report_status()

    for tool in TOOLS:
        status = f"{_c(C.GREEN)}esta{_c(C.NC)}" if have(tool.name) else f"{_c(C.YELLOW)}falta{_c(C.NC)}"
        req = "obligatoria" if tool.required else "opcional"
        say(f"  {tool.name:<12} {status}  ({req})")

    if not missing_required and not missing_optional:
        say(f"\n{_c(C.GREEN)}[+] No falta nada.{_c(C.NC)}")
        return 0

    say("")
    install_all()

    say("")
    required, optional = report_status()
    if required:
        for tool in required:
            phase_fail(f"todavia falta: {tool.name}")
        return 1
    if optional:
        say(f"  {_c(C.YELLOW)}[!]{_c(C.NC)} siguen faltando las opcionales: "
            f"{', '.join(t.name for t in optional)}")
    say(f"\n{_c(C.GREEN)}[+] Dependencias instaladas.{_c(C.NC)}")
    return 0

def cmd_clean() -> int:
    warn("borrando la cache de CVEs...")
    db = cve_db_path()
    if db.exists():
        try:
            db.unlink()
            say(f"  {_c(C.GREEN)}[ok]{_c(C.NC)} removed {db}")
        except OSError as exc:
            phase_fail(f"no se pudo borrar {db}: {exc}")
    else:
        say(f"  {_c(C.GREEN)}[ok]{_c(C.NC)} no CVE cache at {db}")

    tmp = tmp_dir()
    for child in tmp.glob("*"):
        try:
            if child.is_dir():
                import shutil

                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()
        except OSError:
            pass
    say(f"  {_c(C.GREEN)}[ok]{_c(C.NC)} cleared temp files in {tmp}")
    return 0

def cmd_selfcheck() -> int:
    """Diagnostica la maquina.

    Cada linea dice que encontro y si es aceptable, asi un fallo se
    identifica sin leer un traceback.
    """
    from netspy_env import (
        IS_MACOS,
        ROOT,
        config_path,
        data_dir,
        ensure_data_dir,
        platform_label,
        tmp_dir,
    )

    problems: list[str] = []
    warnings: list[str] = []

    def section(title: str) -> None:
        say(f"\n  {_c(C.BOLD)}{title}{_c(C.NC)}")

    def good(label: str, value: str) -> None:
        say(f"    {_c(C.GREEN)}ok{_c(C.NC)}       {label}: {value}")

    def warn(label: str, value: str, hint: str) -> None:
        say(f"    {_c(C.YELLOW)}warn{_c(C.NC)}     {label}: {value}")
        say(f"             -> {hint}")
        warnings.append(label)

    def bad(label: str, value: str, hint: str) -> None:
        say(f"    {_c(C.RED)}fail{_c(C.NC)}     {label}: {value}")
        say(f"             -> {hint}")
        problems.append(label)

    section("Interprete")
    version = ".".join(str(v) for v in sys.version_info[:3])
    if sys.version_info >= (3, 9):
        good("python", version)
    else:
        bad("python", version, "NetSpy needs Python 3.9 or newer")
    good("sistema", platform_label())
    good("codificacion", sys.stdout.encoding or "desconocida")
    good("ejecutable", sys.executable)

    section("Estructura")
    for name, path in [
        ("repo", ROOT),
        ("lib", ROOT / "lib"),
        ("config", config_path()),
        ("licencia", ROOT / "LICENSE"),
    ]:
        if path and Path(path).exists():
            good(name, str(path))
        else:
            bad(name, str(path), "vuelve a clonar el repo")

    section("Carpetas")
    for name, fn in [("datos", ensure_data_dir), ("temporal", tmp_dir)]:
        try:
            path = fn()
            probe = path / ".netspy-write-test"
            probe.write_text("x", encoding="utf-8")
            probe.unlink()
            good(name, str(path))
        except Exception as exc:
            bad(name, "no se puede escribir", str(exc))

    section("Configuracion")
    try:
        cfg = load_config(str(config_path()))
        if cfg:
            good("cargada", f"{len(cfg)} secciones")
            db = cfg.get("vuln", {}).get("cve_db_path", "")
            if db:
                good("cache de CVEs", db)
        else:
            warn("config", "empty", "faltan claves en config/default.yaml")
    except Exception as exc:
        bad("config", "no se pudo cargar", str(exc))

    section("Dependencias")
    try:
        import yaml  # noqa: F401

        good("pyyaml", getattr(yaml, "__version__", "installed"))
    except ImportError:
        bad("pyyaml", "missing", "corre: netspy doctor  (o: py -m pip install pyyaml)")

    for name in ("httpx", "nmap", "openssl", "whatweb", "nuclei"):
        found = which(name)
        if found:
            good(name, found)
        else:
            warn(name, "no esta", "es opcional; corre 'netspy doctor' para instalarla")

    section("NVD")
    try:
        from cve.nvd import API_KEY_ENV, con_api_key, espera_entre_peticiones

        if con_api_key():
            good("api key", f"activa ({API_KEY_ENV})")
            good("limite", f"{espera_entre_peticiones():.1f}s entre peticiones")
        else:
            warn("api key", "no configurada",
                 f"5 peticiones cada 30s. Registrate en "
                 f"https://nvd.nist.gov/developers/request-an-api-key y exporta "
                 f"{API_KEY_ENV}=tu_clave para 50 por 30s")
    except Exception as exc:
        warn("nvd", str(exc), "la fase 4 usa OSV como alternativa")

    section("Capacidades")
    try:
        import sqlite3

        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (a INTEGER)")
        con.close()
        good("sqlite", sqlite3.sqlite_version)
    except Exception as exc:
        bad("sqlite", "unavailable", str(exc))

    try:
        import socket

        socket.getaddrinfo("localhost", None)
        good("dns", "el resolver responde")
    except OSError as exc:
        warn("dns", f"no se pudo resolver localhost ({exc})", "revisa la red y el DNS")

    if not is_interactive():
        warn("terminal", "la salida no es un terminal", "sin colores, normal cuando redirigis")
    else:
        good("terminal", "interactivo")

    say("")
    if problems:
        say(f"  {_c(C.RED)}[x] {len(problems)} blocking problem(s): {', '.join(problems)}{_c(C.NC)}")
        say("      NetSpy no va a andar bien hasta que se arreglen.")
        return 1

    if warnings:
        say(f"  {_c(C.YELLOW)}[!] {len(warnings)} aviso(s). NetSpy deberia andar igual.{_c(C.NC)}")
    else:
        say(f"  {_c(C.GREEN)}[+] Todo en orden.{_c(C.NC)}")

    say("")
    say(f"  directorio de datos: {data_dir()}")
    say(f"  lanzador: netspy{' .bat' if IS_WINDOWS else ''} / python netspy.py")
    return 0

def cmd_license() -> int:
    lic = ROOT / "LICENSE"
    if lic.exists():
        say(lic.read_text(encoding="utf-8", errors="replace"))
    else:
        say("No se encontro el archivo de licencia.")
    return 0


# --------------------------------------------------------------------------
# stealth (MAC spoofing)
# --------------------------------------------------------------------------
