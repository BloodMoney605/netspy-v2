"""Ejecucion de las fases como subproceso."""

from __future__ import annotations

import subprocess

from cli.salida import C, _c
from netspy_env import IS_WINDOWS, ROOT, python_exe


def run_phase(script: str, *args: str) -> int:
    """Ejecuta una fase como subproceso.

    En Windows el hijo no recibe Ctrl+C si no esta en su propio process group,
    y una auditoria interrumpida dejaba nmap o httpx corriendo. Con Popen se
    puede terminar el hijo explicitamente.
    """
    cmd = [python_exe(), str(ROOT / "lib" / script), *args]

    popen_kwargs: dict = {}
    if IS_WINDOWS:
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    proc = None
    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
        return proc.wait()
    except KeyboardInterrupt:
        _terminate(proc)
        raise
    except Exception as exc:  # pragma: no cover
        _terminate(proc)
        print(f"  {_c(C.RED)}[!]{_c(C.NC)} no se pudo arrancar {script}: {exc}")
        return 1

def _terminate(proc) -> None:
    """Frena el subproceso de una fase, y lo mata si no hace caso."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
    except Exception:
        pass
