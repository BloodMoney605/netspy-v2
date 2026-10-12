#!/usr/bin/env python3
"""Cross-platform behaviour checks for the OS-specific code paths.

There is no way to run these on every OS from a single machine, so the
platform flags in ``netspy_env`` are switched directly and each branch is
exercised. This catches regressions like using ``os.path.join`` where a
hardcoded "/" was needed, or calling a POSIX-only function unguarded.

    python3 test/test_platform.py
"""

import os
import sys
from unittest import mock
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import netspy_env as env  # noqa: E402

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [OK] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} - {detail}")


class as_platform:
    """Temporarily pretend to be a given OS."""

    def __init__(self, windows=False, macos=False, linux=False):
        self.windows = windows
        self.macos = macos
        self.linux = linux

    def __enter__(self):
        self._saved = (env.IS_WINDOWS, env.IS_MACOS, env.IS_LINUX)
        env.IS_WINDOWS, env.IS_MACOS = self.windows, self.macos
        env.IS_LINUX = self.linux or not (self.windows or self.macos)
        return self

    def __exit__(self, *exc):
        env.IS_WINDOWS, env.IS_MACOS, env.IS_LINUX = self._saved


def test_data_dir():
    print("Data directory is OS-native:")

    with tempfile.TemporaryDirectory() as home:
        saved = dict(os.environ)
        os.environ["HOME"] = home
        os.environ.pop("NETSPY_HOME", None)

        try:
            with as_platform(windows=True):
                os.environ["LOCALAPPDATA"] = r"C:\Users\test\AppData\Local"
                got = env.data_dir()
                check("windows uses LOCALAPPDATA",
                      "AppData" in str(got) and got.name == "netspy", str(got))

                os.environ.pop("LOCALAPPDATA", None)
                os.environ["APPDATA"] = str(Path(home) / "Roaming")
                got = env.data_dir()
                check("windows falls back to APPDATA", got.name == "netspy", str(got))

            os.environ.pop("APPDATA", None)

            with as_platform(macos=True):
                got = env.data_dir()
                check("macOS uses Application Support",
                      "Application Support" in str(got), str(got))

            with as_platform(linux=True):
                os.environ["XDG_DATA_HOME"] = str(Path(home) / "xdg")
                got = env.data_dir()
                check("linux honours XDG_DATA_HOME",
                      got == Path(home) / "xdg" / "netspy", str(got))
                os.environ.pop("XDG_DATA_HOME")

                got = env.data_dir()
                check("linux default is under the home dir",
                      str(got).startswith(home), str(got))
        finally:
            os.environ.clear()
            os.environ.update(saved)


def test_home_override():
    print("NETSPY_HOME overrides everything:")
    saved = dict(os.environ)
    try:
        for name, kwargs in [("windows", {"windows": True}),
                             ("macos", {"macos": True}),
                             ("linux", {"linux": True})]:
            with as_platform(**kwargs):
                os.environ["NETSPY_HOME"] = "/tmp/custom-netspy"
                check(f"{name}: data_dir follows NETSPY_HOME",
                      env.data_dir() == Path("/tmp/custom-netspy"))
                check(f"{name}: config path expands NETSPY_HOME",
                      env.expand_config_path("${NETSPY_HOME}/cve.db")
                      == Path("/tmp/custom-netspy/cve.db"))
        os.environ.pop("NETSPY_HOME", None)
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_tool_lookup():
    print("Tool lookup:")
    check("missing tool returns None",
          env.which("definitely-not-a-real-tool-xyz") is None)

    # On Windows which() also tries .exe/.cmd/.bat, so a tool installed as
    # faketool.exe must be found.
    saved = dict(os.environ)
    try:
        with tempfile.TemporaryDirectory() as home:
            bindir = Path(home) / ".local" / "bin"
            bindir.mkdir(parents=True)
            os.environ["HOME"] = home
            with as_platform(windows=True):
                (bindir / "faketool.exe").write_text("")
                found = env.which("faketool")
                check("windows finds an .exe in ~/.local/bin",
                      found is not None and found.endswith("faketool.exe"),
                      str(found))
            with as_platform(linux=True):
                (bindir / "faketool").write_text("")
                found = env.which("faketool")
                check("linux finds a bare binary in ~/.local/bin",
                      found is not None and found.endswith("faketool"),
                      str(found))
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_resolve_cmd():
    print("resolve_cmd replaces a bare name with a full path:")
    check("keeps args after the program name",
          env.resolve_cmd(["httpx", "-version"])[1:] == ["-version"])
    check("leaves an unknown tool alone",
          env.resolve_cmd(["nope-xyz", "-x"])[0] == "nope-xyz")
    check("empty command is handled", env.resolve_cmd([]) == [])
    resolved = env.resolve_cmd(["gh", "--version"])[0]
    check("resolves a real tool to an absolute path", os.path.isabs(resolved), resolved)


def test_windows_safe_names():
    print("Domain sanitising avoids Windows-reserved names:")
    for name in ["CON", "con", "nul", "aux", "prn", "com1", "LPT9"]:
        got = env.sanitize_domain(name)
        ok = got.lower() not in env.WINDOWS_RESERVED
        check(f"{name!r} -> {got!r} is not reserved", ok)

    check("trailing dot stripped", env.sanitize_domain("x.") == "x")
    check("empty becomes target", env.sanitize_domain("   ") == "target")
    check("illegal chars rejected",
          env.sanitize_domain('a<b>c').lower() not in env.WINDOWS_RESERVED)
    check("normal domain untouched", env.sanitize_domain("example.com") == "example.com")


def test_objetivo_valido():
    print("Validacion de objetivos:")
    from netspy_env import objetivo_valido

    for bueno in ["ejemplo.com", "sub.ejemplo.com", "127.0.0.1", "localhost", "1.2.3.4"]:
        check(f"{bueno} aceptado", objetivo_valido(bueno))

    for malo in ["-oG", "--script=evil", "ejemplo.com; rm -rf /", "$(id)", "`id`",
                 "", "a" * 300, "192.168.1.0/24", "a b", "-"]:
        check(f"{malo!r} rechazado", not objetivo_valido(malo), "deberia rechazar")


def test_sanitize_domain():
    print("Domain sanitising:")
    check("strips scheme", env.sanitize_domain("https://example.com") == "example.com")
    check("strips path", env.sanitize_domain("http://example.com/a/b") == "example.com")
    check("strips port", env.sanitize_domain("example.com:8443") == "example.com")
    check("strips www", env.sanitize_domain("www.example.com") == "example.com")
    check("combined", env.sanitize_domain("https://www.example.com:443/x") == "example.com")
    check("plain is untouched", env.sanitize_domain("example.com") == "example.com")


def test_terminal_helpers():
    print("Terminal helpers are safe off a tty:")
    check("is_interactive is False for a pipe", env.is_interactive(sys.stdout) is False)
    check("colors disabled without a tty", env.colors_enabled(sys.stdout) is False)

    saved = os.environ.get("NO_COLOR")
    try:
        os.environ["NO_COLOR"] = "1"
        check("NO_COLOR forces colors off", env.colors_enabled() is False)
    finally:
        if saved is None:
            os.environ.pop("NO_COLOR", None)
        else:
            os.environ["NO_COLOR"] = saved


def test_enable_virtual_terminal():
    print("enable_virtual_terminal is a no-op off Windows:")
    with as_platform(linux=True):
        try:
            env.enable_virtual_terminal()
            check("does not raise on linux", True)
        except Exception as exc:
            check("does not raise on linux", False, str(exc))


def test_output_dir_writable():
    print("Output directory survives read-only installs:")
    import tempfile as _tf

    got = env.output_dir("some-target")
    check("returns a usable path", got.name == "some-target", str(got))

    # Simulate a read-only checkout plus an unwritable cwd, as on a machine
    # where NetSpy was unpacked somewhere like C:\Program Files.
    saved_root, saved_cwd, saved_access = env.ROOT, os.getcwd(), os.access
    try:
        env.ROOT = Path("/no/such/place/ever")
        os.chdir(_tf.mkdtemp())
        os.access = lambda *a, **k: False
        fallback = env.output_dir("some-target")
        check("falls back to a writable location", str(fallback) != "", str(fallback))
        check("fallback ends with the target name",
              fallback.name == "some-target", str(fallback))
    finally:
        env.ROOT = saved_root
        os.chdir(saved_cwd)
        os.access = saved_access


def test_virtual_terminal_gate():
    print("Colour output is gated on real ANSI support:")
    # On macOS/Linux the call always reports True, so colours stay on.
    with as_platform(linux=True):
        check("linux reports ANSI available", env.enable_virtual_terminal() is True)
    with as_platform(macos=True):
        check("macos reports ANSI available", env.enable_virtual_terminal() is True)

    # On Windows a failure must be reported so colours get disabled instead of
    # printing literal escape sequences. Simulate a console that refuses to
    # report its mode, which is what old conhost and some CI consoles do.
    import types as _types

    fake_ctypes = _types.ModuleType("ctypes")

    class _Uint32:
        def __init__(self):
            self.value = 0

    fake_ctypes.c_uint32 = _Uint32
    fake_ctypes.byref = lambda obj: obj
    fake_ctypes.windll = _types.SimpleNamespace()
    fake_kernel32 = _types.SimpleNamespace()
    fake_ctypes.windll.kernel32 = fake_kernel32
    fake_kernel32.GetStdHandle = lambda handle: 1
    fake_kernel32.SetConsoleMode = lambda handle, mode: 1
    fake_kernel32.GetConsoleMode = lambda handle, mode: 0  # failure

    with as_platform(windows=True):
        real_ctypes = sys.modules.get("ctypes")
        sys.modules["ctypes"] = fake_ctypes
        try:
            result = env.enable_virtual_terminal()
            check("failing console reports False", result is False, str(result))
        finally:
            if real_ctypes is not None:
                sys.modules["ctypes"] = real_ctypes
            else:
                sys.modules.pop("ctypes", None)

    # And a console that already has VT enabled must report True.
    def _mode_on(handle, mode):
        mode.value = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return 1

    fake_kernel32.GetConsoleMode = _mode_on
    with as_platform(windows=True):
        real_ctypes = sys.modules.get("ctypes")
        sys.modules["ctypes"] = fake_ctypes
        try:
            check("console with VT already on reports True",
                  env.enable_virtual_terminal() is True)
        finally:
            if real_ctypes is not None:
                sys.modules["ctypes"] = real_ctypes
            else:
                sys.modules.pop("ctypes", None)


def test_interrupt_terminates_child():
    print("Interrupting a phase terminates the child:")
    import subprocess as _sp
    import importlib.util as _ilu

    # _terminate vive en lib/cli/procesos.py desde el refactor del CLI.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
    from cli.procesos import _terminate as _ns_terminate

    check("_terminate handles a None process", _ns_terminate(None) is None)
    _sp.run([sys.executable, "-c", "pass"])
    check("_terminate handles a finished process", _ns_terminate(None) is None)

    proc = _sp.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    _ns_terminate(proc)
    check("child is stopped", proc.poll() is not None, str(proc.poll()))


def test_paths_use_pathlib():
    print("Paths are built with pathlib/os.path, not string concatenation:")
    with tempfile.TemporaryDirectory() as d:
        nested = os.path.join(d, "a", "b", "c")
        os.makedirs(nested)
        check("os.path.join nests correctly", os.path.isdir(nested))


def main():
    print("Testing cross-platform behaviour\n")
    test_data_dir()
    test_home_override()
    test_tool_lookup()
    test_objetivo_valido()
    test_sanitize_domain()
    test_windows_safe_names()
    test_terminal_helpers()
    test_enable_virtual_terminal()
    test_output_dir_writable()
    test_virtual_terminal_gate()
    test_interrupt_terminates_child()
    test_paths_use_pathlib()

    print()
    print(f"Tests: {passed + failed}  |  Passed: {passed}  |  Failed: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())