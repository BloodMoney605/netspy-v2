#!/usr/bin/env python3
"""Detecta nombres usados sin haberlos importado o definido."""
import ast, builtins, pathlib, sys

BIEN = set(dir(builtins)) | {
    "__name__", "__file__", "__doc__", "__package__", "__spec__",
    "__loader__", "__builtins__",
}


def definidos_de(arbol):
    out = set()
    for n in ast.walk(arbol):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = n.args
                for x in a.args + a.kwonlyargs + a.posonlyargs:
                    out.add(x.arg)
                if a.vararg:
                    out.add(a.vararg.arg)
                if a.kwarg:
                    out.add(a.kwarg.arg)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            out.add(n.id)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                if a.name != "*":
                    out.add((a.asname or a.name).split(".")[0])
        elif isinstance(n, ast.ExceptHandler) and n.name:
            out.add(n.name)
        elif isinstance(n, ast.comprehension):
            for t in ast.walk(n.target):
                if isinstance(t, ast.Name):
                    out.add(t.id)
        elif isinstance(n, ast.Lambda):
            a = n.args
            for x in a.args + a.kwonlyargs + a.posonlyargs:
                out.add(x.arg)
            if a.vararg:
                out.add(a.vararg.arg)
            if a.kwarg:
                out.add(a.kwarg.arg)
    return out


def main():
    raiz = pathlib.Path(__file__).resolve().parent.parent
    fallos = 0
    objetivos = sorted(raiz.glob("lib/**/*.py")) + [raiz / "netspy.py", raiz / "install.py"]
    for f in objetivos:
        if not f.exists():
            continue
        arbol = ast.parse(f.read_text(encoding="utf-8"))
        globals_ = set(BIEN)
        for n in ast.walk(arbol):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    if a.name != "*":
                        globals_.add((a.asname or a.name).split(".")[0])
        faltan = sorted(
            {n.id for n in ast.walk(arbol) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
            - globals_ - definidos_de(arbol)
        )
        if faltan:
            print(f"{f.relative_to(raiz)}: sin definir -> {faltan}")
            fallos += 1
    if fallos:
        print(f"\n{fallos} archivo(s) con nombres sin definir")
        return 1
    print("sin nombres sin definir")
    return 0


if __name__ == "__main__":
    sys.exit(main())
