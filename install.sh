#!/usr/bin/env bash
# Instalador de NetSpy para Linux y macOS.
#
#     ./install.sh              instala todo
#     ./install.sh --no-tools   saltea las herramientas externas
#
# Este wrapper delega en install.py, que es el que anda en los tres sistemas.
# Queda para los que ya lo usan asi.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PY="$candidate"
        break
    fi
done

if [ -z "$PY" ]; then
    echo "[x] No se encontro Python 3.9 o superior en el PATH." >&2
    echo "    Bajalo de https://www.python.org/downloads/ y" >&2
    echo "    volve a correr este script." >&2
    exit 1
fi

exec "$PY" "$SCRIPT_DIR/install.py" "$@"