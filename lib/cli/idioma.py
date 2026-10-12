"""Textos de la interfaz.

Solo espanol. Para cambiar el idioma habria que editar la tabla de arriba.
"""

from __future__ import annotations

import os

# Tono del menu y del prompt de sigilo.
STRINGS = {
    "choice": "Opcion",
    "domain": "Dominio",
    "target": "IP o rango",
    "directory": "Directorio",
    "threads": "Hilos",
    "running": "Ejecutando...",
    "back": "Enter para volver al menu...",
    "main_title": "Menu principal",
    "stealth": "Sigilo",
    "stealth_title": "Configuracion de sigilo",
    "stealth_sub": "Estas opciones bajan tu huella durante el escaneo",
    "opt_1": "Auditar dominio (todo el pipeline, con reporte)",
    "opt_2": "Escanear dominio (recon, puertos, fingerprint y CVEs)",
    "opt_3": "Reconocer (solo subdominios y DNS)",
    "opt_4": "Escanear puertos (IP o rango)",
    "opt_5": "Armar reporte (datos que ya existen)",
    "opt_6": "Instalar dependencias",
    "opt_7": "Ver licencia",
    "opt_q": "Salir",
    "s1": "Alto: MAC + esperas al azar + user-agent falso",
    "s2": "Medio: esperas al azar + user-agent falso",
    "s3": "Bajo: cambiar la MAC",
    "s4": "Ninguno (escaneo directo)",
    "none": "ninguno",
    "run_doctor": "Corre 'netspy doctor' para instalar lo que falte",
    "byes": "Chau.",
}


def tr(clave: str) -> str:
    return STRINGS.get(clave, clave)
