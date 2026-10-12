@echo off
REM Lanzador de NetSpy para Windows.
REM
REM Doble clic en este archivo, o desde CMD / PowerShell:
REM     netspy.bat audit --domain ejemplo.com
REM
REM Busca un Python utilizable (py, python, python3) y le pasa el trabajo a
REM netspy.py, que es el punto de entrada multiplataforma.

setlocal enabledelayedexpansion

REM Se queda en la carpeta del script para encontrar config\ y lib\.
cd /d "%~dp0"

set "PYEXE="

REM En Windows primero se prueba el lanzador de Python.
where py >nul 2>nul && set "PYEXE=py"
if not defined PYEXE (
    where python >nul 2>nul && set "PYEXE=python"
)
if not defined PYEXE (
    where python3 >nul 2>nul && set "PYEXE=python3"
)

if not defined PYEXE (
    echo [x] No se encontro Python 3.9 o superior en el PATH.
    echo.
    echo     Bajalo de https://www.python.org/downloads/
    echo     y tilda "Add python.exe to PATH" durante la instalacion.
    echo.
    pause
    exit /b 1
)

"%PYEXE%" "%~dp0netspy.py" %*
set "RC=%ERRORLEVEL%"

REM Si fallo, deja la ventana abierta para que se pueda leer el error.
if not "%RC%"=="0" (
    echo.
    echo [x] netspy salio con el codigo %RC%.
    echo     Para las dependencias: netspy.bat doctor
    echo     Para revisar la maquina: netspy.bat selfcheck
    pause
)

endlocal & exit /b %RC%