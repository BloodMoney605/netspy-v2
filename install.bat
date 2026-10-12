@echo off
REM Instalador de NetSpy para Windows.
REM
REM     install.bat              instala todo
REM     install.bat --no-tools   saltea las herramientas externas
REM
REM Equivale a: py install.py

setlocal

cd /d "%~dp0"

set "PYEXE="

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
    echo     Despues corre este archivo otra vez.
    echo.
    pause
    exit /b 1
)

echo [*] Usando %PYEXE%
"%PYEXE%" --version
echo.

"%PYEXE%" "%~dp0install.py" %*
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo [+] Instalacion terminada.
    echo.
    echo     netspy.bat doctor        revisa las dependencias
    echo     netspy.bat selfcheck     diagnostica la maquina
    echo     netspy.bat audit --domain ejemplo.com
    echo     netspy.bat               menu interactivo
) else (
    echo [x] La instalacion fallo con el codigo %RC%.
)

pause
endlocal & exit /b %RC%