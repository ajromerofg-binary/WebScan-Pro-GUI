@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM  WebScan Pro GUI - Launcher para Windows
REM  Sr.Robot Labs
REM ============================================================
REM  IMPORTANTE: el motor de analisis (webscanpro.sh) es un script
REM  Bash que depende de curl. Windows NO trae Bash ni curl por
REM  defecto. Para que esto funcione necesitas UNA de estas dos
REM  opciones instaladas:
REM
REM    A) Git for Windows (recomendado, mas ligero)
REM       https://git-scm.com/download/win
REM       Instala bash.exe y curl.exe y los añade al PATH.
REM
REM    B) WSL (Windows Subsystem for Linux)
REM       wsl --install   (desde una terminal como administrador)
REM       Instala una distro Linux completa (Ubuntu, etc.)
REM
REM  Sin una de las dos, la interfaz arrancara pero cualquier
REM  escaneo fallara al no encontrar "bash".
REM ============================================================

cd /d "%~dp0"

echo.
echo === WebScan Pro GUI - comprobando requisitos ===
echo.

REM --- Comprobar Python ---
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] No se encontro "python" en el PATH.
    echo         Instala Python 3.10 o superior desde https://python.org
    echo         y marca la casilla "Add python.exe to PATH" durante la instalacion.
    pause
    exit /b 1
)
echo [OK] Python encontrado.

REM --- Comprobar bash (Git for Windows o WSL) ---
where bash >nul 2>nul
if errorlevel 1 (
    echo [AVISO] No se encontro "bash" en el PATH.
    echo         El motor de analisis es un script Bash y no podra ejecutarse.
    echo         Instala Git for Windows ^(https://git-scm.com/download/win^)
    echo         o WSL ^(wsl --install^) antes de lanzar un escaneo.
    echo.
    echo         Continuando de todos modos para que puedas ver la interfaz...
    echo.
) else (
    echo [OK] bash encontrado.
)

REM --- Comprobar curl (necesario para el motor) ---
where curl >nul 2>nul
if errorlevel 1 (
    echo [AVISO] No se encontro "curl" en el PATH. El motor lo necesita.
) else (
    echo [OK] curl encontrado.
)

REM --- Crear entorno virtual si no existe ---
if not exist venv (
    echo.
    echo Creando entorno virtual...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] No se pudo crear el entorno virtual.
        pause
        exit /b 1
    )
)

call venv\Scripts\activate.bat

REM --- Instalar dependencias ---
echo.
echo Instalando dependencias ^(solo la primera vez tarda^)...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Fallo instalando dependencias. Revisa tu conexion o requirements.txt.
    pause
    exit /b 1
)

REM --- Lanzar la aplicacion ---
echo.
echo Iniciando WebScan Pro GUI...
echo.
python main.py

if errorlevel 1 (
    echo.
    echo [ERROR] La aplicacion termino con un error. Revisa el mensaje de arriba.
    pause
)

endlocal
