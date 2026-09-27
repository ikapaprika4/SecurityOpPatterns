@echo off
rem  SOC Workbench -- double-click to open it. Drop files, folders or .zip
rem  archives onto this icon to open it with them already analysed.
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY goto :nopython
%PY% -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul || goto :oldpython

rem  pythonw.exe (next to python.exe) runs the app without a console window.
rem  (%* stays outside parenthesised blocks: a dropped "cap(1).pcap" would end one.)
set "PYW="
for /f "delims=" %%W in ('%PY% -c "import os, sys; print(os.path.join(os.path.dirname(sys.executable), 'pythonw.exe'))"') do set "PYW=%%W"
if not defined PYW goto :console
if not exist "%PYW%" goto :console
start "" "%PYW%" -m socworkbench %*
exit /b 0

:console
%PY% -m socworkbench %*
exit /b %errorlevel%

:oldpython
echo SOC Workbench needs Python 3.10 or newer; the Python found is older
echo (or is only the Microsoft Store placeholder).
goto :help

:nopython
echo SOC Workbench needs Python 3.10 or newer, and none was found.

:help
echo Install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH"),
echo then double-click this file again. Optional, for a desktop window instead of
echo a browser tab:  pip install pywebview
echo.
pause
exit /b 1
