@echo off
cd /d "%~dp0"
start "" pythonw "%~dp0LAN_Scanner.pyw"
if errorlevel 1 (
    python "%~dp0main.py"
)
