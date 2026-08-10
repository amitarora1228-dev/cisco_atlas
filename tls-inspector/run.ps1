# TLS Inspector — one-shot launcher (creates venv, installs deps, starts server)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    python -m venv .venv
}

& ".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
& ".venv\Scripts\python.exe" -m pip install -r requirements.txt --quiet

Write-Host "`nStarting TLS Inspector at http://127.0.0.1:8000`n" -ForegroundColor Green
$env:PYTHONIOENCODING = "utf-8"
& ".venv\Scripts\python.exe" -m uvicorn app.server:app --host 127.0.0.1 --port 8000
