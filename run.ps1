# Project ATLAS - start the unified web shell on Windows.
#
# ATLAS runs directly on the host; there is no container. This script owns the
# whole contract: virtualenv, pinned dependencies, PYTHONPATH for the package
# layout, and the tshark preflight.
#
#   .\run.ps1                      start on 127.0.0.1:8000
#   .\run.ps1 -BindHost 0.0.0.0    bind all interfaces (see the warning below)
#   .\run.ps1 -Port 9000

[CmdletBinding()]
param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Application start-up must never install packages; that is this script's job.
$env:DARTHAWK_AUTO_INSTALL = "0"
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONPATH = @(
    (Join-Path $PSScriptRoot "packages\capture_inspector"),
    (Join-Path $PSScriptRoot "packages\darthawk"),
    (Join-Path $PSScriptRoot "packages\atlas_core"),
    (Join-Path $PSScriptRoot "apps")
) -join ";"

$venv = Join-Path $PSScriptRoot ".venv"
$python = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "[atlas] creating virtualenv"
    py -3 -m venv $venv
}

Write-Host "[atlas] installing pinned dependencies"
& $python -m pip install --quiet --upgrade pip
& $python -m pip install --quiet `
    -r packages\capture_inspector\requirements.txt `
    -r packages\darthawk\requirements.txt `
    -r requirements-web.txt

# Capture Inspector skips packet analysis silently when tshark is absent, which
# looks identical to an empty capture. Say so here instead.
# Normalise to a plain string: Get-Command yields CommandInfo, the fallback
# yields a path, and only one of those has a .Path property.
$tsharkPath = (Get-Command tshark -ErrorAction SilentlyContinue).Source
if (-not $tsharkPath) {
    foreach ($candidate in @("$env:ProgramFiles\Wireshark\tshark.exe",
                             "${env:ProgramFiles(x86)}\Wireshark\tshark.exe")) {
        if (Test-Path $candidate) { $tsharkPath = $candidate; break }
    }
}
if ($tsharkPath) {
    $tsharkVersion = & $tsharkPath --version 2>$null | Select-Object -First 1
    Write-Host "[atlas] tshark: $tsharkVersion"
} else {
    Write-Warning "tshark not found - packet analysis will be DISABLED."
    Write-Warning "DART bundle analysis is unaffected."
    Write-Warning "Install Wireshark from https://www.wireshark.org/download.html"
}

if ($BindHost -ne "127.0.0.1" -and $BindHost -ne "localhost") {
    Write-Warning "Binding to $BindHost exposes ATLAS beyond this machine."
    Write-Warning "Uploads contain captures and DART bundles. Put an authenticating reverse proxy in front first."
}

Write-Host "[atlas] http://${BindHost}:${Port}"
& $python -m uvicorn web.main:app --host $BindHost --port $Port
