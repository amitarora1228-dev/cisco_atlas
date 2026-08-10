New-Item -ItemType Directory -Force -Path C:\keys | Out-Null
# Machine-level env var so new processes can pick it up
setx SSLKEYLOGFILE "C:\keys\sslkeys.log" /M | Out-Null
Write-Host ("SSLKEYLOGFILE(Machine)=" + [Environment]::GetEnvironmentVariable('SSLKEYLOGFILE','Machine'))

# Launcher that sets the var in-process and starts a FRESH Edge (must have NO other Edge running)
$bat = @'
@echo off
set SSLKEYLOGFILE=C:\keys\sslkeys.log
start "" "msedge.exe" --new-window
'@
Set-Content -Path "C:\keys\launch_edge_keylog.bat" -Value $bat -Encoding ASCII
Write-Host "Launcher written: C:\keys\launch_edge_keylog.bat"

Write-Host "=== pktmon start help ==="
pktmon start --help 2>&1
