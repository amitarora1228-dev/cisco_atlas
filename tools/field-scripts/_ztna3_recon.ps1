New-Item -ItemType Directory -Force -Path C:\keys | Out-Null
Write-Host "=== HOST ==="
hostname
Write-Host "=== tshark path ==="
$ts = "C:\Program Files\Wireshark\tshark.exe"
$dc = "C:\Program Files\Wireshark\dumpcap.exe"
Write-Host ("tshark exists: " + (Test-Path $ts))
Write-Host ("dumpcap exists: " + (Test-Path $dc))
Write-Host "=== SSLKEYLOGFILE (Machine) ==="
Write-Host ([Environment]::GetEnvironmentVariable('SSLKEYLOGFILE','Machine'))
Write-Host "=== capture interfaces ==="
if (Test-Path $dc) { & $dc -D }
Write-Host "=== python ==="
(Get-Command python -ErrorAction SilentlyContinue).Source
