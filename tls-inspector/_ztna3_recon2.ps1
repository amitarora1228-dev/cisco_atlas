Write-Host "=== Windows ==="
(Get-CimInstance Win32_OperatingSystem).Caption
[Environment]::OSVersion.Version.ToString()
Write-Host "=== pktmon ==="
(Get-Command pktmon -ErrorAction SilentlyContinue).Source
Write-Host "=== pktmon pcapng support ==="
pktmon pcapng 2>&1 | Select-Object -First 3
Write-Host "=== browser processes running now ==="
Get-Process chrome,msedge,firefox -ErrorAction SilentlyContinue | Select-Object Name,Id | Format-Table -AutoSize
Write-Host "=== active session user ==="
query user 2>&1
