Write-Host "=== Stop RawCap loopback ==="
Get-Process RawCap -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 800
Write-Host "=== RawCap loopback stdout ==="
Get-Content "C:\keys\rawcap_loop.txt" -ErrorAction SilentlyContinue | Select-Object -Last 3
Write-Host "=== Stop pktmon egress + convert ==="
pktmon stop 2>&1 | Out-Null
Remove-Item "C:\keys\egress.pcapng" -ErrorAction SilentlyContinue
pktmon etl2pcap C:\keys\egress.etl --out C:\keys\egress.pcapng 2>&1 | Select-Object -Last 3
Write-Host "=== Sizes ==="
Get-ChildItem C:\keys\loop.pcap, C:\keys\egress.pcapng, C:\keys\sslkeys.log -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "=== keylog growth ==="
$lines = (Get-Content C:\keys\sslkeys.log | Measure-Object -Line).Lines
Write-Host ("keylog_lines_now=" + $lines + " (baseline was 16853)")
