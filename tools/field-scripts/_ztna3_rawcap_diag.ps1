Write-Host "=== RawCap loopback log ==="
Get-Content "C:\keys\rawcap_loop.txt" -ErrorAction SilentlyContinue | Select-Object -Last 8
Write-Host "=== loop.pcap size ==="
if (Test-Path "C:\keys\loop.pcap") { Write-Host ((Get-Item "C:\keys\loop.pcap").Length.ToString() + " bytes") } else { Write-Host "no loop.pcap" }
Write-Host "=== RawCap process alive? ==="
Get-Process RawCap -ErrorAction SilentlyContinue | Select-Object Id, StartTime | Format-Table -AutoSize
Write-Host "=== Windows Firewall inbound rule for RawCap? ==="
Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object { $_.Program -like "*RawCap*" } | ForEach-Object { $r = $_ | Get-NetFirewallRule; Write-Host ($r.DisplayName + " | " + $r.Direction + " | " + $r.Action + " | Enabled=" + $r.Enabled) }
Write-Host "=== Current established conns to 127.0.0.1:5002 (apps using the SWG proxy) ==="
Get-NetTCPConnection -State Established -RemoteAddress 127.0.0.1 -RemotePort 5002 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
