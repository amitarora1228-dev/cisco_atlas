Write-Host "=== Network adapters ==="
Get-NetAdapter | Select-Object Name, InterfaceDescription, ifIndex, Status, LinkSpeed | Format-Table -AutoSize
Write-Host ""
Write-Host "=== Cisco / SASE processes ==="
Get-Process | Where-Object { $_.Name -match 'vpn|acsock|csc|umbrella|swg|anyconnect|cisco|secure' } | Select-Object Name, Id, Path | Format-Table -AutoSize
Write-Host ""
Write-Host "=== Loopback listeners (127.0.0.1 / ::1) - possible SWG proxy ==="
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -in @('127.0.0.1','::1') } | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object LocalPort | Format-Table -AutoSize
Write-Host ""
Write-Host "=== Established conns to loopback (app -> local proxy) ==="
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -in @('127.0.0.1','::1') } | Measure-Object | Select-Object -ExpandProperty Count
Write-Host ""
Write-Host "=== System proxy settings (WinINET) ==="
$p = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
Write-Host ("ProxyEnable=" + $p.ProxyEnable + "  ProxyServer=" + $p.ProxyServer + "  AutoConfigURL=" + $p.AutoConfigURL)
Write-Host ""
Write-Host "=== pktmon components (look for loopback) ==="
pktmon list 2>&1
