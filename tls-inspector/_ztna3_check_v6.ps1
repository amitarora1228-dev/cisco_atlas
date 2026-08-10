Write-Host "=== SWG agent (csc_swgagent) listeners ==="
$swg = (Get-Process csc_swgagent -ErrorAction SilentlyContinue).Id
Write-Host ("csc_swgagent PID = " + $swg)
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $swg } | Select-Object LocalAddress, LocalPort | Sort-Object LocalPort | Format-Table -AutoSize
Write-Host "=== Established connections TO the SWG agent port 5002 (who connects, v4 vs v6) ==="
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 5002 -or $_.LocalPort -eq 5002 } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Format-Table -AutoSize
Write-Host "=== Count established loopback conns: IPv4 vs IPv6 ==="
$v4 = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -eq '127.0.0.1' } | Measure-Object).Count
$v6 = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -eq '::1' } | Measure-Object).Count
Write-Host ("established_to_127.0.0.1 = " + $v4)
Write-Host ("established_to_::1       = " + $v6)
