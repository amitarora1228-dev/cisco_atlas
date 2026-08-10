Add-Type -AssemblyName System.Core
# Show sessions of RawCap and the apps using 127.0.0.1:5002
Write-Host "=== Interactive sessions (quser) ==="
try { quser } catch { Write-Host "quser n/a" }

Write-Host "=== Sessions of processes owning conns to 127.0.0.1:5002 ==="
$conns = Get-NetTCPConnection -RemoteAddress 127.0.0.1 -RemotePort 5002 -State Established -ErrorAction SilentlyContinue
$pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
$rows = foreach ($procId in $pids) {
  $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
  if ($p) { [pscustomobject]@{ PID=$procId; Name=$p.ProcessName; Session=$p.SessionId } }
}
$rows | Sort-Object Session,Name | Format-Table -AutoSize

Write-Host "=== Count established conns to 127.0.0.1:5002 ==="
($conns | Measure-Object).Count

Write-Host "=== The SWG agent (csc_swgagent) session ==="
Get-Process csc_swgagent -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,SessionId | Format-Table -AutoSize

Write-Host "=== olk.exe (New Outlook) / Adobe present? sessions ==="
Get-Process olk,Acrobat,Adobe*,CCXProcess,CoreSync,AdobeIPCBroker -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,SessionId | Format-Table -AutoSize
