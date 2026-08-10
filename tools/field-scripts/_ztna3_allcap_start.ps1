$rc = "C:\keys\RawCap.exe"

# Stop any running RawCap + pktmon first
Get-Process RawCap -ErrorAction SilentlyContinue | Stop-Process -Force
pktmon stop 2>&1 | Out-Null
Start-Sleep -Milliseconds 500
Remove-Item C:\keys\cap_*.pcap, C:\keys\rc_*.txt -ErrorAction SilentlyContinue

# Enumerate ALL IPv4 addresses (RawCap can't do IPv6), skip APIPA link-local 169.254
$addrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '169.254.*' } |
    Select-Object -ExpandProperty IPAddress -Unique

Write-Host ("Interfaces to capture: " + ($addrs -join ', '))

$started = @()
foreach ($ip in $addrs) {
    $safe = $ip -replace '[^0-9]', '_'
    $out = "C:\keys\cap_$safe.pcap"
    $log = "C:\keys\rc_$safe.txt"
    $p = Start-Process -FilePath $rc -ArgumentList "-f","$ip","`"$out`"" -PassThru -WindowStyle Hidden -RedirectStandardOutput $log
    $started += [pscustomobject]@{ IP=$ip; PID=$p.Id; File=$out }
    Start-Sleep -Milliseconds 300
}
Write-Host "=== RawCap instances running ==="
$started | ForEach-Object { Write-Host ("  " + $_.IP + "  PID=" + $_.PID + "  -> " + $_.File) }

$k = "C:\keys\sslkeys.log"
if (Test-Path $k) { Write-Host ("keylog_lines_baseline=" + ((Get-Content $k | Measure-Object -Line).Lines)) }
Write-Host "READY: reproduce Outlook auth + Adobe now."
