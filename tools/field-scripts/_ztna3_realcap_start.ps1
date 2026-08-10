$rc  = "C:\keys\RawCap.exe"
$loop = "C:\keys\loop.pcap"
$loglp = "C:\keys\rawcap_loop.txt"
Remove-Item $loop,$loglp,"C:\keys\loopback_test.pcap","C:\keys\rawcap_out.txt" -ErrorAction SilentlyContinue

# Start RawCap on loopback (127.0.0.1), flush each packet, run until stopped
$p = Start-Process -FilePath $rc -ArgumentList "-f","127.0.0.1","`"$loop`"" -PassThru -WindowStyle Hidden -RedirectStandardOutput $loglp
Start-Sleep -Milliseconds 500
Write-Host ("RawCap loopback PID = " + $p.Id)

# Also (re)start pktmon on physical NIC for the egress leg
pktmon stop 2>&1 | Out-Null
pktmon start --capture --pkt-size 0 --file-name C:\keys\egress.etl --file-size 1024 --log-mode circular 2>&1 | Out-Null
Write-Host "pktmon egress capture started"

# Record current keylog line count as a baseline marker
$k = "C:\keys\sslkeys.log"
if (Test-Path $k) { Write-Host ("keylog_lines_baseline=" + ((Get-Content $k | Measure-Object -Line).Lines)) }
Write-Host "READY: reproduce Outlook auth + Adobe now."
