$rc="C:\keys\RawCap.exe"; $loop="C:\keys\diag_loop.pcap"; $log="C:\keys\diag_rawcap.txt"; $keys="C:\keys\sslkeys.log"
Remove-Item $loop,$log -ErrorAction SilentlyContinue

# kill any stale RawCap
Get-Process RawCap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# baseline keylog size
$base = 0; if (Test-Path $keys) { $base = (Get-Content $keys | Measure-Object -Line).Lines }
Set-Content "C:\keys\diag_keys_baseline.txt" $base

# start RawCap on loopback (runs until killed)
$p = Start-Process $rc -ArgumentList "-f","127.0.0.1","`"$loop`"" -PassThru -WindowStyle Hidden -RedirectStandardOutput $log
Set-Content "C:\keys\diag_rawcap_pid.txt" $p.Id
Start-Sleep -Seconds 2

# prove it is live: make a test connection to 127.0.0.1:5002 and watch count climb
try { $c = New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1",5002); Start-Sleep -Milliseconds 300; $c.Close() } catch {}
Start-Sleep -Seconds 1

Write-Host ("SSLKEYLOGFILE = " + [Environment]::GetEnvironmentVariable("SSLKEYLOGFILE","Machine"))
Write-Host ("keylog baseline lines = " + $base)
Write-Host ("RawCap PID = " + $p.Id + "  alive = " + (-not $p.HasExited))
Write-Host "=== RawCap stdout (proves capture is LIVE) ==="
Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 3
Write-Host "=== READY: reproduce the Outlook/Adobe failure NOW (close+reopen the app to force fresh connections) ==="
