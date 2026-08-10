$loop="C:\keys\s3_loop.pcap"; $log="C:\keys\s3_rawcap.txt"
Remove-Item $loop,$log -ErrorAction SilentlyContinue
Get-Process RawCap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# batch wrapper so we can redirect RawCap stdout to a file
$bat = "C:\keys\s3_rawcap.bat"
Set-Content -Path $bat -Encoding ascii -Value '@echo off
"C:\keys\RawCap.exe" -f 127.0.0.1 C:\keys\s3_loop.pcap > C:\keys\s3_rawcap.txt 2>&1'

# create an interactive scheduled task that runs in the currently logged-on user's session (session 3)
schtasks /delete /f /tn "RawCapS3" 2>$null | Out-Null
$create = schtasks /create /f /tn "RawCapS3" /tr "$bat" /sc once /st 00:00 /ru administrator /it /rl highest 2>&1
Write-Host "=== schtasks create result ==="
$create

Write-Host "=== run task ==="
schtasks /run /tn "RawCapS3" 2>&1
Start-Sleep -Seconds 3

Write-Host "=== RawCap process + session (expect Session=3) ==="
Get-Process RawCap -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,SessionId | Format-Table -AutoSize

# session-0 baseline test connection (to compare capture behavior)
try { $c = New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1",5002); Start-Sleep -Milliseconds 300; $c.Close() } catch {}
Start-Sleep -Seconds 1
Write-Host "=== RawCap stdout so far ==="
Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 3
Write-Host "=== s3_loop.pcap size ==="
if (Test-Path $loop) { Write-Host ((Get-Item $loop).Length.ToString() + " bytes") } else { Write-Host "NO PCAP" }
