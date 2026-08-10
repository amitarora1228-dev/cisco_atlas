$rc="C:\keys\RawCap.exe"; $loop="C:\keys\poc_loop.pcap"; $log="C:\keys\poc_rawcap.txt"; $pk="C:\keys\poc_keys.log"
Remove-Item $loop,$log,$pk -ErrorAction SilentlyContinue
Remove-Item "C:\keys\edge_poc" -Recurse -Force -ErrorAction SilentlyContinue

# 1) Start RawCap on loopback
$p = Start-Process $rc -ArgumentList "-f","127.0.0.1","`"$loop`"" -PassThru -WindowStyle Hidden -RedirectStandardOutput $log
Start-Sleep -Seconds 1

# 2) Fresh headless Edge with isolated keylog -> forces a NEW TLS handshake through the SWG
$env:SSLKEYLOGFILE=$pk
$edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
if(-not(Test-Path $edge)){ $edge="$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe" }
Write-Host ("edge exe exists: " + (Test-Path $edge))
$e = Start-Process $edge -ArgumentList "--headless=new","--disable-gpu","--no-first-run","--no-default-browser-check","--user-data-dir=C:\keys\edge_poc","https://example.com/" -PassThru
Start-Sleep -Seconds 9

# 3) Stop everything
Get-Process msedge -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*edge_poc*' -or $_.Id -eq $e.Id } | Stop-Process -Force -ErrorAction SilentlyContinue
try { Stop-Process -Id $e.Id -Force -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Milliseconds 500
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

Write-Host "=== RawCap stdout (last 3) ==="
Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 3
Write-Host "=== poc_loop.pcap size ==="
if (Test-Path $loop) { Write-Host ((Get-Item $loop).Length.ToString() + " bytes") } else { Write-Host "NO PCAP" }
Write-Host "=== poc_keys.log lines ==="
if (Test-Path $pk) { Write-Host ((Get-Content $pk | Measure-Object -Line).Lines) } else { Write-Host "NO KEYS" }
