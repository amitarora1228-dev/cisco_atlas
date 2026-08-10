$rc="C:\keys\RawCap.exe"; $loop="C:\keys\diag_loop.pcap"; $log="C:\keys\diag_rawcap.txt"; $keys="C:\keys\sslkeys.log"

# stop RawCap gracefully first (Ctrl-C not possible; kill)
Get-Process RawCap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$base = 0; if (Test-Path "C:\keys\diag_keys_baseline.txt") { $base = [int](Get-Content "C:\keys\diag_keys_baseline.txt") }
$now = (Get-Content $keys | Measure-Object -Line).Lines

Write-Host "=== RawCap stdout (final) ==="
Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 4
Write-Host ("=== diag_loop.pcap size ===")
if (Test-Path $loop) { Write-Host ((Get-Item $loop).Length.ToString() + " bytes") } else { Write-Host "NO PCAP" }
Write-Host ("=== keylog growth: baseline " + $base + " -> now " + $now + " (added " + ($now-$base) + ") ===")
