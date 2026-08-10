$loop="C:\keys\s3_loop.pcap"; $log="C:\keys\s3_rawcap.txt"; $keys="C:\keys\sslkeys.log"

Get-Process RawCap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
schtasks /end /tn "RawCapS3" 2>$null | Out-Null
Start-Sleep -Seconds 1

$base = 0; if (Test-Path "C:\keys\s3_keys_baseline.txt") { $base = [int](Get-Content "C:\keys\s3_keys_baseline.txt") }
$now = (Get-Content $keys | Measure-Object -Line).Lines

Write-Host "=== RawCap stdout (final) ==="
Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 4
Write-Host "=== s3_loop.pcap size ==="
if (Test-Path $loop) { Write-Host ((Get-Item $loop).Length.ToString() + " bytes") } else { Write-Host "NO PCAP" }
Write-Host ("=== keylog growth: baseline " + $base + " -> now " + $now + " (added " + ($now-$base) + ") ===")
