$f = "C:\keys\sslkeys.log"
if (Test-Path $f) {
    $item = Get-Item $f
    Write-Host ("EXISTS size_bytes=" + $item.Length + " lastwrite=" + $item.LastWriteTime)
    $lines = (Get-Content $f -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
    Write-Host ("lines=" + $lines)
    Write-Host "--- first 5 lines ---"
    Get-Content $f -TotalCount 5 -ErrorAction SilentlyContinue
} else {
    Write-Host "NOT_FOUND: sslkeys.log does not exist yet"
}
Write-Host "=== edge running ==="
(Get-Process msedge -ErrorAction SilentlyContinue | Measure-Object).Count
