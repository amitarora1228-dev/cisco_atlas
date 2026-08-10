Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
$n = (Get-Process msedge -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host ("edge_remaining=" + $n)
