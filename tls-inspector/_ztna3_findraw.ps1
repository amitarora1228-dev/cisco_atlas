Write-Host "=== C:\keys contents ==="
Get-ChildItem C:\keys -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "=== search RawCap anywhere obvious ==="
$cand = @("C:\keys\RawCap.exe","C:\Users\Administrator\RawCap.exe","C:\Windows\System32\RawCap.exe")
foreach ($c in $cand) { if (Test-Path $c) { Write-Host ("FOUND: " + $c + " = " + (Get-Item $c).Length + " bytes") } }
Write-Host "=== home dir listing ==="
Get-ChildItem C:\Users\Administrator -Filter "RawCap*" -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize
