Write-Host "=== Edge managed by policy? ==="
$edgePol = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (Test-Path $edgePol) {
    Write-Host "EDGE_POLICY_PRESENT = YES (managed)"
    (Get-Item $edgePol).Property | Select-Object -First 20 | ForEach-Object { Write-Host ("  policy: " + $_) }
} else {
    Write-Host "EDGE_POLICY_PRESENT = NO"
}
Write-Host "=== CloudManagement / MDM enrollment ==="
$cloud = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\CloudManagementEnrollmentToken"
Write-Host ("CloudMgmtToken present: " + (Test-Path $cloud))
Write-Host "=== Firefox installed? ==="
$ffPaths = @("C:\Program Files\Mozilla Firefox\firefox.exe","C:\Program Files (x86)\Mozilla Firefox\firefox.exe")
$ff = $ffPaths | Where-Object { Test-Path $_ }
if ($ff) { Write-Host ("FIREFOX = " + $ff) } else { Write-Host "FIREFOX = NOT_INSTALLED" }
Write-Host "=== Chrome installed? ==="
$chPaths = @("C:\Program Files\Google\Chrome\Application\chrome.exe","C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")
$ch = $chPaths | Where-Object { Test-Path $_ }
if ($ch) { Write-Host ("CHROME = " + $ch) } else { Write-Host "CHROME = NOT_INSTALLED" }
Write-Host "=== machine SSLKEYLOGFILE ==="
Write-Host ([Environment]::GetEnvironmentVariable('SSLKEYLOGFILE','Machine'))
