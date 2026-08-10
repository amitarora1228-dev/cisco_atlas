Write-Host "=== Outlook processes ==="
Get-Process -Name OUTLOOK,olk -ErrorAction SilentlyContinue | Select-Object Name, Id, Path | Format-List
Write-Host "=== classic Outlook exe ==="
$paths = @(
  "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
  "C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE"
)
$paths | Where-Object { Test-Path $_ } | ForEach-Object { Write-Host $_ }
Write-Host "=== New Outlook (olk) present? ==="
$olk = Get-AppxPackage -Name Microsoft.OutlookForWindows -ErrorAction SilentlyContinue
if ($olk) { Write-Host ("NEW_OUTLOOK_INSTALLED = " + $olk.Version) } else { Write-Host "NEW_OUTLOOK_INSTALLED = NO" }
Write-Host "=== WebView2 runtime ==="
$wv = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -ErrorAction SilentlyContinue
if ($wv) { Write-Host ("WEBVIEW2 = " + $wv.pv) } else { Write-Host "WEBVIEW2 = not found via that key" }
