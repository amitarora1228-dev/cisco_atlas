Write-Host "=== Grant AppContainer write access to C:\keys ==="
icacls C:\keys /grant "*S-1-15-2-1:(OI)(CI)M" | Out-Null   # ALL APPLICATION PACKAGES
icacls C:\keys /grant "*S-1-15-2-2:(OI)(CI)M" | Out-Null   # ALL RESTRICTED APPLICATION PACKAGES
icacls C:\keys
Write-Host "=== WebView2 child processes of Outlook (before) ==="
Get-Process msedgewebview2 -ErrorAction SilentlyContinue | Select-Object Id | Format-Table -AutoSize
Write-Host "=== Restart New Outlook ==="
Get-Process olk -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process msedgewebview2 -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
Write-Host "olk stopped. Launch it fresh from the Start menu / taskbar now."
