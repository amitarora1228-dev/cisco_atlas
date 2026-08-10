$name = "Block QUIC (TLS_Inspector test)"
# Remove if it already exists (idempotent)
Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
# Block outbound UDP 443 (and 80) = QUIC / HTTP/3
New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block -Protocol UDP -RemotePort 443,80 -Profile Any -Enabled True | Out-Null
Write-Host "=== Rule created ==="
Get-NetFirewallRule -DisplayName $name | Select-Object DisplayName, Direction, Action, Enabled | Format-List
$pf = Get-NetFirewallPortFilter | Where-Object { $_.InstanceID -in (Get-NetFirewallRule -DisplayName $name).Name }
Get-NetFirewallRule -DisplayName $name | Get-NetFirewallPortFilter | Select-Object Protocol, RemotePort | Format-List
