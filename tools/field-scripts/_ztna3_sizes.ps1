Get-ChildItem C:\keys\cap.pcapng, C:\keys\sslkeys.log | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,2)}}, LastWriteTime | Format-Table -AutoSize
$kl = (Get-Content C:\keys\sslkeys.log | Measure-Object -Line).Lines
Write-Host ("keylog_lines=" + $kl)
