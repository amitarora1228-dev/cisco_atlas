$rc  = "C:\keys\RawCap.exe"
$out = "C:\keys\loopback_test.pcap"
$log = "C:\keys\rawcap_out.txt"
Remove-Item $out,$log -ErrorAction SilentlyContinue

# Start RawCap in background: flush each packet, auto-stop after 8s, sniff 127.0.0.1
$p = Start-Process -FilePath $rc -ArgumentList "-f","-s","8","127.0.0.1","`"$out`"" -PassThru -WindowStyle Hidden -RedirectStandardOutput $log
Start-Sleep -Milliseconds 800

# Generate KNOWN loopback traffic: connect to local SWG agent (127.0.0.1:5002)
for ($i=0; $i -lt 12; $i++) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect("127.0.0.1", 5002)
        $s = $c.GetStream()
        $b = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: test.local`r`n`r`n")
        $s.Write($b,0,$b.Length)
        Start-Sleep -Milliseconds 60
        $c.Close()
    } catch {}
}

$p.WaitForExit(15000) | Out-Null
Start-Sleep -Milliseconds 400

Write-Host "=== RawCap stdout (last lines) ==="
Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 6
Write-Host "=== pcap result ==="
if (Test-Path $out) {
    $len = (Get-Item $out).Length
    Write-Host ("pcap_bytes=" + $len + "  (24-byte global header means >24 = has packets)")
} else {
    Write-Host "NO_PCAP_CREATED"
}
