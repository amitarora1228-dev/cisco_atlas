# Capture Inspector - Server Control panel (WinForms GUI)
# Start / Stop / Restart the local uvicorn server and open it in a browser.

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Configuration ---------------------------------------------------------
# Resolve the app folder whether running as a .ps1 script or a compiled .exe.
if ($PSScriptRoot) {
    $Root = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $Root = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $Root = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}
$PyExe   = Join-Path $Root ".venv\Scripts\python.exe"
$AppMod  = "app.server:app"
$BindHost = "127.0.0.1"
$Port    = 8000
$Url     = "http://$BindHost`:$Port"

# --- Helpers ---------------------------------------------------------------
# State is cached between refreshes so the expensive lookups run on a state
# CHANGE, not on every tick.
$script:CachedPid   = $null
$script:LastRunning = $null

function Test-PortListening {
    # Is anything listening on $Port? Pure .NET, no WMI.
    # This runs on the UI thread every couple of seconds, so it has to be
    # effectively free. Get-NetTCPConnection was measured at ~950 ms on a host
    # with a few hundred connections; called twice per 2 s tick it blocked the
    # message pump for almost the entire interval, which is why the window could
    # not process a click.
    try {
        $props = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        foreach ($ep in $props.GetActiveTcpListeners()) {
            if ($ep.Port -eq $Port) { return $true }
        }
    } catch { }
    return $false
}

function Resolve-ServerPid {
    # Expensive (WMI-backed). Only called when the running state changes.
    try {
        $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop | Select-Object -First 1
        if ($conn) { return [int]$conn.OwningProcess }
    } catch { }
    return $null
}

function Get-ServerPid {
    if ($script:CachedPid) { return $script:CachedPid }
    return (Resolve-ServerPid)
}

function Test-ServerRunning {
    return (Test-PortListening)
}

function Wait-ForState {
    # Wait until the server really reaches the wanted state, pumping the message
    # queue meanwhile. A fixed Start-Sleep froze the window for its whole
    # duration and was wrong either way: too long when the server was already
    # up, too short when it was slow to bind.
    param([bool]$Want, [int]$TimeoutMs = 6000)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        if ((Test-PortListening) -eq $Want) { return $true }
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 60
    }
    return $false
}

function Start-Server {
    if (Test-ServerRunning) { return }
    if (-not (Test-Path $PyExe)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Python virtual environment not found at:`n$PyExe`n`nRun run.ps1 once to create it.",
            "Capture Inspector", "OK", "Error") | Out-Null
        return
    }
    $env:PYTHONIOENCODING = "utf-8"
    # Deliberately NOT $args — that is an automatic variable in PowerShell.
    $uvicornArgs = @("-m", "uvicorn", $AppMod, "--host", $BindHost, "--port", "$Port")
    Start-Process -FilePath $PyExe -ArgumentList $uvicornArgs -WorkingDirectory $Root -WindowStyle Minimized | Out-Null
}

function Stop-Server {
    # Kill the process bound to the port (and any stray uvicorn workers).
    $serverPid = Get-ServerPid
    if ($serverPid) {
        try { Stop-Process -Id $serverPid -Force -ErrorAction SilentlyContinue } catch { }
    }
    # The command-line sweep is the expensive part (~380 ms), so only pay for it
    # when there is a python process to sweep at all.
    try {
        if (@(Get-Process python -ErrorAction SilentlyContinue).Count -gt 0) {
            Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
                Where-Object { $_.CommandLine -like '*uvicorn*' -and $_.CommandLine -like '*app.server:app*' } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        }
    } catch { }
    $script:CachedPid   = $null
    $script:LastRunning = $null
}

# --- UI --------------------------------------------------------------------
$form                 = New-Object System.Windows.Forms.Form
$form.Text            = "Capture Inspector - Server Control"
$form.Size            = New-Object System.Drawing.Size(380, 250)
$form.StartPosition   = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox     = $false
$form.BackColor       = [System.Drawing.Color]::FromArgb(247, 247, 247)
$form.Font            = New-Object System.Drawing.Font("Segoe UI", 9)

# Title
$title           = New-Object System.Windows.Forms.Label
$title.Text      = "Capture Inspector"
$title.Font      = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::FromArgb(55, 60, 66)
$title.Location  = New-Object System.Drawing.Point(20, 14)
$title.AutoSize  = $true
$form.Controls.Add($title)

# Status dot + text
$dot          = New-Object System.Windows.Forms.Label
$dot.Text     = [char]0x25CF
$dot.Font     = New-Object System.Drawing.Font("Segoe UI", 14)
$dot.Location = New-Object System.Drawing.Point(20, 48)
$dot.AutoSize = $true
$form.Controls.Add($dot)

$status          = New-Object System.Windows.Forms.Label
$status.Location = New-Object System.Drawing.Point(44, 52)
$status.AutoSize = $true
$form.Controls.Add($status)

$urlLabel          = New-Object System.Windows.Forms.LinkLabel
$urlLabel.Text     = $Url
$urlLabel.Location = New-Object System.Drawing.Point(22, 78)
$urlLabel.AutoSize = $true
$urlLabel.Add_LinkClicked({ Start-Process $Url }) | Out-Null
$form.Controls.Add($urlLabel)

# Buttons
function New-Btn($text, $x, $y, $w, $color) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $text
    $b.Location  = New-Object System.Drawing.Point($x, $y)
    $b.Size      = New-Object System.Drawing.Size($w, 38)
    $b.FlatStyle = "Flat"
    $b.FlatAppearance.BorderSize = 0
    $b.ForeColor = [System.Drawing.Color]::White
    $b.BackColor = $color
    $b.Font      = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    return $b
}

$btnStart   = New-Btn "Start"   20  112 105 ([System.Drawing.Color]::FromArgb(46, 160, 67))
$btnStop    = New-Btn "Stop"    132 112 105 ([System.Drawing.Color]::FromArgb(207, 34, 46))
$btnRestart = New-Btn "Restart" 244 112 105 ([System.Drawing.Color]::FromArgb(219, 109, 40))
$btnOpen    = New-Btn "Open in browser" 20 158 329 ([System.Drawing.Color]::FromArgb(62, 132, 229))
$form.Controls.AddRange(@($btnStart, $btnStop, $btnRestart, $btnOpen))

function Update-Status {
    # ONE state read per refresh. The previous version called the port lookup
    # twice — once to test, once again to interpolate the PID into the label —
    # doubling an already blocking call.
    $running = Test-PortListening
    if ($running -ne $script:LastRunning) {
        $script:LastRunning = $running
        $script:CachedPid = if ($running) { Resolve-ServerPid } else { $null }
    }
    if ($running) {
        $dot.ForeColor    = [System.Drawing.Color]::FromArgb(46, 160, 67)
        $status.Text      = if ($script:CachedPid) { "Running  -  PID $($script:CachedPid)" } else { "Running" }
        $status.ForeColor = [System.Drawing.Color]::FromArgb(46, 160, 67)
        $btnStart.Enabled = $false
        $btnStop.Enabled  = $true
        $btnOpen.Enabled  = $true
    } else {
        $dot.ForeColor    = [System.Drawing.Color]::FromArgb(150, 150, 150)
        $status.Text      = "Stopped"
        $status.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
        $btnStart.Enabled = $true
        $btnStop.Enabled  = $false
        $btnOpen.Enabled  = $false
    }
}

$btnStart.Add_Click({
    $btnStart.Enabled = $false
    Start-Server
    [void](Wait-ForState -Want $true)
    Update-Status
}) | Out-Null

$btnStop.Add_Click({
    $btnStop.Enabled = $false
    Stop-Server
    [void](Wait-ForState -Want $false)
    Update-Status
}) | Out-Null

$btnRestart.Add_Click({
    $btnRestart.Enabled = $false
    Stop-Server
    [void](Wait-ForState -Want $false)
    Start-Server
    [void](Wait-ForState -Want $true)
    $btnRestart.Enabled = $true
    Update-Status
}) | Out-Null

$btnOpen.Add_Click({ Start-Process $Url }) | Out-Null

# Auto-refresh status every 2 seconds.
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 2000
$timer.Add_Tick({ Update-Status }) | Out-Null
$timer.Start()

Update-Status
[System.Windows.Forms.Application]::EnableVisualStyles()
[void]$form.ShowDialog()
$timer.Stop()
