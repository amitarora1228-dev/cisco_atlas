# Generates app.ico - a simple Capture Inspector icon (magnifier on Cisco blue).
Add-Type -AssemblyName System.Drawing

$size = 256
$bmp  = New-Object System.Drawing.Bitmap $size, $size
$g    = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::Transparent)

# Rounded background in Cisco blue.
$bg = [System.Drawing.Color]::FromArgb(4, 159, 217)
$brush = New-Object System.Drawing.SolidBrush $bg
$rect = New-Object System.Drawing.Rectangle 8, 8, ($size-16), ($size-16)
$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$r = 48
$path.AddArc($rect.X, $rect.Y, $r, $r, 180, 90)
$path.AddArc($rect.Right-$r, $rect.Y, $r, $r, 270, 90)
$path.AddArc($rect.Right-$r, $rect.Bottom-$r, $r, $r, 0, 90)
$path.AddArc($rect.X, $rect.Bottom-$r, $r, $r, 90, 90)
$path.CloseFigure()
$g.FillPath($brush, $path)

# Magnifying glass (white).
$penW = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), 22
$penW.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$penW.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
$g.DrawEllipse($penW, 70, 64, 92, 92)
$g.DrawLine($penW, 156, 150, 196, 190)

$g.Dispose()

# Save as .ico via icon handle.
$icoPath = Join-Path $PSScriptRoot "app.ico"
$hicon = $bmp.GetHicon()
$icon  = [System.Drawing.Icon]::FromHandle($hicon)
$fs = [System.IO.File]::Create($icoPath)
$icon.Save($fs)
$fs.Close()
$icon.Dispose()
$bmp.Dispose()
Write-Host "Icon written to $icoPath"
