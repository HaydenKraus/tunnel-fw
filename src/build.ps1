# Сборка «Тоннеля»: рисует иконку и компилирует TunnelFW.exe встроенным csc
$src = $PSScriptRoot
$out = Split-Path $src
Add-Type -AssemblyName System.Drawing

function New-IconPng([int]$s) {
    $bmp = New-Object Drawing.Bitmap $s, $s
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $r = [Math]::Max(3, $s * 0.22); $d = $r * 2
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $path.AddArc(0, 0, $d, $d, 180, 90); $path.AddArc($s - $d - 1, 0, $d, $d, 270, 90)
    $path.AddArc($s - $d - 1, $s - $d - 1, $d, $d, 0, 90); $path.AddArc(0, $s - $d - 1, $d, $d, 90, 90)
    $path.CloseFigure()
    $grad = New-Object Drawing.Drawing2D.LinearGradientBrush (New-Object Drawing.Point 0, 0), (New-Object Drawing.Point $s, $s), ([Drawing.Color]::FromArgb(22, 22, 22)), ([Drawing.Color]::FromArgb(92, 12, 20))
    $g.FillPath($grad, $path)
    # Арка тоннеля
    $pen = New-Object Drawing.Pen ([Drawing.Color]::FromArgb(225, 29, 46)), ([Math]::Max(1.6, $s * 0.1))
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $x = $s * 0.24; $w = $s * 0.52; $top = $s * 0.24; $bottom = $s * 0.76
    $g.DrawArc($pen, $x, $top, $w, $w, 180, 180)
    $g.DrawLine($pen, $x, $top + $w / 2, $x, $bottom)
    $g.DrawLine($pen, $x + $w, $top + $w / 2, $x + $w, $bottom)
    # Свет в конце тоннеля
    $c = $s * 0.18
    $g.FillEllipse([Drawing.Brushes]::White, $s / 2 - $c / 2, $s * 0.5, $c, $c)
    $g.Dispose()
    $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
    , $ms.ToArray()
}

$sizes = 16, 24, 32, 48, 256
$pngs = foreach ($s in $sizes) { , (New-IconPng $s) }
$ms = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter $ms
$w.Write([int16]0); $w.Write([int16]1); $w.Write([int16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $b = [byte]($sizes[$i] % 256)
    $w.Write($b); $w.Write($b); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([int16]1); $w.Write([int16]32); $w.Write([int]$pngs[$i].Length); $w.Write([int]$offset)
    $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $w.Write($p) }
[IO.File]::WriteAllBytes("$src\TunnelFW.ico", $ms.ToArray())

& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /codepage:65001 /target:winexe /optimize `
    "/win32icon:$src\TunnelFW.ico" "/out:$out\TunnelFW.exe" `
    /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:Microsoft.CSharp.dll /r:System.Core.dll "$src\*.cs"
"exit: $LASTEXITCODE"
