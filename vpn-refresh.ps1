# vpn-refresh.ps1  --  pull subscription text, rebuild config, restart the tunnel
#
# Source list: <root>\subs\sources.txt, one "key = url" per line, '#' starts a comment.
# Optional mirrors: lines like "mirror = https://your-mirror.example/" — the mirrors are
# tried in order in front of each url, so a plain url works through a reachable proxy too.
# That file is deliberately NOT part of the repository.
$ErrorActionPreference = 'Continue'
$ProgressPreference     = 'SilentlyContinue'
$root  = $PSScriptRoot
$subs  = Join-Path $root 'subs'
New-Item -ItemType Directory -Force -Path $subs | Out-Null

$listFile = Join-Path $subs 'sources.txt'
if (-not (Test-Path $listFile)) {
    Write-Host "[X] missing $listFile" -ForegroundColor Red
    Write-Host "    expected lines:  name = https://.../sub   (one per subscription)" -ForegroundColor DarkGray
    exit 1
}

$sources = [ordered]@{}
$mirrors = @()
foreach ($raw in Get-Content $listFile) {
    $line = $raw.Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }
    $eq = $line.IndexOf('=')
    if ($eq -lt 1) { continue }
    $key = $line.Substring(0, $eq).Trim()
    $val = $line.Substring($eq + 1).Trim()
    if ($key -eq 'mirror') { $mirrors += $val } else { $sources[$key] = $val }
}
if ($sources.Count -eq 0) { Write-Host "[X] $listFile holds no sources" -ForegroundColor Red; exit 1 }

Write-Host ("[1/3] pulling {0} subscription(s)..." -f $sources.Count) -ForegroundColor Cyan
foreach ($k in $sources.Keys) {
    $out = Join-Path $subs "$k.txt"
    $ok = $false
    foreach ($prefix in @('') + $mirrors) {
        $url = if ($prefix) { $prefix + $sources[$k] } else { $sources[$k] }
        $code = curl.exe -sL --max-time 40 -o $out $url -w "%{http_code}"
        $size = if (Test-Path $out) { (Get-Item $out).Length } else { 0 }
        if ($code -eq '200' -and $size -gt 200) {
            Write-Host ("      {0,-12} {1,8} bytes" -f $k, $size); $ok = $true; break
        }
    }
    if (-not $ok) { Write-Host ("      {0,-12} failed (kept previous copy)" -f $k) -ForegroundColor Yellow }
}

Write-Host "[2/3] rebuilding config..." -ForegroundColor Cyan
& python (Join-Path $root 'build_config.py')
if ($LASTEXITCODE -ne 0) { Write-Host "[X] build failed, old config kept" -ForegroundColor Red; exit 1 }

Write-Host "[3/3] restarting tunnel..." -ForegroundColor Cyan
if (Get-Process mihomo -ErrorAction SilentlyContinue) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'vpn-on.ps1')
} else {
    Write-Host "      tunnel idle; config updated (run vpn-on.ps1)" -ForegroundColor Yellow
}
