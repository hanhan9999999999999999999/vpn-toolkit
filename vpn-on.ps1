# vpn-on.ps1  --  start mihomo and switch the Windows system proxy on
# Layout: <root>\bin\mihomo.exe, <root>\data\config.yaml, <root>\data\ (geo files, cache)
param([int]$Port = 7891)
$ErrorActionPreference = 'Stop'
$root  = $PSScriptRoot
$exe   = Join-Path $root 'bin\mihomo.exe'
$data  = Join-Path $root 'data'
$cfg   = Join-Path $data 'config.yaml'
$reg   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

if (-not (Test-Path $exe)) { Write-Host "[X] mihomo.exe missing: $exe" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $cfg)) { Write-Host "[X] config.yaml missing: $cfg" -ForegroundColor Red; exit 1 }

Get-Process mihomo -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

Start-Process -FilePath $exe -ArgumentList @('-d', $data, '-f', $cfg) -WindowStyle Hidden | Out-Null

$ok = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) { $ok = $true; break }
}
if (-not $ok) { Write-Host "[X] mihomo did not open port $Port" -ForegroundColor Red; exit 2 }

Set-ItemProperty -Path $reg -Name ProxyEnable  -Value 1 -Type DWord
Set-ItemProperty -Path $reg -Name ProxyServer  -Value "127.0.0.1:$Port" -Type String
Set-ItemProperty -Path $reg -Name ProxyOverride -Value 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>' -Type String
Remove-ItemProperty -Path $reg -Name AutoConfigURL -ErrorAction SilentlyContinue

if (-not ('WinInetRefresh' -as [type])) {
    Add-Type -Namespace W -Name WinInetRefresh -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(System.IntPtr h, int o, System.IntPtr b, int l);
'@
}
[W.WinInetRefresh]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[W.WinInetRefresh]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null

$code = curl.exe -s -o NUL -x "http://127.0.0.1:$Port" --max-time 15 -w "%{http_code}" http://www.gstatic.com/generate_204
Write-Host ""
Write-Host "[OK] system proxy -> 127.0.0.1:$Port   probe: HTTP $code" -ForegroundColor Green
Write-Host "     dashboard: http://127.0.0.1:9090"
