# vpn-off.ps1  --  stop mihomo and switch the Windows system proxy off
$ErrorActionPreference = 'SilentlyContinue'
$reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

Get-Process mihomo | Stop-Process -Force
Start-Sleep -Milliseconds 300

Set-ItemProperty -Path $reg -Name ProxyEnable -Value 0 -Type DWord
Remove-ItemProperty -Path $reg -Name ProxyServer -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $reg -Name ProxyOverride -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $reg -Name AutoConfigURL -ErrorAction SilentlyContinue

if (-not ('WinInetRefresh' -as [type])) {
    Add-Type -Namespace W -Name WinInetRefresh -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(System.IntPtr h, int o, System.IntPtr b, int l);
'@
}
[W.WinInetRefresh]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[W.WinInetRefresh]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null

$code = curl.exe -s -o NUL --max-time 8 -w "%{http_code}" http://www.gstatic.com/generate_204
Write-Host ""
Write-Host "[OK] proxy OFF, direct network restored (direct probe: HTTP $code)" -ForegroundColor Yellow
