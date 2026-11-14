# vpn-toggle.ps1  --  one-click on/off, meant for a desktop shortcut
$root = $PSScriptRoot
$running = Get-Process mihomo -ErrorAction SilentlyContinue
if ($running) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'vpn-off.ps1')
} else {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'vpn-on.ps1')
}
