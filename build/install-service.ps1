<#
.SYNOPSIS
  Installs TheFirewall without the MSI: run from the folder that contains TheFirewall.Service.exe
  (for example a published or downloaded zip). Must be run as administrator.
#>
param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
$service = Join-Path $PSScriptRoot "TheFirewall.Service.exe"
if (-not (Test-Path $service)) { $service = Join-Path (Get-Location) "TheFirewall.Service.exe" }
if (-not (Test-Path $service)) { throw "TheFirewall.Service.exe not found." }

if ($Uninstall) {
    & $service uninstall
    & $service unregister-tray
} else {
    & $service install
    & $service register-tray (Join-Path (Split-Path $service) "TheFirewall.exe")
}
