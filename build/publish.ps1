<#
.SYNOPSIS
  Publishes TheFirewall (app + service) and builds the MSI installer.

.EXAMPLE
  ./build/publish.ps1 -Version 1.2.0
  ./build/publish.ps1 -Runtime win-arm64 -SkipInstaller
#>
param(
    [string]$Version = "1.0.0",
    [string]$Configuration = "Release",
    [ValidateSet("win-x64", "win-arm64")]
    [string]$Runtime = "win-x64",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$publishDir = Join-Path $root "artifacts/publish/$Runtime"
$installerDir = Join-Path $root "artifacts/installer"

if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }

# App and service share one self-contained runtime in the same folder.
$common = @("-c", $Configuration, "-r", $Runtime, "--self-contained", "true", "-o", $publishDir,
            "-p:Version=$Version", "-p:DebugType=none", "-p:GenerateDocumentationFile=false")

Write-Host "Publishing app..." -ForegroundColor Cyan
dotnet publish (Join-Path $root "src/TheFirewall.App/TheFirewall.App.csproj") @common
if ($LASTEXITCODE -ne 0) { throw "App publish failed" }

Write-Host "Publishing service..." -ForegroundColor Cyan
dotnet publish (Join-Path $root "src/TheFirewall.Service/TheFirewall.Service.csproj") @common
if ($LASTEXITCODE -ne 0) { throw "Service publish failed" }

if ($SkipInstaller) { return }

Write-Host "Building installer..." -ForegroundColor Cyan
$platform = if ($Runtime -eq "win-arm64") { "ARM64" } else { "x64" }
dotnet build (Join-Path $root "installer/TheFirewall.Installer/TheFirewall.Installer.wixproj") -c $Configuration `
    -p:ProductVersion=$Version -p:Platform=$platform -p:PublishDir="$publishDir\" -o $installerDir
if ($LASTEXITCODE -ne 0) { throw "Installer build failed" }

Get-ChildItem $installerDir -Filter *.msi | ForEach-Object { Write-Host "Installer: $($_.FullName)" -ForegroundColor Green }
