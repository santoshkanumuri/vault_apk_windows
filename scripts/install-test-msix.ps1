param(
    # Remove the test package (and, when run as administrator, its trusted test certificate).
    [switch]$Uninstall,
    [string]$IdentityName = 'Nuvori.Desktop.Test',
    [string]$Publisher = 'CN=Nuvori Test'
)

$ErrorActionPreference = 'Stop'

# Installs the test MSIX from artifacts\msix on this PC.
#   Developer Mode on : registers the loose files. No administrator rights and no certificate.
#   Developer Mode off: run from an administrator PowerShell. The test certificate is added to
#                       this PC's Trusted People store, then the signed package is installed.
# The vault is not touched: the package uses the same %APPDATA%\com.nuvori.desktop folder.
# Quit Nuvori first (tray icon > Quit Nuvori), so the vault backup below is consistent.

$output = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'artifacts\msix'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Uninstall) {
    Get-AppxPackage -Name $IdentityName | Remove-AppxPackage
    if ($admin) {
        Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { $_.Subject -eq $Publisher } | Remove-Item
    }
    Write-Host 'Test package removed. The vault and the installer build are unchanged.'
    return
}

if (Get-Process -Name nuvori -ErrorAction SilentlyContinue) {
    throw 'Nuvori is running. Quit it from the tray icon (Quit Nuvori), then run this script again.'
}

# Keep a copy of the vault folder before the first run of a new build.
$vault = Join-Path $env:APPDATA 'com.nuvori.desktop'
if (Test-Path -LiteralPath $vault) {
    $backup = "$vault.backup-" + (Get-Date -Format 'yyyyMMdd-HHmmss')
    Copy-Item -LiteralPath $vault -Destination $backup -Recurse
    Write-Host "Vault folder copied to $backup"
}

$developerMode = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -ErrorAction SilentlyContinue).AllowDevelopmentWithoutDevLicense -eq 1

if ($developerMode) {
    Get-AppxPackage -Name $IdentityName | Remove-AppxPackage
    Add-AppxPackage -Register (Join-Path $output 'layout\AppxManifest.xml')
} else {
    # Update in place, as the Store does: Windows keeps the passkey provider turned on.
    if (-not $admin) {
        throw 'Turn on Developer Mode (Settings > System > For developers), or run this script from an administrator PowerShell.'
    }
    $package = Get-ChildItem -LiteralPath $output -Filter 'Nuvori_*_x64.msix' | Sort-Object LastWriteTime | Select-Object -Last 1
    if (-not $package) { throw 'No package found. Run scripts\package-msix.ps1 first.' }
    Import-Certificate -FilePath (Join-Path $output 'Nuvori-Test.cer') -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
    Add-AppxPackage -Path $package.FullName -ForceUpdateFromAnyVersion
}

$installed = Get-AppxPackage -Name $IdentityName
Write-Host "Installed $($installed.PackageFullName)"
Write-Host 'Next: open Nuvori from the Start menu and unlock it. In Nuvori, open'
Write-Host 'Settings > Security > Passkeys in Windows. If it shows Turn on, choose it.'
