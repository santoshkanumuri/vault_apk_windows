# Nuvori 2.1.8 and later register the host by themselves (Settings > Browser extension >
# Connect browsers). This script remains for development builds. The extension's manifest key
# fixes its ID, so -ExtensionId is needed only for an older copy without that key.
param(
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId = 'kapellkbongejlglcengbmjnpblemmjm',

    [string]$HostExecutable = '',

    [switch]$Chrome,
    [switch]$Brave,
    # Firefox: its own registry key and a manifest that lists add-on IDs, not extension origins.
    [switch]$Firefox,
    [string]$FirefoxId = 'password-fill@nuvori.santoshkanumuri.com'
)

$ErrorActionPreference = 'Stop'

if (-not $Chrome -and -not $Brave -and -not $Firefox) {
    $Chrome = $true
    $Brave = $true
}

if (-not $HostExecutable) {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Nuvori\nuvori-native-host.exe'),
        (Join-Path $env:ProgramFiles 'Nuvori\nuvori-native-host.exe'),
        (Join-Path $PSScriptRoot '..\src-tauri\target\release\nuvori-native-host.exe')
    )
    $HostExecutable = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $HostExecutable) { throw 'Nuvori native host was not found. Pass -HostExecutable with its installed path.' }
}
$resolvedHost = (Resolve-Path -LiteralPath $HostExecutable).Path
$hostDirectory = Join-Path $env:LOCALAPPDATA 'Nuvori\BrowserHost'
$manifestPath = Join-Path $hostDirectory 'com.nuvori.desktop.json'
New-Item -ItemType Directory -Path $hostDirectory -Force | Out-Null
# A host inside an installed Nuvori folder is used where it is, so installing an update also
# updates the browser host. Other hosts (a dev build) are copied next to the manifest.
$installFolders = @((Join-Path $env:LOCALAPPDATA 'Nuvori'), (Join-Path $env:ProgramFiles 'Nuvori')) |
    ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') }
$hostFolder = [System.IO.Path]::GetDirectoryName($resolvedHost).TrimEnd('\')
$installedHost = if ($installFolders | Where-Object { [string]::Equals($_, $hostFolder, [StringComparison]::OrdinalIgnoreCase) }) {
    $resolvedHost
} else {
    Join-Path $hostDirectory 'nuvori-native-host.exe'
}
if (-not [string]::Equals($resolvedHost, $installedHost, [StringComparison]::OrdinalIgnoreCase)) {
    Copy-Item -LiteralPath $resolvedHost -Destination $installedHost -Force
}

$manifest = [ordered]@{
    name = 'com.nuvori.desktop'
    description = 'Nuvori browser bridge'
    path = $installedHost
    type = 'stdio'
    allowed_origins = @("chrome-extension://$ExtensionId/")
}
$manifestJson = ConvertTo-Json -InputObject $manifest -Depth 4
[System.IO.File]::WriteAllText($manifestPath, $manifestJson, [System.Text.UTF8Encoding]::new($false))

$registryPaths = @()
if ($Chrome) { $registryPaths += 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.nuvori.desktop' }
if ($Brave) { $registryPaths += 'HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.nuvori.desktop' }
foreach ($registryPath in $registryPaths) {
    New-Item -Path $registryPath -Force | Out-Null
    Set-Item -Path $registryPath -Value $manifestPath
}

if ($Firefox) {
    $firefoxManifestPath = Join-Path $hostDirectory 'com.nuvori.desktop.firefox.json'
    $firefoxManifest = [ordered]@{
        name = 'com.nuvori.desktop'
        description = 'Nuvori browser bridge'
        path = $installedHost
        type = 'stdio'
        allowed_extensions = @($FirefoxId)
    }
    [System.IO.File]::WriteAllText($firefoxManifestPath, (ConvertTo-Json -InputObject $firefoxManifest -Depth 4), [System.Text.UTF8Encoding]::new($false))
    $firefoxKey = 'HKCU:\Software\Mozilla\NativeMessagingHosts\com.nuvori.desktop'
    New-Item -Path $firefoxKey -Force | Out-Null
    Set-Item -Path $firefoxKey -Value $firefoxManifestPath
    Write-Output "Registered com.nuvori.desktop for Firefox add-on $FirefoxId at $firefoxManifestPath"
}

Write-Output "Registered com.nuvori.desktop for extension $ExtensionId at $manifestPath"
