param(
    # Package identity. For the Store, use the values Partner Center gives you.
    [string]$IdentityName = 'Nuvori.Desktop.Test',
    [string]$Publisher = 'CN=Nuvori Test',
    [string]$PublisherDisplayName = 'Nuvori',
    # Skip the compile step and package the release build that is already there.
    [switch]$SkipBuild,
    # Skip signing (a Store upload is signed by the Store).
    [switch]$NoSign,
    # Fourth version part, so a fixed test package installs over the same app version.
    # The Store requires 0.
    [ValidateRange(0, 65535)]
    [int]$Revision = 0
)

$ErrorActionPreference = 'Stop'

# Builds an MSIX of Nuvori for Windows. The package gives the app an identity, which the
# Windows passkey provider needs. It contains the same nuvori.exe as the installers, the browser
# host, and the pairing helper.
#
# Output (in artifacts\msix):
#   layout\                      loose files with AppxManifest.xml (for Developer Mode installs)
#   Nuvori_<version>_x64.msix    the package, signed with a local test certificate
#   Nuvori-Test.cer              the public test certificate

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$version = (Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).version
$release = Join-Path $root 'src-tauri\target\release'
$helper = Join-Path $root 'pairing-helper\publish\Nuvori.PairingHelper.exe'

if (-not $SkipBuild) {
    . (Join-Path $PSScriptRoot 'ensure-perl.ps1')
    dotnet publish (Join-Path $root 'pairing-helper\Nuvori.PairingHelper.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o (Split-Path $helper)
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    cargo build --manifest-path (Join-Path $root 'src-tauri\Cargo.toml') --release --bin nuvori-native-host
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Push-Location $root
    try { npm run tauri -- build --no-bundle --config src-tauri/tauri.pairing.conf.json } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

foreach ($file in @((Join-Path $release 'nuvori.exe'), (Join-Path $release 'nuvori-native-host.exe'), $helper)) {
    if (-not (Test-Path -LiteralPath $file)) { throw "Missing build output: $file" }
}

$kit = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'x64\makeappx.exe') } |
    Sort-Object { [version]$_.Name } | Select-Object -Last 1
if (-not $kit) { throw 'The Windows SDK (makeappx.exe) is not installed.' }
$makeappx = Join-Path $kit.FullName 'x64\makeappx.exe'
$signtool = Join-Path $kit.FullName 'x64\signtool.exe'

$output = Join-Path $root 'artifacts\msix'
$layout = Join-Path $output 'layout'
if (Test-Path -LiteralPath $layout) { Remove-Item -LiteralPath $layout -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $layout 'Assets'), (Join-Path $layout 'pairing') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $release 'nuvori.exe'), (Join-Path $release 'nuvori-native-host.exe') -Destination $layout
Copy-Item -LiteralPath $helper -Destination (Join-Path $layout 'pairing')
foreach ($logo in 'StoreLogo.png', 'Square44x44Logo.png', 'Square150x150Logo.png') {
    Copy-Item -LiteralPath (Join-Path $root "src-tauri\icons\$logo") -Destination (Join-Path $layout 'Assets')
}

# The class ID must equal passkey_plugin::CLSID in src-tauri\src\passkey_plugin.rs.
# Write virtualization is off so the package uses the same vault folder and browser registration
# as the installer build (%APPDATA%\com.nuvori.desktop). The Store asks for a reason for the
# `unvirtualizedResources` capability: the vault must survive an uninstall and stay shared with
# the installer build.
$manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  xmlns:com="http://schemas.microsoft.com/appx/manifest/com/windows10"
  xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
  xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10"
  xmlns:desktop6="http://schemas.microsoft.com/appx/manifest/desktop/windows10/6"
  IgnorableNamespaces="uap rescap com uap3 desktop desktop6">
  <Identity Name="$IdentityName" Publisher="$Publisher" Version="$version.$Revision" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Nuvori</DisplayName>
    <PublisherDisplayName>$PublisherDisplayName</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
    <desktop6:FileSystemWriteVirtualization>disabled</desktop6:FileSystemWriteVirtualization>
    <desktop6:RegistryWriteVirtualization>disabled</desktop6:RegistryWriteVirtualization>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0" />
  </Dependencies>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Applications>
    <Application Id="Nuvori" Executable="nuvori.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Nuvori" Description="Your private vault on Windows"
        BackgroundColor="transparent" Square150x150Logo="Assets\Square150x150Logo.png"
        Square44x44Logo="Assets\Square44x44Logo.png" />
      <Extensions>
        <com:Extension Category="windows.comServer">
          <com:ComServer>
            <com:ExeServer Executable="nuvori.exe" DisplayName="Nuvori passkeys" Arguments="-PluginActivated">
              <com:Class Id="6f2b8f0e-4c3a-4d7b-9a51-2e8d1c7f4b90" DisplayName="Nuvori passkeys" />
            </com:ExeServer>
          </com:ComServer>
        </com:Extension>
      </Extensions>
    </Application>
    <!-- The browser extension's native host. The alias puts nuvori-native-host.exe in
         %LOCALAPPDATA%\Microsoft\WindowsApps, where the browser can start it. -->
    <Application Id="BrowserHost" Executable="nuvori-native-host.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Nuvori browser bridge" Description="Connects the Nuvori browser extension"
        BackgroundColor="transparent" Square150x150Logo="Assets\Square150x150Logo.png"
        Square44x44Logo="Assets\Square44x44Logo.png" AppListEntry="none" />
      <Extensions>
        <uap3:Extension Category="windows.appExecutionAlias" Executable="nuvori-native-host.exe" EntryPoint="Windows.FullTrustApplication">
          <uap3:AppExecutionAlias>
            <desktop:ExecutionAlias Alias="nuvori-native-host.exe" />
          </uap3:AppExecutionAlias>
        </uap3:Extension>
      </Extensions>
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
    <rescap:Capability Name="unvirtualizedResources" />
  </Capabilities>
</Package>
"@
[System.IO.File]::WriteAllText((Join-Path $layout 'AppxManifest.xml'), $manifest, (New-Object System.Text.UTF8Encoding($false)))

$package = Join-Path $output ("Nuvori_{0}.{1}_x64.msix" -f $version, $Revision)
& $makeappx pack /d $layout /p $package /o | Out-Null
if ($LASTEXITCODE -ne 0) { throw "makeappx failed with exit code $LASTEXITCODE" }

if (-not $NoSign) {
    # A local test certificate in the current user's store. Its subject must equal the Publisher.
    $certificate = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $Publisher -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1
    if (-not $certificate) {
        $certificate = New-SelfSignedCertificate -Type Custom -Subject $Publisher -KeyUsage DigitalSignature `
            -FriendlyName 'Nuvori MSIX test signing' -CertStoreLocation 'Cert:\CurrentUser\My' `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
    }
    & $signtool sign /fd SHA256 /sha1 $certificate.Thumbprint $package | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE" }
    Export-Certificate -Cert $certificate -FilePath (Join-Path $output 'Nuvori-Test.cer') | Out-Null
}

Write-Host "MSIX ready: $package"
Write-Host "Install it for testing with scripts\install-test-msix.ps1"
