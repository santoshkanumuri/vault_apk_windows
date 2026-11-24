. (Join-Path $PSScriptRoot 'ensure-perl.ps1')
. (Join-Path $PSScriptRoot 'signing.ps1')
$ErrorActionPreference = 'Stop'

# Security review M-07: signing is checked before anything is built, so a release build with
# NUVORI_REQUIRE_SIGNING=1 never produces unsigned installers. See docs/DISTRIBUTION.md.
$signing = Get-NuvoriSigning
if ($signing) {
    # Built into the app and the native host: the signers whose helper, browser host and app
    # processes Nuvori will talk to. See src-tauri/src/signer.rs.
    $env:NUVORI_SIGNER_SHA256 = $signing.SignerHashes
    if ($signing.SignerName) { $env:NUVORI_SIGNER_NAME = $signing.SignerName } else { Remove-Item Env:NUVORI_SIGNER_NAME -ErrorAction SilentlyContinue }
} else {
    Remove-Item Env:NUVORI_SIGNER_SHA256, Env:NUVORI_SIGNER_NAME -ErrorAction SilentlyContinue
}
$project = Join-Path $PSScriptRoot '..\pairing-helper\Nuvori.PairingHelper.csproj'
$output = Join-Path $PSScriptRoot '..\pairing-helper\publish'

dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $output
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# The pairing helper is bundled as a resource, which Tauri does not sign, so it is signed here.
if ($signing) { Invoke-NuvoriSign -Path (Join-Path $output 'Nuvori.PairingHelper.exe') }

cargo build --manifest-path (Join-Path $PSScriptRoot '..\src-tauri\Cargo.toml') --release --bin nuvori-native-host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$buildConfig = 'src-tauri/tauri.pairing.conf.json'
if ($signing) {
    # Tauri signs nuvori.exe, nuvori-native-host.exe, the uninstaller and both installers through
    # sign-file.ps1. The object form keeps paths with spaces in one argument.
    $config = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\src-tauri\tauri.pairing.conf.json') -Raw | ConvertFrom-Json
    $windows = [pscustomobject]@{ signCommand = [pscustomobject]@{
        cmd = 'powershell'
        args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Resolve-Path (Join-Path $PSScriptRoot 'sign-file.ps1')).Path, '%1')
    } }
    $config.bundle | Add-Member -NotePropertyName windows -NotePropertyValue $windows -Force
    $buildConfig = Join-Path ([System.IO.Path]::GetTempPath()) ("nuvori-signed-build-{0}.json" -f [guid]::NewGuid())
    $config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $buildConfig -Encoding utf8
}
try {
    npm run tauri -- build --config $buildConfig
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    if ($signing) { Remove-Item -LiteralPath $buildConfig -Force -ErrorAction SilentlyContinue }
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$version = (Get-Content -LiteralPath (Join-Path $root "package.json") -Raw | ConvertFrom-Json).version
$artifacts = Join-Path $root "artifacts"
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
$installers = @(
    (Join-Path $root ("src-tauri/target/release/bundle/nsis/Nuvori_{0}_x64-setup.exe" -f $version)),
    (Join-Path $root ("src-tauri/target/release/bundle/msi/Nuvori_{0}_x64_en-US.msi" -f $version))
)
if ($signing) {
    # Check every shipped executable, not only what signtool reported, before anything is copied.
    $release = Join-Path $root 'src-tauri/target/release'
    foreach ($file in @((Join-Path $release 'nuvori.exe'), (Join-Path $release 'nuvori-native-host.exe'),
            (Join-Path $root 'pairing-helper/publish/Nuvori.PairingHelper.exe')) + $installers) {
        Test-NuvoriSignature -Path $file
    }
}
$checksums = foreach ($installer in $installers) {
    $name = Split-Path $installer -Leaf
    $destination = Join-Path $artifacts $name
    Copy-Item -LiteralPath $installer -Destination $destination -Force -ErrorAction Stop
    "{0}  {1}" -f (Get-FileHash -LiteralPath $destination -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant(), $name
}
$extensionZip = & (Join-Path $PSScriptRoot 'package-extension.ps1') -Destination $artifacts
$checksums += "{0}  {1}" -f (Get-FileHash -LiteralPath $extensionZip -Algorithm SHA256).Hash.ToLowerInvariant(), (Split-Path $extensionZip -Leaf)
$sums = Join-Path $artifacts "SHA256SUMS-$version.txt"
$checksums | Set-Content -LiteralPath $sums -Encoding ascii
# Signed update channel: with a Tauri signing key set (TAURI_SIGNING_PRIVATE_KEY and, if it has
# one, TAURI_SIGNING_PRIVATE_KEY_PASSWORD), the checksum list gets a detached minisign signature
# that anyone with the public key in docs/DISTRIBUTION.md can check. The key never enters the repo.
if ($env:TAURI_SIGNING_PRIVATE_KEY) {
    npm run tauri -- signer sign $sums
    if ($LASTEXITCODE -ne 0) { throw 'Could not sign the checksum list with the Tauri signing key.' }
} elseif ($env:NUVORI_REQUIRE_SIGNING -eq '1') {
    Write-Warning 'TAURI_SIGNING_PRIVATE_KEY is not set, so the checksum list has no update signature.'
}
if (-not $signing) { Write-Warning 'These installers are unsigned. Do not publish them.' }
Write-Host "Installers ready to share in $artifacts"
