. (Join-Path $PSScriptRoot 'ensure-perl.ps1')
$project = Join-Path $PSScriptRoot '..\pairing-helper\Nuvori.PairingHelper.csproj'
$output = Join-Path $PSScriptRoot '..\pairing-helper\publish'

dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $output
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cargo build --manifest-path (Join-Path $PSScriptRoot '..\src-tauri\Cargo.toml') --release --bin nuvori-native-host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

npm run tauri -- build --config src-tauri/tauri.pairing.conf.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$version = (Get-Content -LiteralPath (Join-Path $root "package.json") -Raw | ConvertFrom-Json).version
$artifacts = Join-Path $root "artifacts"
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
$installers = @(
    (Join-Path $root ("src-tauri/target/release/bundle/nsis/Nuvori_{0}_x64-setup.exe" -f $version)),
    (Join-Path $root ("src-tauri/target/release/bundle/msi/Nuvori_{0}_x64_en-US.msi" -f $version))
)
$checksums = foreach ($installer in $installers) {
    $name = Split-Path $installer -Leaf
    $destination = Join-Path $artifacts $name
    Copy-Item -LiteralPath $installer -Destination $destination -Force -ErrorAction Stop
    "{0}  {1}" -f (Get-FileHash -LiteralPath $destination -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant(), $name
}
$extensionZip = & (Join-Path $PSScriptRoot 'package-extension.ps1') -Destination $artifacts
$checksums += "{0}  {1}" -f (Get-FileHash -LiteralPath $extensionZip -Algorithm SHA256).Hash.ToLowerInvariant(), (Split-Path $extensionZip -Leaf)
$checksums | Set-Content -LiteralPath (Join-Path $artifacts "SHA256SUMS-$version.txt") -Encoding ascii
Write-Host "Installers ready to share in $artifacts"
