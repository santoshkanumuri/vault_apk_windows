param(
    [string]$Destination = (Join-Path $PSScriptRoot '..\artifacts'),
    # Chrome Web Store upload: the store refuses a manifest with a "key" field on a new item.
    [switch]$Store
)

$ErrorActionPreference = 'Stop'

# Zips the browser extension with manifest.json at the root (for "Load unpacked" after
# extracting, or a store upload). Tests and docs stay out. Prints the zip's path.
$extension = (Resolve-Path (Join-Path $PSScriptRoot '..\extension')).Path
$manifestText = Get-Content -LiteralPath (Join-Path $extension 'manifest.json') -Raw
$version = ($manifestText | ConvertFrom-Json).version
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$name = if ($Store) { "Nuvori_extension_{0}_chrome_web_store.zip" } else { "Nuvori_extension_{0}.zip" }
$zip = Join-Path (Resolve-Path $Destination).Path ($name -f $version)

# Copy the shipped files into a clean folder, keeping subfolders such as icons\.
$stage = Join-Path ([IO.Path]::GetTempPath()) ("nuvori-extension-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    $files = Get-ChildItem -LiteralPath $extension -File -Recurse | Where-Object {
        $relative = $_.FullName.Substring($extension.Length + 1)
        $_.Name -notlike '*.test.mjs' -and $_.Extension -ne '.md' -and $relative -notlike 'fixtures\*'
    }
    foreach ($file in $files) {
        $target = Join-Path $stage $file.FullName.Substring($extension.Length + 1)
        New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
    if ($Store) {
        # Remove only the "key" line, so the rest of the manifest stays byte for byte the same.
        $lines = $manifestText -split "`r?`n" | Where-Object { $_ -notmatch '^\s*"key"\s*:' }
        [IO.File]::WriteAllText((Join-Path $stage 'manifest.json'), ($lines -join "`n"), [Text.UTF8Encoding]::new($false))
        $null = Get-Content -LiteralPath (Join-Path $stage 'manifest.json') -Raw | ConvertFrom-Json
    }
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
$zip
