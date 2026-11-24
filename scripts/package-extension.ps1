param(
    [string]$Destination = (Join-Path $PSScriptRoot '..\artifacts'),
    # Chrome Web Store upload: the store refuses a manifest with a "key" field on a new item.
    [switch]$Store,
    # Firefox Add-ons (addons.mozilla.org) upload: an event-page background, the add-on ID, and
    # the data-collection statement Firefox requires. Same code as the Chrome package.
    [switch]$Firefox
)

# The Firefox add-on's permanent ID. The Windows app trusts it (src-tauri/src/browser_setup.rs).
$FirefoxId = 'password-fill@nuvori.santoshkanumuri.com'

$ErrorActionPreference = 'Stop'

# Zips the browser extension with manifest.json at the root (for "Load unpacked" after
# extracting, or a store upload). Tests and docs stay out. Prints the zip's path.
$extension = (Resolve-Path (Join-Path $PSScriptRoot '..\extension')).Path
$manifestText = Get-Content -LiteralPath (Join-Path $extension 'manifest.json') -Raw
$version = ($manifestText | ConvertFrom-Json).version
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$name = if ($Firefox) { "Nuvori_extension_{0}_firefox.zip" } elseif ($Store) { "Nuvori_extension_{0}_chrome_web_store.zip" } else { "Nuvori_extension_{0}.zip" }
$zip = Join-Path (Resolve-Path $Destination).Path ($name -f $version)

# Copy the shipped files into a clean folder, keeping subfolders such as icons\.
$stage = Join-Path ([IO.Path]::GetTempPath()) ("nuvori-extension-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    $files = Get-ChildItem -LiteralPath $extension -File -Recurse | Where-Object {
        $relative = $_.FullName.Substring($extension.Length + 1)
        $_.Name -notlike '*.test.mjs' -and $_.Extension -ne '.md' -and $relative -notlike 'fixtures\*' -and
            # Firefox has no offscreen documents; its background page clears the clipboard itself.
            -not ($Firefox -and $_.Name -in @('offscreen.html', 'offscreen.js'))
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
    if ($Firefox) {
        $manifest = $manifestText | ConvertFrom-Json
        # Chrome-only keys: the unpacked-ID key, the Chrome version floor, the offscreen permission.
        foreach ($property in 'key', 'minimum_chrome_version') { $manifest.PSObject.Properties.Remove($property) }
        $manifest.permissions = @($manifest.permissions | Where-Object { $_ -ne 'offscreen' })
        # Firefox runs the background as an event page, not a service worker.
        $manifest.background = [ordered]@{ scripts = @('signins.js', 'background.js') }
        # 140 (ESR): data_collection_permissions; also covers popover (125), sender.origin (126)
        # and match_origin_as_fallback (128).
        # Mozilla counts data "handled outside the add-on or the local browser" as transmitted, and
        # Nuvori for Windows is outside the browser: declare what reaches it (the same types as the
        # Chrome Web Store disclosure). Nothing goes to the developer or any server.
        $manifest | Add-Member -NotePropertyName browser_specific_settings -NotePropertyValue ([ordered]@{
            gecko = [ordered]@{
                id = $FirefoxId
                strict_min_version = '140.0'
                data_collection_permissions = [ordered]@{
                    required = @('authenticationInfo', 'personallyIdentifyingInfo', 'financialAndPaymentInfo', 'websiteContent')
                }
            }
        })
        $json = $manifest | ConvertTo-Json -Depth 20
        [IO.File]::WriteAllText((Join-Path $stage 'manifest.json'), $json, [Text.UTF8Encoding]::new($false))
        $null = Get-Content -LiteralPath (Join-Path $stage 'manifest.json') -Raw | ConvertFrom-Json
    }
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    if ($Firefox) {
        # addons.mozilla.org rejects backslashes in archive paths, which Compress-Archive writes on
        # Windows PowerShell 5.1 for files in subfolders; write the entries with forward slashes.
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $archive = [IO.Compression.ZipFile]::Open($zip, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse) {
                $entry = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
                $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $entry, [IO.Compression.CompressionLevel]::Optimal)
            }
        } finally { $archive.Dispose() }
    } else {
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
    }
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
$zip
