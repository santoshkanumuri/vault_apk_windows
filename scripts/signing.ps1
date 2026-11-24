# Code signing for Nuvori for Windows releases (security review M-07).
#
# Dot-source this file. Signing is configured only through environment variables, so no
# certificate, password or account detail is ever written to the repository:
#
#   NUVORI_SIGN_MODE                 'certificate' or 'trusted-signing'. Unset: unsigned build.
#   NUVORI_REQUIRE_SIGNING           '1' makes an unconfigured or failed signing stop the build.
#                                    Set it on the machine that builds public releases.
#   NUVORI_SIGN_TIMESTAMP_URL        RFC 3161 timestamp server of your certificate's CA
#                                    (for example http://timestamp.digicert.com). Required.
#
#   Mode 'certificate' (a code signing certificate from a CA, on a hardware token or in the
#   Windows certificate store):
#   NUVORI_SIGN_CERT_THUMBPRINT      SHA-1 thumbprint of the certificate in Cert:\CurrentUser\My
#                                    (or Cert:\LocalMachine\My). The private key never leaves the
#                                    store or token; signtool asks the token for its PIN itself.
#
#   Mode 'trusted-signing' (Azure Trusted Signing):
#   NUVORI_TRUSTED_SIGNING_DLIB      Full path to Azure.CodeSigning.Dlib.dll
#                                    (from the Microsoft.Trusted.Signing.Client package).
#   NUVORI_TRUSTED_SIGNING_METADATA  Full path to the metadata.json that names the Endpoint,
#                                    CodeSigningAccountName and CertificateProfileName. Sign in
#                                    with `az login` (or set the Azure identity variables) first.
#   NUVORI_SIGNER_NAME               The publisher name in the Trusted Signing certificate
#                                    (its common name). Required in this mode, because the
#                                    certificate itself changes every few days.
#
# What the app trusts (src-tauri/src/signer.rs) comes from NUVORI_SIGNER_SHA256 (worked out here
# from NUVORI_SIGN_CERT_THUMBPRINT, plus any hashes you list in it yourself, for example the next
# certificate before a renewal) and NUVORI_SIGNER_NAME.

function Get-NuvoriSigntool {
    if ($env:NUVORI_SIGNTOOL -and (Test-Path -LiteralPath $env:NUVORI_SIGNTOOL)) { return $env:NUVORI_SIGNTOOL }
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $found = Get-ChildItem -LiteralPath $kits -Directory -ErrorAction SilentlyContinue |
        Sort-Object { [version]($_.Name -replace '[^0-9.]', '') } -Descending |
        ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $found) { throw 'signtool.exe was not found. Install the Windows SDK or set NUVORI_SIGNTOOL.' }
    return $found
}

function Get-NuvoriSigningCertificate {
    $thumbprint = ($env:NUVORI_SIGN_CERT_THUMBPRINT -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($thumbprint.Length -ne 40) { throw 'NUVORI_SIGN_CERT_THUMBPRINT must be the 40-digit SHA-1 thumbprint of the signing certificate.' }
    $certificate = Get-ChildItem -LiteralPath Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $thumbprint } | Select-Object -First 1
    if (-not $certificate) { throw "No certificate with thumbprint $thumbprint in the CurrentUser or LocalMachine personal store." }
    if (-not $certificate.HasPrivateKey) { throw "The certificate $thumbprint has no private key on this PC (or its token is not plugged in)." }
    $codeSigning = $certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }
    if (-not $codeSigning) { throw "The certificate $thumbprint is not a code signing certificate." }
    return $certificate
}

# The signing configuration, or $null for an unsigned build. Checks it before anything is built.
function Get-NuvoriSigning {
    $mode = $env:NUVORI_SIGN_MODE
    if (-not $mode) {
        if ($env:NUVORI_REQUIRE_SIGNING -eq '1') { throw 'NUVORI_REQUIRE_SIGNING is 1, but NUVORI_SIGN_MODE is not set.' }
        Write-Warning 'Code signing is not configured (NUVORI_SIGN_MODE). This build is unsigned and only for testing.'
        return $null
    }
    if (-not $env:NUVORI_SIGN_TIMESTAMP_URL -or $env:NUVORI_SIGN_TIMESTAMP_URL -notmatch '^https?://') {
        throw 'NUVORI_SIGN_TIMESTAMP_URL must be the http(s) address of your CA''s RFC 3161 timestamp server.'
    }
    $hashes = @()
    if ($env:NUVORI_SIGNER_SHA256) { $hashes += ($env:NUVORI_SIGNER_SHA256 -split '[,;\s]+' | Where-Object { $_ }) }
    switch ($mode) {
        'certificate' {
            $certificate = Get-NuvoriSigningCertificate
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try { $hash = -join ($sha256.ComputeHash($certificate.RawData) | ForEach-Object { $_.ToString('x2') }) } finally { $sha256.Dispose() }
            if ($hashes -notcontains $hash) { $hashes += $hash }
            $name = $certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            Write-Host "Signing with '$name' (certificate SHA-256 $hash, valid until $($certificate.NotAfter.ToString('yyyy-MM-dd')))."
        }
        'trusted-signing' {
            foreach ($variable in 'NUVORI_TRUSTED_SIGNING_DLIB', 'NUVORI_TRUSTED_SIGNING_METADATA') {
                $value = [Environment]::GetEnvironmentVariable($variable)
                if (-not $value -or -not (Test-Path -LiteralPath $value)) { throw "$variable must be the full path of an existing file." }
            }
            if (-not $env:NUVORI_SIGNER_NAME) { throw 'NUVORI_SIGNER_NAME must hold the publisher name of the Trusted Signing certificate.' }
            Write-Host "Signing with Azure Trusted Signing as '$($env:NUVORI_SIGNER_NAME)'."
        }
        default { throw "NUVORI_SIGN_MODE must be 'certificate' or 'trusted-signing', not '$mode'." }
    }
    return [pscustomobject]@{ Mode = $mode; SignerHashes = ($hashes -join ','); SignerName = $env:NUVORI_SIGNER_NAME }
}

# Signs one file with SHA-256 and an RFC 3161 timestamp, then checks the signature.
function Invoke-NuvoriSign {
    param([Parameter(Mandatory = $true)][string]$Path)
    $signtool = Get-NuvoriSigntool
    $file = (Resolve-Path -LiteralPath $Path).Path
    $arguments = @('sign', '/fd', 'SHA256', '/tr', $env:NUVORI_SIGN_TIMESTAMP_URL, '/td', 'SHA256', '/d', 'Nuvori')
    switch ($env:NUVORI_SIGN_MODE) {
        'certificate' { $arguments += @('/sha1', (Get-NuvoriSigningCertificate).Thumbprint) }
        'trusted-signing' { $arguments += @('/dlib', $env:NUVORI_TRUSTED_SIGNING_DLIB, '/dmdf', $env:NUVORI_TRUSTED_SIGNING_METADATA) }
        default { throw 'Code signing is not configured (NUVORI_SIGN_MODE).' }
    }
    & $signtool @arguments $file
    if ($LASTEXITCODE -ne 0) { throw "signtool could not sign $file (exit code $LASTEXITCODE)." }
    Test-NuvoriSignature -Path $file
}

# Throws unless Windows verifies a timestamped signature by this release's signer on the file.
function Test-NuvoriSignature {
    param([Parameter(Mandatory = $true)][string]$Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid') { throw "$Path is not validly signed: $($signature.Status) $($signature.StatusMessage)" }
    if (-not $signature.TimeStamperCertificate) { throw "$Path is signed without a timestamp, so it would stop verifying when the certificate expires." }
    $certificate = $signature.SignerCertificate
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = -join ($sha256.ComputeHash($certificate.RawData) | ForEach-Object { $_.ToString('x2') }) } finally { $sha256.Dispose() }
    $name = $certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $hashes = @($env:NUVORI_SIGNER_SHA256 -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { ($_ -replace '[^0-9A-Fa-f]', '').ToLowerInvariant() })
    if (($hashes -notcontains $hash) -and ($name -cne $env:NUVORI_SIGNER_NAME)) {
        throw "$Path is signed by '$name' ($hash), which this build does not trust. The app would refuse it."
    }
    Write-Host "Signed: $(Split-Path -Leaf $Path) by '$name'"
}
