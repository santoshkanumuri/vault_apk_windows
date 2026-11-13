if (-not (Get-Command perl -ErrorAction SilentlyContinue)) {
    $portable = Join-Path $env:LOCALAPPDATA 'NuvoriBuildTools\Perl\perl\bin'
    if (-not (Test-Path -LiteralPath (Join-Path $portable 'perl.exe'))) {
        throw 'Perl is required to build vendored OpenSSL. Install Strawberry Perl, then reopen the terminal.'
    }
    $env:Path = "$portable;$env:Path"
}
$env:LC_ALL = 'C'
