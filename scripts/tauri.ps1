param([Parameter(ValueFromRemainingArguments = $true)][string[]]$TauriArgs)

. (Join-Path $PSScriptRoot 'ensure-perl.ps1')
& (Join-Path $PSScriptRoot '..\node_modules\.bin\tauri.cmd') @TauriArgs
exit $LASTEXITCODE
