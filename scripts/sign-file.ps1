# Tauri's bundle.windows.signCommand calls this for every binary and installer it signs
# (security review M-07). Configuration comes from the environment: see signing.ps1.
param([Parameter(Mandatory = $true, Position = 0)][string]$Path)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'signing.ps1')
Invoke-NuvoriSign -Path $Path
