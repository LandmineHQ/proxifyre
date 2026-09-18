param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Administrator privileges are required to install the WFP callout driver."
}

$serviceName = "ProxiFyreWfp"
$sysPath = Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "artifacts\native\$Configuration\ProxiFyre.Wfp.sys"

if ($Uninstall) {
    & sc.exe stop $serviceName | Out-Null
    & sc.exe delete $serviceName | Out-Null
    Write-Host "Removed $serviceName."
    exit 0
}

if (!(Test-Path -LiteralPath $sysPath)) {
    throw "Driver was not found: $sysPath. Run .\scripts\build-wfp.ps1 -Configuration $Configuration first."
}

& sc.exe query $serviceName | Out-Null
if ($LASTEXITCODE -ne 0) {
    & sc.exe create $serviceName type= kernel start= demand binPath= "$sysPath" DisplayName= "ProxiFyre WFP Classifier"
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

& sc.exe start $serviceName
if ($LASTEXITCODE -ne 0) {
    throw "Failed to start $serviceName. The driver must be signed and test signing must be enabled for development builds."
}

Write-Host "Started $serviceName."
