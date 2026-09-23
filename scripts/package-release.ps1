[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [string]$OutputDirectory = "release"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($Configuration -ne "Release") {
    throw "Release packaging requires -Configuration Release."
}

$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$ArtifactMoniker = "{0}_win-x64" -f $Configuration.ToLowerInvariant()
$SourceDirectory = Join-Path $Root "artifacts\bin\ProxiFyre\$ArtifactMoniker"
$NativeDirectory = Join-Path $Root "artifacts\native\$Configuration"

$OutputRoot = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    [System.IO.Path]::GetFullPath($OutputDirectory)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $Root $OutputDirectory))
}

$RootPrefix = $Root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $OutputRoot.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Release output must stay inside the repository: $OutputRoot"
}

$StageDirectory = Join-Path $OutputRoot "ProxiFyre"
$ArchivePath = Join-Path $OutputRoot "proxifyre-win-x64.zip"

$PackageFiles = @(
    [pscustomobject]@{ Name = "ProxiFyre.exe"; Source = $SourceDirectory }
    [pscustomobject]@{ Name = "ProxiFyre.dll"; Source = $SourceDirectory }
    [pscustomobject]@{ Name = "ProxiFyre.deps.json"; Source = $SourceDirectory }
    [pscustomobject]@{ Name = "ProxiFyre.runtimeconfig.json"; Source = $SourceDirectory }
    [pscustomobject]@{ Name = "ProxiFyre.Module.dll"; Source = $NativeDirectory }
    [pscustomobject]@{ Name = "WinDivert.dll"; Source = $NativeDirectory }
    [pscustomobject]@{ Name = "WinDivert64.sys"; Source = $NativeDirectory }
    [pscustomobject]@{ Name = "WinDivert-LICENSE.txt"; Source = $SourceDirectory }
    [pscustomobject]@{ Name = "THIRD_PARTY_NOTICES.md"; Source = $SourceDirectory }
    [pscustomobject]@{ Name = "LICENSE"; Source = $SourceDirectory }
    [pscustomobject]@{ Name = "manifest.json"; Source = $SourceDirectory }
    [pscustomobject]@{ Name = "UuPatchProfiles.json"; Source = $SourceDirectory }
)

$ExpectedNativeHashes = @{
    "WinDivert.dll" = "C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2"
    "WinDivert64.sys" = "8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2"
}

$MissingSources = @($PackageFiles | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $_.Source $_.Name) -PathType Leaf)
})
if ($MissingSources.Count -gt 0) {
    $names = $MissingSources | ForEach-Object { $_.Name }
    throw "Release inputs are missing: $($names -join ', '). Run .\scripts\proxifyre.ps1 build -Configuration Release first."
}

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
}

if (Test-Path -LiteralPath $StageDirectory) {
    $resolvedStage = (Resolve-Path -LiteralPath $StageDirectory).Path
    $outputPrefix = $OutputRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolvedStage.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove release staging path outside the output directory: $resolvedStage"
    }

    Remove-Item -LiteralPath $resolvedStage -Recurse -Force
}

Remove-Item -LiteralPath $ArchivePath -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $StageDirectory -Force | Out-Null

foreach ($file in $PackageFiles) {
    Copy-Item -LiteralPath (Join-Path $file.Source $file.Name) -Destination $StageDirectory -Force
}

foreach ($entry in $ExpectedNativeHashes.GetEnumerator()) {
    $path = Join-Path $StageDirectory $entry.Key
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($actual -ne $entry.Value) {
        throw "Native asset hash mismatch for $($entry.Key): $actual"
    }
}

$driverSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $StageDirectory "WinDivert64.sys")
if ($driverSignature.Status -ne "Valid") {
    throw "WinDivert64.sys signature is not valid: $($driverSignature.Status)"
}

foreach ($jsonFile in @("manifest.json", "UuPatchProfiles.json")) {
    try {
        $null = Get-Content -LiteralPath (Join-Path $StageDirectory $jsonFile) -Raw -Encoding utf8 | ConvertFrom-Json
    }
    catch {
        throw "Release file $jsonFile is not valid JSON: $($_.Exception.Message)"
    }
}

$manifest = Get-Content -LiteralPath (Join-Path $StageDirectory "manifest.json") -Raw -Encoding utf8 | ConvertFrom-Json
$manifestVersion = ([string]$manifest.version).Trim().TrimStart('v')
$applicationVersion = (Get-Item -LiteralPath (Join-Path $StageDirectory "ProxiFyre.exe")).VersionInfo.FileVersion
$manifestVersionMatch = [regex]::Match($manifestVersion, '^(\d+\.\d+\.\d+)')
$applicationVersionMatch = [regex]::Match($applicationVersion, '^(\d+\.\d+\.\d+)')
$versionsMatch = (
    $manifestVersionMatch.Success -and
    $applicationVersionMatch.Success -and
    $manifestVersionMatch.Groups[1].Value -eq $applicationVersionMatch.Groups[1].Value
)
if (-not $versionsMatch) {
    throw "manifest.json version '$manifestVersion' does not match ProxiFyre.exe version '$applicationVersion'."
}

$ExpectedEntries = @($PackageFiles.Name | Sort-Object)
$ActualEntries = @(Get-ChildItem -LiteralPath $StageDirectory -File | Select-Object -ExpandProperty Name | Sort-Object)
$EntryDiff = @(Compare-Object -ReferenceObject $ExpectedEntries -DifferenceObject $ActualEntries)
if ($EntryDiff.Count -gt 0) {
    $details = $EntryDiff | ForEach-Object {
        "{0} {1}" -f $_.SideIndicator, $_.InputObject
    }
    throw "Release staging contents do not match the allowlist: $($details -join ', ')"
}

Compress-Archive -Path (Join-Path $StageDirectory "*") -DestinationPath $ArchivePath -CompressionLevel Optimal -Force

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
try {
    $ArchiveEntries = @(
        $archive.Entries |
            Where-Object { -not [string]::IsNullOrEmpty($_.Name) } |
            Select-Object -ExpandProperty FullName |
            Sort-Object
    )
}
finally {
    $archive.Dispose()
}

$ArchiveDiff = @(Compare-Object -ReferenceObject $ExpectedEntries -DifferenceObject $ArchiveEntries)
if ($ArchiveDiff.Count -gt 0) {
    $details = $ArchiveDiff | ForEach-Object {
        "{0} {1}" -f $_.SideIndicator, $_.InputObject
    }
    throw "Release archive contents do not match the allowlist: $($details -join ', ')"
}

$archiveHash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash
Write-Host "Release package: $ArchivePath"
Write-Host "SHA256: $archiveHash"
