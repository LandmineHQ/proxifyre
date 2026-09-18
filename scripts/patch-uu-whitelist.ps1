param(
    [string]$InputPath,

    [string]$OutputPath,

    [switch]$Apply,

    [switch]$Restore,

    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$ProfilesPath = Join-Path $Root "src\Shared\UuPatchProfiles.json"
$KnownProfiles = (Get-Content -LiteralPath $ProfilesPath -Raw -Encoding utf8 | ConvertFrom-Json).profiles

function Get-UuRoots {
    @(
        (Join-Path ${env:ProgramFiles(x86)} "Netease\UU"),
        (Join-Path $env:ProgramFiles "Netease\UU")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }
}

function Resolve-LocalProxyPath {
    param([string]$Path)

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $resolved = (Resolve-Path -LiteralPath $Path).Path
        if (Test-Path -LiteralPath $resolved -PathType Container) {
            return (Join-Path $resolved "local_proxy.dll")
        }

        return $resolved
    }

    $candidates = foreach ($uuRoot in Get-UuRoots) {
        Get-ChildItem -LiteralPath $uuRoot -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $candidate = Join-Path $_.FullName "local_proxy.dll"
                if (Test-Path -LiteralPath $candidate) {
                    Get-Item -LiteralPath $candidate
                }
            }
    }

    $selected = $candidates |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1

    if ($null -eq $selected) {
        throw "local_proxy.dll was not found under the NetEase UU installation directories."
    }

    return $selected.FullName
}

function Get-UInt16 {
    param(
        [byte[]]$Bytes,
        [int]$Offset
    )

    if ($Offset -lt 0 -or ($Offset + 2) -gt $Bytes.Length) {
        throw "PE read outside the file: $Offset"
    }

    return [BitConverter]::ToUInt16($Bytes, $Offset)
}

function Get-UInt32 {
    param(
        [byte[]]$Bytes,
        [int]$Offset
    )

    if ($Offset -lt 0 -or ($Offset + 4) -gt $Bytes.Length) {
        throw "PE read outside the file: $Offset"
    }

    return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Get-RvaFileOffset {
    param(
        [byte[]]$Bytes,
        [uint32]$Rva
    )

    $peOffset = Get-UInt32 -Bytes $Bytes -Offset 0x3C
    if ((Get-UInt32 -Bytes $Bytes -Offset $peOffset) -ne 0x00004550) {
        throw "The input file is not a valid PE image."
    }

    $sectionCount = Get-UInt16 -Bytes $Bytes -Offset ($peOffset + 0x06)
    $optionalHeaderSize = Get-UInt16 -Bytes $Bytes -Offset ($peOffset + 0x14)
    $sectionTable = $peOffset + 0x18 + $optionalHeaderSize

    for ($index = 0; $index -lt $sectionCount; $index++) {
        $section = $sectionTable + ($index * 0x28)
        $virtualSize = Get-UInt32 -Bytes $Bytes -Offset ($section + 0x08)
        $virtualAddress = Get-UInt32 -Bytes $Bytes -Offset ($section + 0x0C)
        $rawSize = Get-UInt32 -Bytes $Bytes -Offset ($section + 0x10)
        $rawOffset = Get-UInt32 -Bytes $Bytes -Offset ($section + 0x14)
        $span = [Math]::Max($virtualSize, $rawSize)

        if ($Rva -ge $virtualAddress -and $Rva -lt ($virtualAddress + $span)) {
            $offset = [int64]$rawOffset + ([int64]$Rva - [int64]$virtualAddress)
            if ($offset -lt 0 -or $offset -ge $Bytes.Length) {
                throw ("RVA 0x{0:X} resolves outside the file." -f $Rva)
            }

            return [int]$offset
        }
    }

    throw ("RVA 0x{0:X} was not found in a PE section." -f $Rva)
}

function Get-Sha256 {
    param([byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "")
    }
    finally {
        $sha.Dispose()
    }
}

function Convert-HexBytes {
    param([string]$Value)

    return [byte[]](
        $Value.Split(
            [char[]]@(" ", "`t", "`r", "`n"),
            [StringSplitOptions]::RemoveEmptyEntries) |
            ForEach-Object { [Convert]::ToByte($_, 16) }
    )
}

function Test-BytePrefix {
    param(
        [byte[]]$Bytes,
        [int]$Offset,
        [byte[]]$Expected
    )

    if ($Offset -lt 0 -or ($Offset + $Expected.Length) -gt $Bytes.Length) {
        return $false
    }

    for ($index = 0; $index -lt $Expected.Length; $index++) {
        if ($Bytes[$Offset + $index] -ne $Expected[$index]) {
            return $false
        }
    }

    return $true
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required for -Apply or -Restore."
    }
}

function Assert-UuStopped {
    $running = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -like "uu*" -or $_.ProcessName -in @("uu_ball", "uu_launcher") }

    if ($running) {
        $names = ($running | Select-Object -ExpandProperty ProcessName -Unique) -join ", "
        throw "Stop UU before replacing local_proxy.dll. Running processes: $names"
    }
}

function Get-PatchSpecs {
    param([string]$ProfileKey)

    $profile = $KnownProfiles |
        Where-Object { $_.key -eq $ProfileKey } |
        Select-Object -First 1
    if ($null -eq $profile) {
        throw "Unknown patch profile: $ProfileKey"
    }

    return @($profile.targets | ForEach-Object {
        [pscustomobject]@{
            Name = $_.name
            Rva = [Convert]::ToUInt32($_.rva.Substring(2), 16)
            Original = Convert-HexBytes -Value $_.original
            Patched = Convert-HexBytes -Value $_.patched
        }
    })
}

$sourcePath = Resolve-LocalProxyPath -Path $InputPath
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "local_proxy.dll was not found: $sourcePath"
}

$sourceDirectory = Split-Path -Parent $sourcePath
$backups = Get-ChildItem -LiteralPath $sourceDirectory -Filter "local_proxy.dll.uu-original.*.bak" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTimeUtc -Descending

if ($Restore) {
    Assert-Administrator
    Assert-UuStopped

    $backup = $backups | Select-Object -First 1
    if ($null -eq $backup) {
        throw "No original local_proxy.dll backup was found in $sourceDirectory."
    }

    Copy-Item -LiteralPath $backup.FullName -Destination $sourcePath -Force
    Write-Host "Restored $sourcePath from $($backup.FullName)"
    exit 0
}

$versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($sourcePath)
$fileVersion = $versionInfo.FileVersion

$sourceBytes = [IO.File]::ReadAllBytes($sourcePath)
if ($sourceBytes.Length -ge 2 -and $sourceBytes[0] -eq 0x4D -and $sourceBytes[1] -eq 0x5A) {
    $machine = Get-UInt16 -Bytes $sourceBytes -Offset ((Get-UInt32 -Bytes $sourceBytes -Offset 0x3C) + 0x04)
    if ($machine -ne 0x014C) {
        throw "Expected a 32-bit x86 local_proxy.dll."
    }
}
else {
    throw "Input is not a PE image: $sourcePath"
}

$sourceHash = Get-Sha256 -Bytes $sourceBytes
$profile = $KnownProfiles |
    Where-Object {
        ($_.sha256 -eq $sourceHash) -or ($_.patchedSha256 -eq $sourceHash)
    } |
    Select-Object -First 1
if ($null -eq $profile) {
    throw "Unsupported local_proxy.dll SHA256 '$sourceHash'. Add and validate a new version profile before patching."
}
if (-not $Force -and $fileVersion -ne $profile.Version) {
    throw ("SHA256 matches '{0}', but FileVersion is '{1}' instead of '{2}'. Use -Force only after re-validating the version metadata." -f
        $profile.Label, $fileVersion, $profile.Version)
}

$patchSpecs = @(Get-PatchSpecs -ProfileKey $profile.Key)
$patchedBytes = [byte[]]$sourceBytes.Clone()
$patchResults = foreach ($patch in $patchSpecs) {
    $offset = Get-RvaFileOffset -Bytes $sourceBytes -Rva $patch.Rva
    $isOriginal = Test-BytePrefix -Bytes $sourceBytes -Offset $offset -Expected $patch.Original
    $isPatched = Test-BytePrefix -Bytes $sourceBytes -Offset $offset -Expected $patch.Patched
    if (-not $isOriginal -and -not $isPatched) {
        $actual = ($sourceBytes[$offset..($offset + $patch.Original.Length - 1)] |
            ForEach-Object { $_.ToString("X2") }) -join " "
        throw ("Patch target mismatch for '{0}' at RVA 0x{1:X}. Expected '{2}', found '{3}'." -f
            $patch.Name,
            $patch.Rva,
            (($patch.Original | ForEach-Object { $_.ToString("X2") }) -join " "),
            $actual)
    }

    if ($isOriginal) {
        [Array]::Copy($patch.Patched, 0, $patchedBytes, $offset, $patch.Patched.Length)
    }

    [pscustomobject]@{
        Name = $patch.Name
        Rva = $patch.Rva
        FileOffset = $offset
        Status = if ($isPatched) { "AlreadyPatched" } else { "Patched" }
        Original = ($patch.Original | ForEach-Object { $_.ToString("X2") }) -join " "
        Patched = ($patch.Patched | ForEach-Object { $_.ToString("X2") }) -join " "
    }
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $Root "artifacts\uu-patch\$($profile.Key)\local_proxy.dll"
}

$outputDirectory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
[IO.File]::WriteAllBytes($OutputPath, $patchedBytes)

$verifiedBytes = [IO.File]::ReadAllBytes($OutputPath)
foreach ($patch in $patchSpecs) {
    $offset = Get-RvaFileOffset -Bytes $verifiedBytes -Rva $patch.Rva
    if (-not (Test-BytePrefix -Bytes $verifiedBytes -Offset $offset -Expected $patch.Patched)) {
        throw ("Verification failed for '{0}' after writing {1}." -f $patch.Name, $OutputPath)
    }
}

Write-Host ("Source: {0}" -f $sourcePath)
Write-Host ("Profile: {0}" -f $profile.Label)
Write-Host ("Source SHA256: {0}" -f $sourceHash)
Write-Host ("Output: {0}" -f $OutputPath)
Write-Host ("Output SHA256: {0}" -f (Get-Sha256 -Bytes $patchedBytes))
Write-Host ""
Write-Host "Applied patches:"
$patchResults | Format-Table -AutoSize

if (-not $Apply) {
    Write-Host "Patched copy created. Pass -Apply to replace the installed DLL and create a rollback backup."
    exit 0
}

Assert-Administrator
Assert-UuStopped

$backupDirectory = Split-Path -Parent $sourcePath
$backupPath = Join-Path $backupDirectory ("local_proxy.dll.uu-original.{0}.bak" -f $sourceHash.Substring(0, 12))
if (-not (Test-Path -LiteralPath $backupPath)) {
    Copy-Item -LiteralPath $sourcePath -Destination $backupPath
}

Copy-Item -LiteralPath $OutputPath -Destination $sourcePath -Force
Write-Host "Installed patch to $sourcePath"
Write-Host "Rollback backup: $backupPath"
