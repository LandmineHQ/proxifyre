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

function Convert-HexPattern {
    param([string]$Value)

    $tokens = @($Value -split "\s+" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($tokens.Count -eq 0) {
        throw "UU byte signature is empty."
    }

    $values = [byte[]]::new($tokens.Count)
    $masks = [byte[]]::new($tokens.Count)
    for ($index = 0; $index -lt $tokens.Count; $index++) {
        $token = $tokens[$index]
        if ($token -eq "??") {
            continue
        }

        if ($token.Length -ne 2) {
            throw "Invalid UU signature token: $token"
        }

        $values[$index] = [Convert]::ToByte($token, 16)
        $masks[$index] = 0xFF
    }

    return [pscustomobject]@{
        Values = $values
        Masks = $masks
    }
}

function Get-PeSections {
    param([byte[]]$Bytes)

    $peOffset = [int](Get-UInt32 -Bytes $Bytes -Offset 0x3C)
    if ((Get-UInt32 -Bytes $Bytes -Offset $peOffset) -ne 0x00004550) {
        throw "The input file is not a valid PE image."
    }

    $sectionCount = Get-UInt16 -Bytes $Bytes -Offset ($peOffset + 0x06)
    $optionalHeaderSize = Get-UInt16 -Bytes $Bytes -Offset ($peOffset + 0x14)
    $sectionTable = $peOffset + 0x18 + $optionalHeaderSize
    $sections = @()
    for ($index = 0; $index -lt $sectionCount; $index++) {
        $offset = $sectionTable + ($index * 0x28)
        if (($offset + 0x28) -gt $Bytes.Length) {
            throw "The PE section table is truncated."
        }

        $name = [Text.Encoding]::ASCII.GetString($Bytes, $offset, 8).Trim([char]0)
        $virtualSize = Get-UInt32 -Bytes $Bytes -Offset ($offset + 0x08)
        $virtualAddress = Get-UInt32 -Bytes $Bytes -Offset ($offset + 0x0C)
        $rawSize = Get-UInt32 -Bytes $Bytes -Offset ($offset + 0x10)
        $rawOffset = Get-UInt32 -Bytes $Bytes -Offset ($offset + 0x14)
        $characteristics = Get-UInt32 -Bytes $Bytes -Offset ($offset + 0x24)
        if ($rawOffset -ge $Bytes.Length) {
            continue
        }

        if ((($characteristics -band 0x20000000) -eq 0) -and ($name -ne ".text")) {
            continue
        }

        $sections += [pscustomobject]@{
            Name = $name
            VirtualAddress = $virtualAddress
            VirtualSize = $virtualSize
            RawOffset = $rawOffset
            RawSize = [Math]::Min($rawSize, [uint32]($Bytes.Length - $rawOffset))
            Characteristics = $characteristics
        }
    }

    if ($sections.Count -eq 0) {
        throw "The PE image has no executable sections."
    }

    return $sections
}

function Find-PatternRvas {
    param(
        [byte[]]$Bytes,
        [object]$Pattern
    )

    $hits = [Collections.Generic.List[uint32]]::new()
    foreach ($section in (Get-PeSections -Bytes $Bytes)) {
        $start = [int]$section.RawOffset
        $end = $start + [int]$section.RawSize
        for ($offset = $start; ($offset + $Pattern.Values.Length) -le $end; $offset++) {
            $matched = $true
            for ($index = 0; $index -lt $Pattern.Values.Length; $index++) {
                if (($Bytes[$offset + $index] -band $Pattern.Masks[$index]) -ne
                    ($Pattern.Values[$index] -band $Pattern.Masks[$index])) {
                    $matched = $false
                    break
                }
            }

            if ($matched) {
                $hits.Add([uint32]($section.VirtualAddress + ($offset - $start)))
            }
        }
    }

    return $hits.ToArray()
}

function Convert-Rva {
    param([string]$Value)

    $text = if ($Value.StartsWith("0x", [StringComparison]::OrdinalIgnoreCase)) {
        $Value.Substring(2)
    }
    else {
        $Value
    }

    return [Convert]::ToUInt32($text, 16)
}

function Get-ResolvedPatchSpecs {
    param(
        [object]$Profile,
        [byte[]]$Bytes,
        [bool]$AllowRvaFallback
    )

    $specs = @()
    foreach ($target in $Profile.targets) {
        $rva = $null
        $hasSignature = ($target.PSObject.Properties.Name -contains "signature") -and
            (-not [string]::IsNullOrWhiteSpace($target.signature))
        if ($hasSignature) {
            $pattern = Convert-HexPattern -Value $target.signature
            $hits = @(Find-PatternRvas -Bytes $Bytes -Pattern $pattern)
            if ($hits.Count -eq 1) {
                $signatureOffset = if ($target.PSObject.Properties.Name -contains "signatureOffset") {
                    [int]$target.signatureOffset
                }
                else {
                    0
                }

                $resolved = [int64]$hits[0] + $signatureOffset
                if ($resolved -lt 0 -or $resolved -gt [uint32]::MaxValue) {
                    throw "Signature offset is outside the image for '$($target.name)'."
                }

                $rva = [uint32]$resolved
            }
            elseif (-not $AllowRvaFallback -or [string]::IsNullOrWhiteSpace($target.rva)) {
                throw "Signature for '$($target.name)' matched $($hits.Count) locations."
            }
        }

        if ($null -eq $rva) {
            if (-not $AllowRvaFallback -or [string]::IsNullOrWhiteSpace($target.rva)) {
                throw "No usable function signature for '$($target.name)'."
            }

            $rva = Convert-Rva -Value $target.rva
        }

        $offset = Get-RvaFileOffset -Bytes $Bytes -Rva $rva
        $original = Convert-HexBytes -Value $target.original
        $patched = Convert-HexBytes -Value $target.patched
        if (-not (Test-BytePrefix -Bytes $Bytes -Offset $offset -Expected $original) -and
            -not (Test-BytePrefix -Bytes $Bytes -Offset $offset -Expected $patched)) {
            throw "Resolved bytes do not match the known original or patched bytes for '$($target.name)'."
        }

        $specs += [pscustomobject]@{
            Name = $target.name
            Rva = $rva
            Original = $original
            Patched = $patched
        }
    }

    return $specs
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
$exactProfile = $KnownProfiles |
    Where-Object {
        ($_.sha256 -eq $sourceHash) -or ($_.patchedSha256 -eq $sourceHash)
    } |
    Select-Object -First 1
$dynamicMatch = $false
if ($null -ne $exactProfile) {
    $profile = $exactProfile
    $patchSpecs = @(Get-ResolvedPatchSpecs -Profile $profile -Bytes $sourceBytes -AllowRvaFallback $true)
}
else {
    $candidates = @()
    foreach ($candidate in $KnownProfiles) {
        $targets = @($candidate.targets)
        $signatureCount = @($targets | Where-Object {
            ($_.PSObject.Properties.Name -contains "signature") -and
            (-not [string]::IsNullOrWhiteSpace($_.signature))
        }).Count
        if ($signatureCount -ne $targets.Count) {
            continue
        }

        try {
            $candidateSpecs = @(Get-ResolvedPatchSpecs -Profile $candidate -Bytes $sourceBytes -AllowRvaFallback $false)
            $candidates += [pscustomobject]@{
                Profile = $candidate
                Specs = $candidateSpecs
            }
        }
        catch {
        }
    }

    if ($candidates.Count -eq 0) {
        throw "Unsupported local_proxy.dll SHA256 '$sourceHash' and no unique function-signature profile matched."
    }

    if ($candidates.Count -gt 1) {
        $keys = ($candidates | ForEach-Object { $_.Profile.key }) -join ", "
        throw "Multiple UU patch profiles matched the function signatures: $keys"
    }

    $profile = $candidates[0].Profile
    $patchSpecs = $candidates[0].Specs
    $dynamicMatch = $true
}

if (-not $Force -and ($dynamicMatch -or $fileVersion -ne $profile.Version)) {
    throw ("The DLL matches profile '{0}' by {1}, but FileVersion is '{2}' instead of '{3}'. Use -Force only after re-validating the version metadata." -f
        $profile.Label,
        $(if ($dynamicMatch) { "function signatures" } else { "SHA256" }),
        $fileVersion,
        $profile.Version)
}
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
