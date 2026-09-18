param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$projectDir = Join-Path $root "src\ProxiFyre.Wfp"
$source = Join-Path $projectDir "driver.c"
$sharedInclude = Join-Path $root "src\Shared"
$wfpVersion = "10.0.26100.0"
$wfpRoot = "C:\Program Files (x86)\Windows Kits\10"
$outDir = Join-Path $root "artifacts\native\$Configuration"
$objDir = Join-Path $root "artifacts\obj\ProxiFyre.Wfp\$Configuration"
$obj = Join-Path $objDir "driver.obj"
$sys = Join-Path $outDir "ProxiFyre.Wfp.sys"
$pdb = Join-Path $outDir "ProxiFyre.Wfp.pdb"

$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if (!(Test-Path -LiteralPath $vswhere)) {
    throw "vswhere.exe was not found."
}

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ([string]::IsNullOrWhiteSpace($vsPath)) {
    throw "Visual C++ build tools were not found."
}

$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
if (!(Test-Path -LiteralPath $vcvars)) {
    throw "vcvars64.bat was not found: $vcvars"
}

$kmInclude = Join-Path $wfpRoot "Include\$wfpVersion\km"
$sharedSdkInclude = Join-Path $wfpRoot "Include\$wfpVersion\shared"
$ucrtInclude = Join-Path $wfpRoot "Include\$wfpVersion\ucrt"
$umInclude = Join-Path $wfpRoot "Include\$wfpVersion\um"
$kmLib = Join-Path $wfpRoot "Lib\$wfpVersion\km\x64"
$ucrtLib = Join-Path $wfpRoot "Lib\$wfpVersion\ucrt\x64"

foreach ($path in @($source, $kmInclude, $sharedSdkInclude, $ucrtInclude, $umInclude, $kmLib, $ucrtLib)) {
    if (!(Test-Path -LiteralPath $path)) {
        throw "Required WFP build input was not found: $path"
    }
}

New-Item -ItemType Directory -Force -Path $outDir, $objDir | Out-Null

$defines = if ($Configuration -eq "Debug") {
    "/Od /Zi /DDEBUG"
} else {
    "/O2 /DNDEBUG"
}

$compile = @(
    "cl.exe /nologo /kernel /c /W4 /D_AMD64_ /D_WIN64 /DNT /DUNICODE /D_UNICODE /DPOOL_NX_OPTIN_AUTO",
    "/DNTDDI_VERSION=0x0A000008 /D_WIN32_WINNT=0x0A00 /DNDIS60 /DNDIS_SUPPORT_NDIS6 $defines",
    "/I`"$kmInclude`" /I`"$sharedSdkInclude`" /I`"$ucrtInclude`" /I`"$umInclude`" /I`"$sharedInclude`"",
    "/Fo`"$obj`" `"$source`""
) -join " "

$link = @(
    "link.exe /nologo /DRIVER /KERNEL /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB",
    "/OUT:`"$sys`" /PDB:`"$pdb`"",
    "/LIBPATH:`"$kmLib`" /LIBPATH:`"$ucrtLib`"",
    "`"$obj`" ntoskrnl.lib BufferOverflowFastFailK.lib fwpkclnt.lib wdmsec.lib uuid.lib"
) -join " "

$commandLine = "call `"$vcvars`" >nul && $compile && $link"
& cmd.exe /d /c $commandLine
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Copy-Item -LiteralPath (Join-Path $projectDir "ProxiFyre.Wfp.inf") -Destination $outDir -Force
Write-Host "Built $sys"
