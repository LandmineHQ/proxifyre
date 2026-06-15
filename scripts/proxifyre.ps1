param(
    [Parameter(Position = 0)]
    [ValidateSet("build", "run", "ui", "test", "add-app", "init-config", "reset-filter", "license-device", "license-key", "module-publish", "clean", "help")]
    [string]$Command = "help",

    [Parameter(Position = 1)]
    [string]$App,

    [string]$Config = ".\app-config.json",

    [switch]$Detailed,

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$Solution = Join-Path $Root "ProxiFyre.sln"
$Project = Join-Path $Root "src\ProxiFyre\ProxiFyre.csproj"
$ModuleProject = Join-Path $Root "src\ProxiFyre.Module\ProxiFyre.Module.csproj"
$TrafficTestHostProject = Join-Path $Root "src\TrafficTestHost\TrafficTestHost.csproj"
$Artifacts = Join-Path $Root "artifacts"

function Show-Usage {
    Write-Host "Usage:"
    Write-Host "  .\scripts\proxifyre.ps1 build [-Configuration Debug|Release]"
    Write-Host "  .\scripts\proxifyre.ps1 ui"
    Write-Host "  .\scripts\proxifyre.ps1 test <tcp|udp|uu|steam> [-Detailed] [-- <test args>]"
    Write-Host "  .\scripts\proxifyre.ps1 run [-Config .\app-config.json] [-Detailed]"
    Write-Host "  .\scripts\proxifyre.ps1 reset-filter"
    Write-Host "  .\scripts\proxifyre.ps1 license-device"
    Write-Host "  .\scripts\proxifyre.ps1 license-key <device-id>"
    Write-Host "  .\scripts\proxifyre.ps1 module-publish [-Configuration Debug|Release]"
    Write-Host "  .\scripts\proxifyre.ps1 add-app <exe-or-path> [-Config .\app-config.json]"
    Write-Host "  .\scripts\proxifyre.ps1 init-config [-Config .\app-config.json]"
    Write-Host "  .\scripts\proxifyre.ps1 clean"
}

function Remove-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        $resolved = (Resolve-Path -LiteralPath $Path).Path
        if (-not $resolved.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to delete outside repository: $resolved"
        }

        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

function Invoke-ProxiFyreCli {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    dotnet run --project $Project -p:OutputType=Exe -- @Arguments
}

function Get-ArtifactMoniker {
    param([Parameter(Mandatory = $true)][string]$BuildConfiguration)

    return ("{0}_win-x64" -f $BuildConfiguration.ToLowerInvariant())
}

function Assert-BuildOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Description not found: $Path`n请先运行 .\scripts\proxifyre.ps1 build -Configuration $Configuration"
    }
}

switch ($Command) {
    "build" {
        dotnet publish $ModuleProject --configuration $Configuration --runtime win-x64
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        dotnet publish $TrafficTestHostProject --configuration $Configuration --runtime win-x64
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        dotnet build $Solution --configuration $Configuration
        exit $LASTEXITCODE
    }
    "ui" {
        dotnet publish $ModuleProject --configuration $Configuration --runtime win-x64
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        dotnet run --project $Project
        exit $LASTEXITCODE
    }
    "test" {
        $testArgs = @()
        if (-not [string]::IsNullOrWhiteSpace($App)) {
            $testArgs += $App
        }
        if ($Detailed) {
            $testArgs += "--detailed"
        }
        if ($ExtraArgs) {
            if ($ExtraArgs.Length -gt 0 -and $ExtraArgs[0] -eq "--") {
                $ExtraArgs = @($ExtraArgs | Select-Object -Skip 1)
            }

            $testArgs += $ExtraArgs
        }

        $artifactMoniker = Get-ArtifactMoniker -BuildConfiguration $Configuration
        $trafficTestExe = Join-Path $Artifacts "bin\TrafficTest\$artifactMoniker\TrafficTest.exe"
        Assert-BuildOutput -Path $trafficTestExe -Description "TrafficTest executable"

        $testMode = if ([string]::IsNullOrWhiteSpace($App)) { "" } else { $App.ToLowerInvariant() }
        if ($testMode -eq "tcp" -or $testMode -eq "udp") {
            Assert-BuildOutput -Path (Join-Path $Artifacts "bin\ProxiFyre\$artifactMoniker\ProxiFyre.exe") -Description "ProxiFyre executable"
            Assert-BuildOutput -Path (Join-Path $Artifacts "bin\TrafficTestHost\$artifactMoniker\TrafficTestHost.exe") -Description "AOT test host executable"
            Assert-BuildOutput -Path (Join-Path $Artifacts "native\$Configuration\ProxiFyre.Module.dll") -Description "AOT module DLL"
        }

        & $trafficTestExe @testArgs
        exit $LASTEXITCODE
    }
    "run" {
        $runArgs = @("--run", "--config", $Config)
        if ($Detailed) {
            $runArgs += "--detailed"
        }

        Invoke-ProxiFyreCli @runArgs
        exit $LASTEXITCODE
    }
    "reset-filter" {
        Invoke-ProxiFyreCli --reset-filter
        exit $LASTEXITCODE
    }
    "license-device" {
        if (-not [string]::IsNullOrWhiteSpace($App)) {
            throw "license-device does not take an argument."
        }

        Invoke-ProxiFyreCli --license-device
        exit $LASTEXITCODE
    }
    "license-key" {
        if ([string]::IsNullOrWhiteSpace($App)) {
            throw "license-key requires a device id."
        }

        Invoke-ProxiFyreCli --license-key $App
        exit $LASTEXITCODE
    }
    "module-publish" {
        dotnet publish $ModuleProject --configuration $Configuration --runtime win-x64
        exit $LASTEXITCODE
    }
    "add-app" {
        if ([string]::IsNullOrWhiteSpace($App)) {
            throw "add-app requires an executable name or path."
        }

        Invoke-ProxiFyreCli --add-app $App --config $Config
        exit $LASTEXITCODE
    }
    "init-config" {
        Invoke-ProxiFyreCli --init-config --config $Config
        exit $LASTEXITCODE
    }
    "clean" {
        dotnet clean $Solution --configuration $Configuration
        $paths = @(
            $Artifacts,
            (Join-Path $Root "src\ProxiFyre\bin"),
            (Join-Path $Root "src\ProxiFyre\obj"),
            (Join-Path $Root "src\ProxiFyre.Module\bin"),
            (Join-Path $Root "src\ProxiFyre.Module\obj"),
            (Join-Path $Root "src\TrafficTestHost\bin"),
            (Join-Path $Root "src\TrafficTestHost\obj"),
            (Join-Path $Root "src\TrafficTest\bin"),
            (Join-Path $Root "src\TrafficTest\obj")
        )

        foreach ($path in $paths) {
            Remove-RepoPath -Path $path
        }

        exit $LASTEXITCODE
    }
    default {
        Show-Usage
    }
}
