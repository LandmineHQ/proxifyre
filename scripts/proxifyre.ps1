param(
    [Parameter(Position = 0)]
    [ValidateSet("build", "run", "ui", "test", "add-app", "init-config", "reset-filter", "clean", "help")]
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
$TrafficTestProject = Join-Path $Root "src\TrafficTest\TrafficTest.csproj"
$Artifacts = Join-Path $Root "artifacts"

function Show-Usage {
    Write-Host "Usage:"
    Write-Host "  .\scripts\proxifyre.ps1 build [-Configuration Debug|Release]"
    Write-Host "  .\scripts\proxifyre.ps1 ui"
    Write-Host "  .\scripts\proxifyre.ps1 test [curl-ipv4|curl-ipv6|curl-http-ipv4|curl-large-ipv4|curl-large-ipv6|stun-ipv4|stun-ipv6|stun-bench-ipv4|stun-bench-ipv6|stun-scan-ipv4|stun-scan-ipv6|stun-relay-scan-ipv4|stun-relay-scan-ipv6|license-device|license-key] [-Detailed] [-- <test args>]"
    Write-Host "  .\scripts\proxifyre.ps1 test license-key <device-id>"
    Write-Host "  .\scripts\proxifyre.ps1 run [-Config .\app-config.json] [-Detailed]"
    Write-Host "  .\scripts\proxifyre.ps1 reset-filter"
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

switch ($Command) {
    "build" {
        dotnet build $Solution --configuration $Configuration
        exit $LASTEXITCODE
    }
    "ui" {
        dotnet run --project $Project
        exit $LASTEXITCODE
    }
    "test" {
        dotnet build $Project --configuration Debug
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $testArgs = @()
        if (-not [string]::IsNullOrWhiteSpace($App)) {
            $testArgs += $App
        }
        if ($Detailed) {
            $testArgs += "--detailed"
        }
        if ($ExtraArgs) {
            $testArgs += $ExtraArgs
        }

        dotnet run --project $TrafficTestProject -- @testArgs
        exit $LASTEXITCODE
    }
    "run" {
        $runArgs = @("--run", "--config", $Config)
        if ($Detailed) {
            $runArgs += "--detailed"
        }

        dotnet run --project $Project -- @runArgs
        exit $LASTEXITCODE
    }
    "reset-filter" {
        dotnet run --project $Project -- --reset-filter
        exit $LASTEXITCODE
    }
    "add-app" {
        if ([string]::IsNullOrWhiteSpace($App)) {
            throw "add-app requires an executable name or path."
        }

        dotnet run --project $Project -- --add-app $App --config $Config
        exit $LASTEXITCODE
    }
    "init-config" {
        dotnet run --project $Project -- --init-config --config $Config
        exit $LASTEXITCODE
    }
    "clean" {
        dotnet clean $Solution --configuration $Configuration
        $paths = @(
            $Artifacts,
            (Join-Path $Root "src\ProxiFyre\bin"),
            (Join-Path $Root "src\ProxiFyre\obj"),
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
