param(
    [Parameter(Position = 0)]
    [ValidateSet("build", "run", "ui", "test", "add-app", "init-config", "reset-filter", "clean", "help")]
    [string]$Command = "help",

    [Parameter(Position = 1)]
    [string]$App,

    [string]$Config = ".\app-config.json",

    [switch]$Detailed,

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$Solution = Join-Path $Root "ProxiFyre.sln"
$Project = Join-Path $Root "src\ProxiFyre\ProxiFyre.csproj"
$TrafficTestProject = Join-Path $Root "src\TrafficTest\TrafficTest.csproj"

function Show-Usage {
    Write-Host "Usage:"
    Write-Host "  .\proxifyre.ps1 build [-Configuration Debug|Release]"
    Write-Host "  .\proxifyre.ps1 ui"
    Write-Host "  .\proxifyre.ps1 test [curl-ipv4|curl-ipv6|curl-http-ipv4|curl-large-ipv4|curl-large-ipv6|stun-ipv4|stun-ipv6] [-Detailed]"
    Write-Host "  .\proxifyre.ps1 run [-Config .\app-config.json] [-Detailed]"
    Write-Host "  .\proxifyre.ps1 reset-filter"
    Write-Host "  .\proxifyre.ps1 add-app <exe-or-path> [-Config .\app-config.json]"
    Write-Host "  .\proxifyre.ps1 init-config [-Config .\app-config.json]"
    Write-Host "  .\proxifyre.ps1 clean"
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
        dotnet clean $Solution
        $paths = @(
            Join-Path $Root "src\ProxiFyre\bin"
            Join-Path $Root "src\ProxiFyre\obj"
        )

        foreach ($path in $paths) {
            if (Test-Path -LiteralPath $path) {
                $resolved = (Resolve-Path -LiteralPath $path).Path
                if (-not $resolved.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Refusing to delete outside repository: $resolved"
                }

                Remove-Item -LiteralPath $resolved -Recurse -Force
            }
        }

        exit $LASTEXITCODE
    }
    default {
        Show-Usage
    }
}
