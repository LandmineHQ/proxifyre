param(
    [Parameter(Position = 0)]
    [ValidateSet("build", "run", "ui", "add-app", "init-config", "clean", "help")]
    [string]$Command = "help",

    [Parameter(Position = 1)]
    [string]$App,

    [string]$Config = ".\app-config.json",

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$Solution = Join-Path $Root "ProxiFyre.sln"
$Project = Join-Path $Root "src\ProxiFyre\ProxiFyre.csproj"

function Show-Usage {
    Write-Host "Usage:"
    Write-Host "  .\proxifyre.ps1 build [-Configuration Debug|Release]"
    Write-Host "  .\proxifyre.ps1 ui"
    Write-Host "  .\proxifyre.ps1 run [-Config .\app-config.json]"
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
    "run" {
        dotnet run --project $Project -- --run --config $Config
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
