# Repository Guidelines

## Project Structure & Module Organization

ProxiFyre is a Windows-focused .NET 10 solution. The main WPF application and direct traffic relay live in `src/ProxiFyre`, with feature areas split by responsibility: `UI/`, `Relay/`, `PacketFiltering/`, `Network/`, `Process/`, `Configuration/`, `Dependencies/`, `Logging/`, and `Native/`. The traffic and STUN diagnostic runner lives in `src/TrafficTest`. Shared source used by both projects is under `src/Shared`.

Repository-level files include `ProxiFyre.sln`, `global.json`, `Directory.Build.props`, and `manifest.json`. Build output is redirected to `artifacts/`; do not commit generated binaries, logs, caches, or local `app-config.json`.

## Build, Test, and Development Commands

Use the PowerShell wrapper for normal work:

```powershell
.\scripts\proxifyre.ps1 build
.\scripts\proxifyre.ps1 build -Configuration Release
.\scripts\proxifyre.ps1 ui
.\scripts\proxifyre.ps1 run -Config .\app-config.json
.\scripts\proxifyre.ps1 test curl-ipv4
.\scripts\proxifyre.ps1 test stun-ipv4 -Detailed
.\scripts\proxifyre.ps1 reset-filter
.\scripts\proxifyre.ps1 clean
```

`build` compiles the solution, `ui` launches the WPF app, `run` starts relay mode from a config file, `test` runs focused traffic diagnostics, and `clean` removes repo-local build outputs. Direct `dotnet build` is also supported. Runtime relay tests require Windows, WinpkFilter, and Administrator privileges.

## Coding Style & Naming Conventions

The projects use nullable reference types, implicit usings, latest C#, and analyzer/code-style checks. Keep C# indentation at four spaces, use PascalCase for types and public members, camelCase for locals and parameters, and `_camelCase` only when matching existing private-field style. Keep namespaces under `ProxiFyre` or `TrafficTest` and place new files in the matching feature directory.

## Testing Guidelines

There is no separate xUnit/NUnit project at present. Validate behavior with `src/TrafficTest` and targeted wrapper commands, especially for TCP, UDP, IPv4, IPv6, and STUN changes. Prefer adding new focused diagnostic modes to `TrafficTest` when a regression needs repeatable coverage.

## Commit & Pull Request Guidelines

Recent history mostly uses short conventional prefixes such as `feat:` plus concise imperative summaries. Follow that pattern where practical, for example `fix: preserve UDP endpoint ownership`. Pull requests should describe the changed behavior, list the exact commands run, mention any Administrator or WinpkFilter requirement, and include screenshots or logs for UI and relay-diagnostic changes.

## Agent-Specific Instructions

When reading files with Windows PowerShell, always specify UTF-8 explicitly, for example `Get-Content -Encoding UTF8 README.md`.
