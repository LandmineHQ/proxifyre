# Agent Guidelines

## Required Context

- Read `REPO_MAP.md` before changing code. It is the source of truth for
  project layout, runtime flows, file responsibilities, protocols, commands,
  and known limitations.
- Update `REPO_MAP.md` whenever a change adds, moves, or removes files, changes
  a project boundary, changes the relay data flow, or changes a public command,
  configuration field, message, or telemetry contract.
- Do not infer current behavior only from `README.md`; verify it against the
  implementation and this map.

## Project Boundaries

- This is a Windows-only .NET 10 / WPF / NativeAOT project. Preserve the
  current direct-relay architecture unless the user explicitly requests a new
  mode.
- `src/ProxiFyre.Module` links source files from `src/ProxiFyre`; changes to
  those shared relay files affect both the UI-side core and the injected AOT
  module.
- Keep production relay behavior out of `src/ProxiFyre.Probe`. The probe is a
  diagnostic API-hook tool.
- Do not add local TCP/UDP listening ports for direct relay. Preserve the
  relay-outbound bypass filters that prevent recursive interception.
- Keep telemetry optional and non-blocking. Relay operation must continue when
  the telemetry pipe is unavailable.

## Editing Rules

- Use Windows PowerShell for repository commands. When reading raw files, pass
  `-Encoding UTF8`, for example:
  `Get-Content -Encoding UTF8 README.md`.
- Use four-space C# indentation, PascalCase for types and public members,
  camelCase for locals and parameters, and the existing `_camelCase` private
  field style.
- Keep nullable reference types, implicit usings, latest C#, and analyzer/style
  checks enabled. Place new files in the matching feature directory and keep
  namespaces under `ProxiFyre` or `TrafficTest`.
- Prefer existing helpers and architectural patterns over new abstractions.
  Keep edits scoped to the requested behavior.
- Never revert or overwrite unrelated user changes. Work with an existing dirty
  worktree.
- Do not commit generated binaries, runtime DLL copies, logs, caches, or local
  `app-config.json`.

## Build and Validation

Use the wrapper for normal work:

```powershell
.\scripts\proxifyre.ps1 build
.\scripts\proxifyre.ps1 build -Configuration Release
.\scripts\proxifyre.ps1 ui
.\scripts\proxifyre.ps1 run -Config .\app-config.json
.\scripts\proxifyre.ps1 test packet-selftest
.\scripts\proxifyre.ps1 test tcp-selftest
.\scripts\proxifyre.ps1 test udp-selftest
.\scripts\proxifyre.ps1 test <tcp|udp|uu|steam|traffic-telemetry> [-Detailed]
.\scripts\proxifyre.ps1 reset-filter
.\scripts\proxifyre.ps1 clean
```

- `build` publishes the NativeAOT module/probe/test host and builds the
  solution.
- Focused relay tests are implemented by `src/TrafficTest`; there is no
  xUnit/NUnit test project.
- TCP/UDP relay diagnostics and runtime relay operation require Windows,
  WinpkFilter, and Administrator privileges. `traffic-telemetry` does not.
- `packet-selftest`, `tcp-selftest`, and `udp-selftest` validate packet and
  relay state logic without WinpkFilter or Administrator privileges.
- Prefer adding a focused diagnostic mode to `TrafficTest` when a regression
  needs repeatable coverage.
- Report the exact commands run and whether WinpkFilter or Administrator
  privileges were required.

## Commit and Pull Request Style

- Use short conventional prefixes such as `feat:`, `fix:`, `refactor:`, or
  `docs:` with concise imperative summaries.
- Pull requests should describe the changed behavior, validation commands,
  runtime privileges, and any UI or relay logs relevant to the change.
