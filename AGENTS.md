# Agent Guidelines

## Required Context

- Read `REPO_MAP.md` before changing code. It is the source of truth for
  architecture, file ownership, runtime flows, commands, contracts, and known
  limitations.
- Read `docs/UU_ACCELERATOR.md` before changing UU patching, patch profiles,
  UAC behavior, the Settings tab, or UU-related configuration.
- Keep `REPO_MAP.md`, `README.md`, and the UU document synchronized when a
  change alters files, project boundaries, public configuration, commands,
  protocols, or runtime behavior.
- Verify current behavior against source and tests. Do not treat user-facing
  documentation as the implementation.

## Architecture Invariants

- This is a Windows-only .NET 10 WPF and NativeAOT project. Preserve direct
  relay behavior unless the user explicitly requests another mode.
- `src/ProxiFyre.Module` links source files from `src/ProxiFyre`. Whenever a
  shared relay dependency is added, moved, or removed, update the linked
  compile items and verify both the UI/core build and the NativeAOT publish.
- Do not add local TCP or UDP listeners for direct relay. Preserve outbound
  bypass filters that prevent recursive interception and exclude the configured
  core process from relay matching.
- Do not enable WinpkFilter fragment cache or static PASS-table churn in the
  userspace send-tunnel fallback. Kernel static filters are reserved for the WFP
  target-only path, which has explicit target flow ownership.
- Keep UDP relay sockets pinned to the captured adapter interface index. A UDP
  flow must not rely on the OS default route when multiple physical, tunnel, or
  virtual adapters are present.
- Keep packet draining bounded so sustained traffic cannot starve health,
  cancellation, or adapter revalidation. Bound batches by both packet count and
  elapsed time, service adapters round-robin, and run the packet loop on a
  dedicated long-running thread. Re-enumerate and rebind adapters if the
  WinpkFilter adapter set changes during a relay session. Preserve the
  independent packet-loop watchdog so a stalled stage is visible in logs.
- Keep `PacketFilterLoop` as the lifecycle and relay-decision coordinator.
  Per-adapter reads belong in `AdapterPipelineSet`/`AdapterPipeline`, outbound
  filter state belongs in `OutboundFilterController`, packet construction
  belongs in `PacketInjector`, and fake-IP DNS handling belongs in
  `DnsSpoofHandler`.
- Keep `src/ProxiFyre.Probe` diagnostic-only. Production relay behavior belongs
  in the shared relay core and `src/ProxiFyre.Module`.
- Keep telemetry optional and non-blocking. Relay behavior must remain correct
  when the named pipe is unavailable.
- Keep packet construction checksum-correct for IPv4 and IPv6, and preserve
  bounded resource limits for sockets, pass-cache entries, and reassembly.

## UU Integration

- Patch the loaded `local_proxy.dll` image at runtime from the WPF UI. Do not
  modify the installed DLL or its Authenticode content.
- Store patch profiles in `src/Shared/UuPatchProfiles.json`. Each profile must
  include an exact source SHA256, target RVAs, expected original bytes, and
  replacement bytes.
- Fail closed. Validate the complete profile before writing anything, report
  the mismatched function to the UI, and never guess offsets or silently accept
  unknown DLL hashes.
- Preserve UU process matching and ACLs. Removing domain or destination
  restrictions must not make unrelated processes eligible for acceleration.
- Suspend the target process while changing code bytes, restore page protection
  afterward, and flush the instruction cache.
- Persist the UI switch as `enableUuWhitelistPatch`. While enabled, re-check
  loaded UU modules every three seconds and reapply the runtime patch after UU
  restarts or reloads `local_proxy.dll`.
- Determine enabled state by inspecting the live module path, SHA256, and
  target bytes. Do not rely only on an injected status message.
- If UU is elevated and ProxiFyre is not, request elevation with `runas` before
  inspecting or changing UU memory. The elevated UI must wait for the previous
  single-instance mutex to be released.
- If this UI session applied the patch, perform a best-effort restore during
  normal shutdown before disposing the window and log writer.

## Editing Rules

- Use Windows PowerShell for repository commands. Read text files with
  `-Encoding utf8`, for example:
  `Get-Content -Encoding utf8 README.md`.
- Use four-space C# indentation. Follow the existing four-space XAML style,
  PascalCase for types and public members, camelCase for locals and parameters,
  and `_camelCase` for private fields.
- Keep nullable reference types, implicit usings, latest C#, analyzers, and
  style enforcement enabled. Place files in the matching feature directory and
  keep namespaces under `ProxiFyre` or `TrafficTest`.
- Prefer existing helpers and local patterns over new abstractions. Keep edits
  scoped to the requested behavior.
- Never revert or overwrite unrelated user changes. Work with the existing
  dirty worktree unless the user explicitly requests otherwise.
- Do not commit generated binaries, build output, runtime DLL copies, logs,
  caches, local configuration, or credentials.

## Build And Validation

Use the repository wrapper for normal work:

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
.\scripts\build-wfp.ps1 -Configuration Debug
.\scripts\install-wfp.ps1 -Configuration Debug
```

- `build` publishes the NativeAOT module, probe, and test host, then builds the
  solution. Quote the exact command and result in the final report.
- `packet-selftest`, `tcp-selftest`, and `udp-selftest` are driver-free and
  must not require Administrator privileges. `packet-selftest` also validates
  the UU patch catalog and UU configuration round-trip.
- TCP/UDP relay diagnostics and runtime relay operation require Windows,
  WinpkFilter, and Administrator privileges. `traffic-telemetry` does not.
- Runtime UU validation requires a running UU process with `local_proxy.dll`
  loaded and sufficient privileges to inspect or modify that process.
- Build the WFP driver only when changing the WFP integration or when the task
  explicitly requires it. Loading an unsigned development driver requires test
  signing or a trusted test signature.
- Prefer extending `src/TrafficTest` with a focused diagnostic when a regression
  needs repeatable coverage.
- Report every validation command, its result, and any required WinpkFilter or
  Administrator privileges.

## CI And Releases

- `.github/workflows/build.yml` is the only CI producer for the Windows release
  artifact. It must run:

  ```powershell
  .\scripts\proxifyre.ps1 build -Configuration Release
  .\scripts\proxifyre.ps1 test packet-selftest -Configuration Release
  ```

- Keep the artifact name `proxifyre-win-x64` and staged package name
  `proxifyre-win-x64.zip` stable. The Release workflow downloads them by name.
- Keep the ZIP staging contract aligned with the application layout. Required
  entries are `ProxiFyre.exe`, `ProxiFyre.dll`, `ProxiFyre.deps.json`,
  `ProxiFyre.runtimeconfig.json`, `ProxiFyre.Module.dll`,
  `ProxiFyre.Probe.dll`, `manifest.json`, and `UuPatchProfiles.json`.
- Keep `README.md` and `UU_ACCELERATOR.md` out of the release ZIP because they
  are not runtime dependencies.
- Do not stage local configuration, logs, PDB files, build caches, or runtime
  DLL copies. Include the optional WFP `.sys` and `.inf` files when present.
- Release promotion is manual and requires a successful numeric `build_id`
  plus a semantic `version`. New releases remain drafts unless the user
  explicitly requests immediate publication.
- After changing workflows, run:

  ```powershell
  actionlint .github/workflows/build.yml .github/workflows/release.yml
  ```

  Also reproduce the PowerShell staging block against a local Release build.

## Commit And Pull Request Style

- Use short conventional prefixes such as `feat:`, `fix:`, `refactor:`, or
  `docs:` with a concise imperative summary.
- Pull requests should describe changed behavior, validation commands,
  required privileges, and relevant UI or relay logs.
- Do not include unrelated worktree changes in a commit without the user's
  approval.
