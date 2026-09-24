# Agent Guidelines

## Required Context

- Read `REPO_MAP.md` before changing code. It is the source of truth for
  architecture, file ownership, runtime flows, commands, contracts, and known
  limitations.
- Read `docs/UU_ACCELERATOR.md` before changing UU patching, patch profiles,
  UAC behavior, the Settings tab, or UU-related configuration.
- Treat `docs/UU_ACCELERATOR.md` as the reference for UU policy variables,
  target-function contracts, replacement stubs, and profile resolution.
- Keep `REPO_MAP.md`, `README.md`, `docs/UU_ACCELERATOR.md`, and
  `docs/UU_ACCELERATOR.zh-CN.md` synchronized when a change alters files,
  project boundaries, public configuration, commands, protocols, or runtime
  behavior.
- Verify current behavior against source and tests. Do not treat user-facing
  documentation as the implementation.

## Architecture Invariants

- This is a Windows-only .NET 10 WPF, NativeAOT, and WinDivert relay project.
  Preserve WinDivert-only relay behavior unless the user explicitly requests
  another mode.
- `src/ProxiFyre.Module` links source files from `src/ProxiFyre`. Whenever a
  shared relay dependency is added, moved, or removed, update the linked
  compile items and verify both the UI/core build and the NativeAOT publish.
- `WinDivertPacketRouter` owns the WinDivert NETWORK capture/inject loop.
  Process attribution uses the WinDivert FLOW layer with IP Helper table
  fallback; do not assume NETWORK packets contain a PID.
- The elevated UI opens WinDivert handles and `WinDivertHandleBroker` duplicates
  them into the injected target process. Preserve this path so target
  applications do not need to run elevated.
- Module `RUN`/`RELOAD`/`STOP` commands and module events must carry the
  per-session token. Do not re-enable lower-integrity `WM_COPYDATA` on the
  module control window.
- Treat command delivery and command acceptance as separate states. A timeout
  must never close brokered WinDivert handles that the target may already have
  consumed. `ATTACH` is the authenticated reconnection path after a UI restart.
- TCP relay intentionally terminates the client-side TCP connection in
  user-space and forwards it through a real remote socket. UDP relay must not
  open a local listener. Preserve relay-process/tuple exclusion so relay-owned
  sockets cannot be captured recursively.
- Keep UDP relay sockets pinned to the captured adapter interface index. A UDP
  flow must not rely on the OS default route when multiple physical, tunnel, or
  virtual adapters are present.
- Keep UDP remote-response endpoint policy fully open. Do not reintroduce
  remote IP or port allowlists; retain client endpoint, process identity,
  adapter/interface, and generation validation.
- Keep `WinDivertPacketRouter` as the userspace capture/inject boundary and
  preserve bounded flow, connection, and packet-builder limits.
- Keep WinDivert receive and packet processing decoupled through the bounded
  processing queue. Do not move process-table queries, socket I/O, or packet
  injection back onto the receive thread.
- Preserve target-generation checks in UDP send queues. A relay shutdown or
  target reload must not accept packets or sends from an older ownership
  generation.
- Relay-owned sockets must be excluded by process identity and/or registered
  tuple so their own outbound packets cannot recurse through the relay.
- Keep TCP packet state in `TcpDirectRelay` and UDP relay handling in
  `WinDivertUdpRelay`/`UdpDirectRelay`.
- Keep `src/ProxiFyre.Probe` diagnostic-only. It must not be a production
  runtime dependency or be staged into the release ZIP. Production relay
  behavior belongs in the shared relay core and `src/ProxiFyre.Module`.
- Keep telemetry optional and non-blocking. Relay behavior must remain correct
  when the named pipe is unavailable.
- Persist detailed logging as `detailed` in `app-config.json`, default it to
  disabled, and apply runtime changes without restarting the relay.
- Log every exception-driven fallback as `WARN`; do not demote fallback paths
  to informational logs.
- Keep WinDivert response packet construction checksum-correct for IPv4 and
  IPv6, and preserve bounded limits for proxy connections, UDP flows, and
  packet queues.

## UU Integration

- Patch the loaded `local_proxy.dll` image at runtime from the WPF UI. Do not
  modify the installed DLL or its Authenticode content.
- Store patch profiles in `src/Shared/UuPatchProfiles.json`. Each profile must
  include an exact source SHA256 and expected original/replacement bytes. Every
  target must include a unique function signature; fixed RVAs are only the fast
  path for an exact hash match.
- Keep the maintained `uu-5247` profile as the exact-hash anchor unless the
  target function bodies diverge. The current signatures resolve the same seven
  RVAs in `5247` and `5248`; do not add a duplicate profile with identical
  signatures because unknown-hash resolution would become ambiguous.
- Do not use the UU installation directory, product version, or file version as
  the compatibility key. Current `local_proxy.dll` builds can all report
  version `9.9.9.99`.
- Preserve each target's return ABI. Replacement stubs must be the same length
  as the original prefix and must retain the target's `ret imm16` stack cleanup
  width.
- Fail closed. Validate the complete profile before writing anything, report
  the mismatched function to the UI, and never guess offsets or silently accept
  an unresolved or ambiguous DLL version.
- Preserve UU process matching and ACLs. Removing domain or destination
  restrictions must not make unrelated processes eligible for acceleration.
- Suspend the target process while changing code bytes, restore page protection
  afterward, and flush the instruction cache.
- Persist the UI switch as `enableUuWhitelistPatch`. While enabled, re-check
  loaded UU modules every three seconds and reapply the runtime patch after UU
  restarts or reloads `local_proxy.dll`.
- Determine enabled state by inspecting the live module path, SHA256 or
  validated function signature, and target bytes. Do not rely only on an
  injected status message.
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
.\scripts\proxifyre.ps1 package -Configuration Release
.\scripts\proxifyre.ps1 ui
.\scripts\proxifyre.ps1 run -Config .\app-config.json
.\scripts\proxifyre.ps1 test packet-selftest
.\scripts\proxifyre.ps1 test tcp-selftest
.\scripts\proxifyre.ps1 test udp-selftest
.\scripts\proxifyre.ps1 test <tcp|udp|uu|steam|traffic-telemetry> [-Detailed]
.\scripts\proxifyre.ps1 clean
```

- `build` publishes the NativeAOT module, probe, and test host, then builds the
  solution. Quote the exact command and result in the final report.
- `packet-selftest`, `tcp-selftest`, and `udp-selftest` are driver-free and
  must not require Administrator privileges. `packet-selftest` also validates
  the UU patch catalog and UU configuration round-trip.
- TCP/UDP relay diagnostics and runtime relay operation require Windows,
  Administrator privileges for the signed WinDivert driver, and a target
  process that can use the native WinDivert runtime. `traffic-telemetry` does
  not.
- Runtime UU validation requires a running UU process with `local_proxy.dll`
  loaded and sufficient privileges to inspect or modify that process.
- After changing UU signatures, validate uniqueness against every available
  supported installation build, including `5247` and `5248`:
  `node scripts/check-uu-signatures.cjs src/Shared/UuPatchProfiles.json <local_proxy.dll>`.
- WinDivert must be deployed with the official `WinDivert.dll` and digitally
  signed `WinDivert64.sys`. Do not patch, resign, or replace the driver.
- Keep the pinned WinDivert 2.2.2 SHA-256 values synchronized with the native
  package; fail closed on any hash mismatch.
- Prefer extending `src/TrafficTest` with a focused diagnostic when a regression
  needs repeatable coverage.
- Report every validation command, its result, and any required WinDivert or
  Administrator privileges.

## CI And Releases

- `.github/workflows/build.yml` is the only CI producer for the Windows release
  artifact. It must run:

  ```powershell
  .\scripts\proxifyre.ps1 build -Configuration Release
  .\scripts\proxifyre.ps1 test packet-selftest -Configuration Release
  .\scripts\proxifyre.ps1 test tcp-selftest -Configuration Release
  .\scripts\proxifyre.ps1 test udp-selftest -Configuration Release
  .\scripts\proxifyre.ps1 package -Configuration Release
  ```

- Keep the artifact name `proxifyre-win-x64` and staged package name
  `proxifyre-win-x64.zip` stable. The Release workflow downloads them by name.
- Keep the ZIP staging contract aligned with the application layout. Required
  entries are `ProxiFyre.exe`, `ProxiFyre.dll`, `ProxiFyre.deps.json`,
  `ProxiFyre.runtimeconfig.json`, `ProxiFyre.Module.dll`,
  `WinDivert.dll`, `WinDivert64.sys`, `WinDivert-LICENSE.txt`,
  `THIRD_PARTY_NOTICES.md`, `LICENSE`, `manifest.json`, and
  `UuPatchProfiles.json`.
- Keep release staging and validation in `scripts/package-release.ps1`; do not
  duplicate the production file allowlist in workflow YAML.
- Keep `manifest.json`, the application file version, and the manual Release
  `version` input synchronized. Packaging and release promotion must fail on a
  mismatch.
- Keep `README.md`, `UU_ACCELERATOR.md`, and `UU_ACCELERATOR.zh-CN.md` out of
  the release ZIP because they are not runtime dependencies.
- Do not stage local configuration, logs, PDB files, build caches, or runtime
  DLL copies. The official WinDivert DLL, driver, and license are required
  release entries.
- Release promotion is manual and requires a successful numeric `build_id`
  plus a semantic `version`. New releases remain drafts unless the user
  explicitly requests immediate publication.
- After changing workflows, run:

  ```powershell
  actionlint .github/workflows/build.yml .github/workflows/release.yml
  ```

  Also reproduce `scripts/package-release.ps1` against a local Release build.

## Commit And Pull Request Style

- Use short conventional prefixes such as `feat:`, `fix:`, `refactor:`, or
  `docs:` with a concise imperative summary.
- Pull requests should describe changed behavior, validation commands,
  required privileges, and relevant UI or relay logs.
- Do not include unrelated worktree changes in a commit without the user's
  approval.
