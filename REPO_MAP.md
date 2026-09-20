# ProxiFyre Repository Map

This document maps the repository as it exists in the working tree. It covers
the project layout, runtime data flows, important contracts, file ownership,
build entry points, and known constraints. Generated output under
`artifacts/`, log files, local configuration, and build caches are excluded.

## System Summary

ProxiFyre is a Windows-only .NET 10 direct traffic relay. It watches
application traffic through WinpkFilter, identifies the owning process, creates
normal outbound sockets for selected flows, and injects synthetic response
packets back into Windows TCP/IP without opening local TCP or UDP listeners.

The WPF Settings tab also provides an optional UU Game Booster compatibility
toggle. It applies a signature-validated, reversible code patch to the loaded
`local_proxy.dll` image in a running UU process. It never modifies the
installed DLL from the UI and preserves UU's process ACL.

The repository has two execution modes:

- No command-line arguments: launch the WPF UI.
- One or more command-line arguments: run `Cli` for relay, configuration,
  reset, license, or maintenance operations.

The production relay is compiled as a NativeAOT shared DLL and injected into a
configured target process. The AOT module owns the relay's outbound sockets, so
Windows reports those sockets under the target process rather than the UI
process.

## High-Level Architecture

```text
ProxiFyre.sln
|-- ProxiFyre
|   |-- Program -> UI or CLI
|   |-- UI -> ConfigurationStore + AotModuleController
|   |-- AotModuleController -> injection + WM_COPYDATA control channel
|   `-- RelayService -> PacketFilterLoop + TCP/UDP direct relays
|       |-- AdapterPipelineSet -> AdapterPipeline per adapter
|       |-- OutboundFilterController
|       |-- PacketInjector
|       `-- DnsSpoofHandler
|-- ProxiFyre.Module
|   `-- ModuleExports -> injected RelayService + telemetry client
|-- ProxiFyre.Wfp
|   `-- WFP ALE connect callout + user-mode flow event protocol
|-- TrafficTest
|   |-- AotModuleTestController -> temporary injected test process
|   |-- curl TCP diagnostic
|   `-- STUN UDP diagnostic
`-- TrafficTestHost
    `-- minimal WPF message loop used as an injection target

ProxiFyre.Probe is published by the wrapper but is not part of the solution.
Shared source files are linked into multiple projects rather than packaged as a
separate assembly.
```

## Projects

| Project | Output | Responsibility |
| --- | --- | --- |
| `src/ProxiFyre/ProxiFyre.csproj` | `WinExe`, WPF plus CLI | UI, command parsing, configuration, dependency management, injection control, packet filtering, direct relay core, telemetry server, updates. |
| `src/ProxiFyre.Module/ProxiFyre.Module.csproj` | NativeAOT shared DLL | Injected relay host. Exports `ProxiFyre_GetMsgProc`, creates a hidden message window, receives commands, starts/stops `RelayService`, and publishes telemetry. |
| `src/ProxiFyre.Wfp/ProxiFyre.Wfp.vcxproj` | Windows kernel driver | WFP ALE connect classifier built with the WDK; standalone build is `scripts/build-wfp.ps1`. |
| `src/ProxiFyre.Probe/ProxiFyre.Probe.csproj` | NativeAOT shared DLL | Diagnostic probe. Hooks `DeviceIoControl` and `FilterSendMessage` in a target process and records call buffers. Not the production relay. |
| `src/TrafficTest/TrafficTest.csproj` | Windows console executable | Focused integration diagnostics. References `ProxiFyre` and uses its internal APIs, test controllers, TCP/UDP clients, and network-table readers. |
| `src/TrafficTestHost/TrafficTestHost.csproj` | WPF executable | Minimal process with a message loop. Traffic tests copy it to `steamwebhelper.exe` and inject the AOT module into that exact test process. |

`src/Shared` is not a project. Its files are included as linked `Compile`
items by `ProxiFyre`, `ProxiFyre.Module`, and in some cases other projects.

`ProxiFyre.sln` includes `ProxiFyre`, `ProxiFyre.Module`, `TrafficTest`, and
`TrafficTestHost`. `ProxiFyre.Probe` is built separately by
`scripts/proxifyre.ps1`.

## Repository-Level Files

| Path | Purpose |
| --- | --- |
| `AGENTS.md` | Instructions for coding agents. Points to this map for repository structure and behavior. |
| `REPO_MAP.md` | Architecture, runtime flow, file ownership, protocol, command, and testing reference. |
| `README.md` | Concise project description, build requirements, and build commands. |
| `ProxiFyre.sln` | Visual Studio solution for the four main projects. |
| `Directory.Build.props` | Enables centralized artifacts output under `artifacts/`. |
| `Directory.Build.targets` | Removes temporary `_wpftmp` output directories after WPF builds. |
| `global.json` | Pins the expected .NET SDK to `10.0.100` with latest-feature roll-forward. |
| `manifest.json` | Local version, source URL, and announcement metadata copied into application output. |
| `scripts/proxifyre.ps1` | Main PowerShell development wrapper for build, UI, run, tests, config, license, publishing, reset, and clean operations. |
| `scripts/patch-uu-whitelist.ps1` | Binary patcher for UU `local_proxy.dll`. It keeps the existing process ACL and disables the TCP/UDP domain and destination allow/deny gates before UU writes the active proxy settings to `uuwfp.sys`. |
| `scripts/check-uu-signatures.cjs` | Validates that every UU profile function signature resolves exactly once in the target DLL and matches its recorded RVA when present. |
| `src/Shared/UuPatchProfiles.json` | Shared UU patch profile catalog used by both the WPF runtime patcher and the offline PowerShell patcher. Each profile contains source/patched SHA256 values, expected original/replacement bytes, and unique function signatures with offsets. |
| `docs/UU_ACCELERATOR.md` | UU architecture, WFP driver interface, whitelist processing, runtime patch semantics, UI behavior, and known limitations. |
| `.github/workflows/build.yml` | Windows x64 Release build, packet self-test, release staging, and named build-artifact upload. |
| `.github/workflows/release.yml` | Manual promotion of a successful Build artifact into a GitHub Release. |
| `.gitignore` | Excludes build output, logs, caches, local `app-config.json`, and temporary files. |
| `app-config.json` | Local runtime configuration. It is intentionally ignored by Git. |
| `LICENSE` | Repository license. |

## GitHub Workflows

### Build

`.github/workflows/build.yml` runs on pushes to any branch, `v*` tags, pull
requests targeting `main`, and manual dispatch.

The Windows job:

1. Installs the .NET 10 SDK and restores through the NuGet cache.
2. Runs `.\scripts\proxifyre.ps1 build -Configuration Release`.
3. Runs `.\scripts\proxifyre.ps1 test packet-selftest -Configuration Release`.
4. Stages the WPF application, NativeAOT module/probe, `manifest.json`, and
   `UuPatchProfiles.json`.
5. Excludes local configuration, logs, and PDB files.
6. Includes `ProxiFyre.Wfp.sys` and `ProxiFyre.Wfp.inf` when the optional WFP
   build output exists.
7. Validates that every required release file exists, creates
   `release/proxifyre-win-x64.zip`, and uploads it as the
   `proxifyre-win-x64` artifact for 90 days.

The required ZIP entries are `ProxiFyre.exe`, `ProxiFyre.dll`,
`ProxiFyre.deps.json`, `ProxiFyre.runtimeconfig.json`,
`ProxiFyre.Module.dll`, `ProxiFyre.Probe.dll`, `manifest.json`, and
`UuPatchProfiles.json`. `README.md` and `UU_ACCELERATOR.md` are explicitly
excluded from the release package because they are not runtime dependencies.

### Release

`.github/workflows/release.yml` is manual. It takes the successful Build
workflow's numeric `build_id` and a semantic `version`.

The job validates that the referenced workflow run completed successfully,
downloads the exact `proxifyre-win-x64` artifact, and names the release asset
`proxifyre-<version>-build-<build_id>-<short-sha>.zip`.

When the version does not exist, the workflow creates a draft GitHub Release
targeting the build commit. When it already exists, the workflow uploads or
replaces the matching asset with `gh release upload --clobber`. The job summary
reports the version, build ID, asset path, and SHA256.

## End-to-End Runtime Flows

### UI and AOT module startup

1. `Program.Main` rejects non-Windows systems.
2. With no arguments, `UiSingleInstanceCoordinator` acquires a named mutex. A
   second instance signals the first instance through a named event and exits.
3. `MainWindow` creates `ConfigurationStore`, starts `TrafficTelemetryServer`,
   creates the tray icon, and wires the child controls.
4. The configuration is loaded from `app-config.json` next to the built
   executable. A missing file is created with defaults.
5. On first load, the UI tries to reconnect to an already loaded module in a
   process selected from `coreProcessName`.
6. Clicking Load Module refreshes target discovery, validates the license,
   ensures WinpkFilter is installed, chooses a target process, and injects
   `ProxiFyre.Module.dll`.
7. Injection first uses `WH_GETMESSAGE` hooks on target threads that can pump
   messages. If no window thread exists or hooks do not complete, the fallback
   is `CreateRemoteThread` plus `LoadLibraryW`.
8. The module creates a hidden control window with the class
   `ProxiFyre.Module.ControlWindow`.
9. The UI sends `RUN` through `WM_COPYDATA`. The module loads the configuration,
   normalizes `coreProcessName` to its current process, starts `RelayService`,
   and optionally connects `TrafficTelemetryClient` to the UI pipe.
10. UI and module exchange `HEARTBEAT`, `PING`, `RUN`, `RELOAD`, and `STOP`
    messages. The module emits `loaded`, `running`, `reloaded`, `stopped`,
    `status`, `log`, `lost`, and `error` events.
11. The injected DLL remains resident until the target process exits.

### UU runtime patch

1. The Settings tab raises `UuPatchToggleRequested` when the UU switch changes.
2. `UuRuntimePatcher` scans processes whose executable is under a NetEase UU
   installation root and locates loaded `local_proxy.dll` modules.
3. The module file is hashed for the exact-profile fast path and scanned for
   unique function signatures when the hash is unknown.
4. Each resolved target address is read from the live process. The patcher
   accepts only the exact original bytes or the exact known patched bytes.
5. Enabling the switch asks for confirmation, then suspends the UU process,
   changes the target page to `PAGE_EXECUTE_READWRITE`, writes the replacement
   stubs, flushes the instruction cache, and restores page protection.
6. Disabling the switch writes the original bytes back while the process is
   suspended.
7. The installed DLL is never changed by the WPF UI. Restarting UU removes the
   runtime patch until the toggle is applied again.
8. If ProxiFyre exits normally after applying a patch in the current UI
   session, it performs a best-effort restore before closing.
9. When `enableUuWhitelistPatch` is true, a 3-second UI timer re-inspects UU
   and automatically reapplies the patch after UU restarts or reloads
   `local_proxy.dll`.
10. If UU requires elevation, enabling the persisted setting restarts the WPF
    UI through the `runas` verb. The elevated UI waits for the previous
    single-instance mutex before starting the monitor.

### CLI relay startup

1. `Cli.RunAsync` attaches to the parent console when launched from a Windows
   GUI executable.
2. `--run` loads the selected configuration, creates `CoreLogger`, ensures
   WinpkFilter, and starts `RelayService` in the CLI process.
3. `Ctrl+C` cancels the linked cancellation token, stops the relay, restores
   adapter mode, clears filters, and closes the driver handle.

### Packet filtering and direct relay

```text
application packet
  -> WinpkFilter send tunnel
  -> AdapterPipelineSet round-robin scheduler
  -> AdapterPipeline read
  -> PacketView parse
  -> process owner lookup
  -> configured app match
  -> TCP/UDP direct relay
  -> outbound Socket to original destination
  -> response read from Socket
  -> PacketInjector synthetic IPv4/IPv6 packet
  -> SendPacketToMstcp
  -> original application socket
```

Important behavior:

- Only the adapter send path is tunneled. Incoming traffic normally stays on
  the Windows stack so process attribution remains available.
- When the WFP classifier device is available, the adapter starts in normal
  pass-through mode. WFP resolves the application before the connection is
  emitted and WinpkFilter installs `FILTER_PACKET_REDIRECT` rules only for
  confirmed target five-tuples. Without WFP, ProxiFyre uses the userspace
  send-tunnel fallback without a kernel PASS cache; every non-target outbound
  packet is returned to its adapter from user mode.
- Pended UDP authorization captures and reinjects the first datagram through
  `FwpsInjectTransportSendAsync` after the user-mode verdict. Pending events
  are reaped after five seconds and the user-mode classifier fault stops the
  relay instead of leaving connections blocked.
- Relay-created outbound socket flows are recognized in user mode and returned
  to their adapter, preventing the relay from recursively intercepting itself.
- The userspace send-tunnel fallback intentionally disables WinpkFilter's
  fragment cache and static PASS table. Kernel filter-table churn can otherwise
  leave the machine with no working outbound path even while user-mode packet
  reads continue. WFP target-only mode is the only mode that installs kernel
  static filters, and it requires fragment cache support.
- The packet loop logs a health record every 30 seconds with mode, read/pass/
  redirect totals, adapter and MSTCP send outcomes, filter-table failures, and
  adapter queue depth. This remains enabled when detailed packet logging is off.
- An independent watchdog logs when the packet loop makes no progress for 30
  seconds, including the current stage and last known queue state, then logs
  recovery once progress resumes. This distinguishes a blocked driver call from
  normal relay traffic without depending on the packet thread.
- Continuous packet drains are bounded by both packet count and elapsed time,
  and adapters are serviced round-robin so a busy virtual or tunnel adapter
  cannot starve the active physical adapter. The dedicated long-running packet
  thread re-enumerates WinpkFilter adapters every five seconds and rebinds them
  when the adapter set changes during a session.
- TCP relay connections are capped at 4096, matching the UDP socket limit, so
  relay-owned kernel bypass entries cannot grow without bound.
- TCP interception starts on a SYN-only packet. The first packet passes
  normally when Windows has not yet published an owning process.
- TCP uses per-connection random initial sequence numbers, an MSS-bearing
  SYN-ACK, long-unwrapped sequence arithmetic, ACK-driven retransmission,
  client receive-window enforcement, bounded out-of-order buffering, and
  explicit half-close/FIN/RST states.
- UDP state is keyed by adapter, client address/port, and remote address/port.
  An unconnected remote socket is reused per relay key so a response from a
  changed source endpoint is preserved. Relay sockets pin the captured
  interface index with `IP_UNICAST_IF`/`IPV6_UNICAST_IF`, so multi-adapter and
  VPN route changes cannot silently move a relayed flow to another adapter.
- WinpkFilter adapter names are resolved through Windows
  `NetworkInterface.Id`/GUID as well as name, description, and MAC address.
  This is required for Wintun and virtual adapters that have no usable MAC.
- The relay does not open local listening ports. It does create outbound
  sockets, so normal Windows firewall behavior still applies.
- IPv4 and IPv6 are supported, including VLAN-tagged Ethernet frames. Outgoing
  IP fragments are reassembled before relay, and oversized UDP responses are
  fragmented to the adapter MTU before injection.

## `src/ProxiFyre`

### Entry points and command handling

| Path | Responsibility |
| --- | --- |
| `Program.cs` | Process entry point. Chooses CLI or WPF based on argument count; enforces single-instance UI behavior. |
| `Cli.cs` | Parses `--run`, `--config`, `--detailed`, `--reset-filter`, `--license-device`, `--license-key`, `--add-app`, and `--init-config`; writes traffic snapshots to the console. |

### `Configuration/`

| Path | Responsibility |
| --- | --- |
| `AppConfiguration.cs` | Loads and validates JSON configuration; normalizes `coreProcessName`; reads direct `apps` and `disabledApps`; saves sample/simple configurations; excludes the configured core process from relay matching. |
| `ConfigurationStore.cs` | Owns the config path, load-or-create behavior, change detection, atomic-ish save key tracking, and license-key preservation. |
| `DynamicAppConfiguration.cs` | Holds the current immutable configuration and publishes replacements using volatile reads/writes for live reloads. |

Supported configuration fields:

| Field | Meaning |
| --- | --- |
| `coreProcessName` | Process name used to select the AOT injection target. Defaults to `steamwebhelper.exe`. |
| `apps` | Direct application patterns. |
| `disabledApps` | Direct application patterns retained in the UI but excluded from relay matching. |
| `licenseKey` | Device-bound registration key stored in the configuration. |
| `moduleDllName` | DLL injected into the target. Defaults to `ProxiFyre.Module.dll`; the probe can be selected explicitly. |
| `enableFakeIpWhitelist` | Enables the special fake-IP DNS response path in `PacketFilterLoop`. |
| `enableUuWhitelistPatch` | Persists the Settings-tab UU runtime patch preference and enables the 3-second UU module monitor. |

Configuration hot reload currently keys on `coreProcessName` plus `apps`.
Changes limited to `enableFakeIpWhitelist`, `moduleDllName`, or `licenseKey`
require a full stop/load or explicit reload path rather than relying only on
the file watcher.

### `Dependencies/`

| Path | Responsibility |
| --- | --- |
| `WinpkFilterDependency.cs` | Detects the `ndisrd` service, WinpkFilter registry records, and MSI product code; downloads the pinned 3.6.2.1 x64 MSI with a GitHub/ghproxy fallback; installs or uninstalls with elevated `msiexec`; writes installer logs. |
| `WinpkFilterManager.cs` | UI-friendly wrapper around dependency detection and install/uninstall operations. Raises `StatusChanged`. |

### `Logging/`

| Path | Responsibility |
| --- | --- |
| `CoreLogger.cs` | Thread-safe append-only logger with timestamps. Writes to `proxifyre-core.log` and the attached console. Used by CLI and injected module hosts. |

### `ModuleLoading/`

| Path | Responsibility |
| --- | --- |
| `AotModuleController.cs` | Main injection and lifecycle controller. Resolves target processes, validates licenses, ensures the driver, copies the native DLL to a timestamped runtime path, installs hooks or uses remote-thread injection, locates the module window, sends commands, maintains heartbeats, reconnects, and cleans hooks. |
| `AotModuleTestController.cs` | Thin test-only wrapper that injects into an explicit PID, supplies a generated license key, and completes when the module reports that it is running. |
| `ModuleMessageClient.cs` | Creates a UI-side STA message window, sends `WM_COPYDATA` commands with timeouts, parses module events, and raises `ModuleEvent`. |
| `ModuleProcessLocator.cs` | Finds processes by configured name, orders them by PID, resolves image paths, and tests process liveness. |

Injection target ranking prefers visible top-level windows, then hidden
non-special windows, then low-priority integration windows, then ordinary
process threads. Candidate ordering then uses PID.

### `Native/`

| Path | Responsibility |
| --- | --- |
| `NdisApi.cs` | Managed `NDISRD` wrapper. Opens the kernel device, issues `DeviceIoControl` requests, reads one packet at a time, sends packets to MSTCP or the adapter, manages adapter mode/events, queue-depth queries, MTUs, and VLAN metadata, resets queues, and builds adapter/source/destination-aware outbound filters. |

Key native constants and structures include `IntermediateBuffer`,
`EthRequest`, `AdapterMode`, `StaticFilter`, and `TcpAdapterList`. The current
frame limit is `1514` bytes and the unsorted read API intentionally supports
one packet per call.

### `Network/`

| Path | Responsibility |
| --- | --- |
| `NetworkKeys.cs` | Immutable keys and relay target records: TCP session keys, UDP endpoint/relay keys, relay outbound flows, and `DirectRelayTarget` with process, client, adapter, and Ethernet context. |
| `NetworkEndpointResolver.cs` | Creates bind endpoints, remote endpoints, wildcard endpoints, and repairs IPv6 scope IDs for link-local, site-local, and multicast destinations. |
| `TlsSniParser.cs` | Parses TLS ClientHello and DTLS ClientHello SNI values with bounded probing and plausibility checks. Used for diagnostics. |
| `WfpProtocol.cs` | Mirrors the native WFP flow-event and verdict structures plus control-device IOCTL constants. |
| `WfpFlowClassifier.cs` | Opens the WFP control device, reads pending ALE connect events, resolves PID/process/config classification, and returns permit verdicts while optionally installing target redirect rules. |

### `PacketFiltering/`

| Path | Responsibility |
| --- | --- |
| `PacketFilterLoop.cs` | Packet-loop coordinator. Owns driver startup, event waiting, bounded draining, cancellation, TCP/UDP relay decisions, process matching, pass-through, and periodic health reporting. Adapter I/O, outbound filtering, injection, and DNS interception are delegated to the components below. |
| `AdapterPipeline.cs` | Per-adapter ingress pipeline. Owns one WinpkFilter adapter handle and reads one packet at a time into the shared packet processor. |
| `AdapterPipelineSet.cs` | Adapter lifecycle and scheduling. Enumerates adapters, sets modes, binds packet events, performs round-robin reads, rebinds after adapter-set changes, and restores normal adapter state. |
| `OutboundFilterController.cs` | Owns WFP target redirects, userspace send-tunnel fallback filters, temporary pass flows, expiration, retry, and filter-table health counters. |
| `PacketInjector.cs` | Builds and injects synthetic IPv4/IPv6 TCP, UDP, ICMP, and fragmented UDP packets. Owns transport/network checksums and MSTCP injection counters. |
| `DnsSpoofHandler.cs` | Handles fake-IP DNS queries and response injection through `PacketInjector`; also exposes DNS query parsing used by diagnostics. |
| `OutboundPassFlowRegistry.cs` | Stores dynamically classified non-target flow keys with a bounded capacity and TTL, evicting the oldest key when full and returning expired entries for kernel filter-table removal. |
| `IpFragmentReassembler.cs` | Reassembles IPv4/IPv6 outgoing fragments with VLAN metadata, per-assembly limits, duplicate detection, overlap validation, and original-fragment preservation for transparent pass-through. |
| `PacketView.cs` | Zero-copy-ish `ref struct` over an Ethernet or VLAN-tagged frame. Parses IPv4/IPv6, skips supported IPv6 extension headers, exposes addresses, ports, TCP options/urgent pointer, UDP declared length, and payload spans. |
| `PacketWakeSignal.cs` | Auto-reset event used by relay sockets to wake the packet loop after traffic counters or injected packets change. |
| `PacketFilterReset.cs` | Reset utility for `--reset-filter`. Clears static filters, removes adapter events, resets adapter modes, and flushes queued packets. |

### `ProxiFyre.Wfp/`

| Path | Responsibility |
| --- | --- |
| `driver.c` | Native WFP callout driver. Registers ALE_AUTH_CONNECT callouts for IPv4/IPv6, pends connect authorization, publishes PID/five-tuple/interface events through a control device, reinjects pended UDP first datagrams, and permits after a user-mode verdict or on timeout/unload. |
| `ProxiFyre.Wfp.inf` | Kernel service installation metadata for `ProxiFyre.Wfp.sys`. |
| `ProxiFyre.Wfp.vcxproj` | Visual Studio/WDK project metadata. The repository build script is authoritative when the installed Visual Studio build tools lack WDK platform-toolset integration. |

`Network/WfpProtocol.cs` and `Network/WfpFlowClassifier.cs` implement the
user-mode side; `Shared/WfpProtocol.h` is the shared wire layout.

### `Process/`

| Path | Responsibility |
| --- | --- |
| `ProcessLookup.cs` | Refreshes Windows IPv4/IPv6 TCP and UDP owner tables, caches PID information with a short validity window, resolves process names and image paths, supports wildcard UDP binding fallback, and handles ambiguous TCP port ownership conservatively. |
| `ProcessMatcher.cs` | Implements application matching. Bare names use substring matching, complete `.exe` paths use exact path comparison, directory patterns use normalized path prefixes, and other path-like values retain legacy substring matching. |

### `Relay/`

| Path | Responsibility |
| --- | --- |
| `RelayService.cs` | Owns relay lifetime and task supervision. Starts/stops the packet loop and TCP/UDP relays, watches configuration changes, reports one-second traffic snapshots, and propagates unexpected filter failure. |
| `TcpDirectRelay.cs` | Tracks TCP connections by adapter and full four-tuple; connects outbound sockets with a source-address/interface, source-address-only, then wildcard fallback for retryable local route errors; handles random ISN/MSS negotiation using the adapter MTU, long-unwrapped sequencing, retransmission, ACK processing, client windows, bounded out-of-order data, SYN payload bypass, urgent data best effort, half-close/FIN/RST, pending writes, deterministic failure cleanup, SNI probing, bypass registration, and maintenance cleanup. |
| `UdpDirectRelay.cs` | Tracks one unconnected outbound UDP socket per adapter/four-tuple with serialized creation/removal; pins the captured interface index, handles bind fallback, owner/process validation, same-address alternate response ports, broadcast/multicast pass-through, DTLS SNI probing, ICMP error callbacks, response injection callbacks, traffic counters, and activity-based cleanup. |
| `TrafficCounter.cs` | Thread-safe cumulative TCP/UDP upload/download counters and current-rate snapshot calculation. |

### `Telemetry/`

| Path | Responsibility |
| --- | --- |
| `TrafficTelemetryServer.cs` | UI-side named-pipe server. Accepts one module client through an explicit current-user DACL and a Medium mandatory label so an elevated UI can receive telemetry from non-elevated injected processes, reads newline-delimited snapshots, and invokes the UI callback. |

Wire format is defined in `src/Shared/TrafficTelemetry.cs`. Telemetry is
best-effort and intentionally separate from logs and the control channel.

### `UI/`

| Path | Responsibility |
| --- | --- |
| `App.xaml`, `App.xaml.cs` | WPF application resource definitions and application type. |
| `MainWindow.xaml`, `MainWindow.xaml.cs` | Main shell and orchestration: config load/save, rule editing, module attach/load/stop/reload, license dialog flow, update check, WinpkFilter actions, logs, tray behavior, telemetry status, and single-instance activation. |
| `HeaderBar.xaml`, `HeaderBar.xaml.cs` | Branding, source link, local/remote version display, running badge, and start/stop command. |
| `AnnouncementPanel.xaml`, `AnnouncementPanel.xaml.cs` | Displays dismissible manifest announcements. |
| `RuleEntryBar.xaml`, `RuleEntryBar.xaml.cs` | Collects `coreProcessName`, custom rules, application paths, and directory paths. |
| `ApplicationRulesTab.xaml`, `ApplicationRulesTab.xaml.cs` | Searchable application-rule list with enable/disable, edit, and remove actions. |
| `ApplicationRulesManager.cs` | Observable rule collection, filtering, sorting, duplicate checks, add/replace/remove/toggle operations, and conversion to enabled or disabled configuration patterns. |
| `ConfiguredApplication.cs` | UI model for executable, directory, and custom rule entries, including the persisted enabled/disabled state. |
| `ApplicationRuleKind.cs` | Rule-kind enum used for sorting and presentation. |
| `FuzzyMatcher.cs` | Search matcher that ignores spaces, hyphens, and underscores and supports ordered character subsequences. |
| `IconLoader.cs` | Extracts and freezes executable icons for WPF display. |
| `RuleEditDialog.cs` | Modal editor for custom application rules. |
| `RegistrationDialog.cs` | Device-ID display and license-key validation dialog. |
| `RuntimeInfoTab.xaml`, `RuntimeInfoTab.xaml.cs` | Shows relay mode, protocols, module target, socket ownership hint, config path, selectable read-only license key, and reload action. |
| `SettingsTab.xaml`, `SettingsTab.xaml.cs` | Displays WinpkFilter status with install/uninstall action and the UU runtime-patch toggle with confirmation/status events. |
| `SettingsViewModel.cs` | Observable presentation state for WinpkFilter and UU runtime-patch controls. |
| `UuPatchToggleRequestedEventArgs.cs` | Carries the requested enabled state from the Settings toggle to the MainWindow controller. |
| `LogsTab.xaml`, `LogsTab.xaml.cs` | Virtualized log list with select-all/selected copy and Ctrl+C support. |
| `MainTabs.xaml`, `MainTabs.xaml.cs` | Composes the four tabs and bridges child-control events to `MainWindow`. |
| `TrafficStatusBar.xaml`, `TrafficStatusBar.xaml.cs` | Displays upload/download totals and rates. |
| `ObservableObject.cs` | Small `INotifyPropertyChanged` base class. |
| `ItemRequestedEventArgs.cs`, `TextRequestedEventArgs.cs` | Child-control event payloads. |
| `UiSingleInstanceCoordinator.cs` | Named mutex/event coordination and activation of the existing main window. |

### Other `ProxiFyre` files

| Path | Responsibility |
| --- | --- |
| `Updates/UpdateChecker.cs` | Reads the assembly version and remote `manifest.json`; falls back through ghproxy; returns no-update, update-available, or failed results. |
| `Properties/AssemblyInfo.cs` | Grants `InternalsVisibleTo("TrafficTest")`. |
| `Assets/AppIcon.ico` | Application and tray icon resource. |

### `Uu/`

| Path | Responsibility |
| --- | --- |
| `UuElevation.cs` | Checks whether ProxiFyre is elevated, recognizes the elevated-UI launch argument, and restarts the WPF process through `runas` before UU process inspection or memory patching. |
| `UuPatchCatalog.cs` | Loads and validates UU patch profiles from `UuPatchProfiles.json`, parses hex byte arrays, RVAs, and wildcard function signatures, and resolves profiles by exact hash or signature. |
| `UuPatchLocator.cs` | Parses the PE executable sections, finds each function signature uniquely, maps signature offsets to RVAs, and rejects missing, ambiguous, or byte-mismatched targets. |
| `UuRuntimePatcher.cs` | Scans running UU processes for loaded `local_proxy.dll` modules, validates each target function, applies or restores code bytes with `VirtualProtectEx`/`WriteProcessMemory`, suspends the target process during writes, and flushes the instruction cache. |

## `src/ProxiFyre.Module`

| Path | Responsibility |
| --- | --- |
| `ModuleExports.cs` | NativeAOT entry surface and injected host. Exports `ProxiFyre_GetMsgProc`, starts a module initializer, creates the module control window, parses commands, starts/stops/reloads `RelayService`, emits events, manages UI heartbeat, and owns module logging. |
| `TrafficTelemetryClient.cs` | Best-effort named-pipe client. Reconnects in the background and writes one serialized `TrafficSnapshot` per relay statistics interval. |
| `ProxiFyre.Module.csproj` | Builds the production shared DLL. Links selected relay, configuration, networking, filtering, process, logging, license, and protocol files from the main project. |

## `src/ProxiFyre.Probe`

| Path | Responsibility |
| --- | --- |
| `ProbeExports.cs` | Diagnostic NativeAOT module. Installs inline x86/x64 hooks for `DeviceIoControl` and `FilterSendMessage`, logs input/output buffers, exposes the same command window protocol, and disables hooks on stop or timeout. |
| `ProxiFyre.Probe.csproj` | Builds the probe as a separate shared NativeAOT DLL into `artifacts/native/<Configuration>/`. |

The probe is for investigation only. It does not contain the production relay
loop.

## `src/Shared`

| Path | Responsibility |
| --- | --- |
| `LicenseKey.cs` | Creates a machine-bound device ID from `MachineGuid` or machine name, derives a fixed-length grouped license key, normalizes user input, and validates keys in fixed time. |
| `ModuleMessageProtocol.cs` | Defines `WM_COPYDATA` IDs, message-window class, hook export name, newline-delimited command/event serialization, Base64 event text, reply HWND handling, and boolean parsing. |
| `TrafficTelemetry.cs` | Defines the telemetry pipe name and compact total plus TCP/UDP `seq/up/down/upRate/downRate` line serialization and parsing. |

## `src/TrafficTest`

| Path | Responsibility |
| --- | --- |
| `Program.cs` | Minimal top-level call into `TrafficTestRunner.RunAsync`. |
| `TrafficTestRunner.cs` | Dispatches test and diagnostic modes; prepares a temporary AOT host; injects the module with an explicit PID; waits for relay readiness; runs curl/STUN; prints core-log summaries; also implements diagnostic injection and the Leigod demo child/parent modes. |
| `TestHelp.cs` | CLI help for TCP, UDP, process, telemetry, and Leigod diagnostics. |
| `TrafficTestConstants.cs` | Shared test-host process name. |
| `Curl/CurlTest.cs` | Runs system `curl.exe` without proxy environment variables and considers a 2xx response successful. |
| `Diagnostics/ProcessNetworkDiagnostic.cs` | Samples process TCP listeners, UDP endpoints, and TCP connections; supports text and JSON output. |
| `Diagnostics/TrafficTelemetryDiagnostic.cs` | Starts a telemetry server and client, sends three snapshots, and verifies delivery without WinpkFilter or Administrator rights. |
| `Diagnostics/PacketSelfTest.cs` | Driver-free parser, VLAN, TCP option/URG, UDP declared-length, IPv4/IPv6 fragment reassembly, UU patch-profile catalog, and outbound pass-flow registry capacity/TTL checks. |
| `Diagnostics/TcpRelaySelfTest.cs` | Driver-free loopback validation for TCP handshake, zero-window flow control, retransmission, bidirectional data, and the client FIN transition. |
| `Diagnostics/UdpRelaySelfTest.cs` | Driver-free loopback validation for UDP forwarding and alternate response endpoint preservation. |
| `Diagnostics/WindowsNetworkTable.cs` | Reads IPv4/IPv6 TCP and UDP owner tables from `iphlpapi.dll` for diagnostics. |
| `Diagnostics/WindowsProcessQuery.cs` | Finds processes and executable paths by name or PID. |
| `Infrastructure/CliOptions.cs` | Common option parsing helpers for split and `--name=value` forms. |
| `Infrastructure/CoreLogReporter.cs` | Shared-reader helpers for waiting on log markers and printing event/error counters plus relevant log tails. |
| `Infrastructure/ProcessIdentity.cs` | Resolves the current executable name for STUN test matching. |
| `Infrastructure/ProcessRunner.cs` | Starts child processes, optionally removes proxy variables, and quotes arguments. |
| `Infrastructure/RepositoryPaths.cs` | Walks parent directories until it finds `ProxiFyre.sln`. |
| `LeigodRedirectDemo.cs` | Environment-specific WFP/Leigod redirect demo with parent and child modes, temporary `steamwebhelper.exe`, DNS checks, connection monitoring, and TLS verification. |
| `Models/StunResult.cs` | STUN success/failure result record. |
| `Models/TestResult.cs` | Generic test stdout/stderr result. |
| `Options/TestKind.cs` | Relay test kind enum: curl or STUN. |
| `Options/TestOptions.cs` | Parses TCP and UDP test arguments and builds the curl command line. |
| `Stun/StunBindingTest.cs` | Runs one STUN binding request and reports mapped/remote endpoints and timing. |
| `Stun/StunClient.cs` | Resolves STUN endpoints, constructs binding requests, validates transaction IDs and magic cookies, and parses MAPPED-ADDRESS and XOR-MAPPED-ADDRESS. |

## `src/TrafficTestHost`

| Path | Responsibility |
| --- | --- |
| `App.xaml`, `App.xaml.cs` | Starts the WPF test host. |
| `MainWindow.xaml`, `MainWindow.xaml.cs` | Small visible window whose message loop is the injection target. |
| `TrafficTestHost.csproj` | Windows x64 WPF project. |

## Control and Data Contracts

### UI-to-module control channel

- Message: `WM_COPYDATA` (`0x004A`).
- Command ID: `0x50584643`.
- Event ID: `0x50584645`.
- Window class: `ProxiFyre.Module.ControlWindow`.
- Native hook export: `ProxiFyre_GetMsgProc`.
- Payload format: newline-delimited `key=value` text.
- Commands: `HEARTBEAT`, `PING`, `RUN`, `RELOAD`, `STOP`.
- `RUN` carries `configPath`, optional `logPath`, `replyHwnd`, `detailed`,
  and `telemetryPipeName`.

### Telemetry channel

- Pipe name: `ProxiFyre.Telemetry.v1`.
- Direction: module-side client writes to UI-side server.
- Encoding: UTF-8, one line per snapshot.
- Format:
  `seq=<n> up=<bytes> down=<bytes> upRate=<bytes/s> downRate=<bytes/s> tcpUp=<bytes> tcpDown=<bytes> tcpUpRate=<bytes/s> tcpDownRate=<bytes/s> udpUp=<bytes> udpDown=<bytes> udpUpRate=<bytes/s> udpDownRate=<bytes/s>`.
- Delivery is best-effort and does not block relay operation.

### Traffic accounting

`TrafficCounter` increments TCP/UDP upload bytes when payload is written to the
outbound socket and download bytes when payload is read from it. `RelayService`
samples cumulative totals and per-protocol totals once per second, calculates
rates, and forwards the snapshot to either the console or telemetry client. TCP
and UDP counters include relay payload bytes only, not Ethernet/IP/TCP/UDP
headers, handshake packets, retransmissions, or bypassed direct traffic.

### Process matching

- A pattern without `/` or `\` performs case-insensitive substring matching
  against the process executable name.
- A fully qualified `.exe` path performs normalized case-insensitive exact
  matching.
- A fully qualified directory path with a trailing separator, or an existing
  directory, matches executable paths under that directory.
- Other path-like patterns retain legacy case-insensitive path-substring
  matching.
- The configured `coreProcessName` is excluded to avoid host-process relay
  loops.

## Build and Output Layout

The PowerShell wrapper is the normal entry point:

| Command | Behavior |
| --- | --- |
| `.\scripts\proxifyre.ps1 build` | Publishes `ProxiFyre.Module`, `ProxiFyre.Probe`, and `TrafficTestHost`, then builds the solution. |
| `.\scripts\proxifyre.ps1 build -Configuration Release` | Same build flow in Release. |
| `.\scripts\proxifyre.ps1 ui` | Publishes module and probe, then runs the WPF app. |
| `.\scripts\proxifyre.ps1 run -Config .\app-config.json` | Runs `ProxiFyre --run` from the main project. |
| `.\scripts\proxifyre.ps1 test <mode> [-Detailed]` | Runs the already-built `TrafficTest.exe`. TCP/UDP modes have additional artifact prerequisites. |
| `.\scripts\proxifyre.ps1 reset-filter` | Clears WinpkFilter adapter state. |
| `.\scripts\proxifyre.ps1 add-app <pattern>` | Adds one application pattern to the selected config. |
| `.\scripts\proxifyre.ps1 init-config` | Writes a sample config. |
| `.\scripts\proxifyre.ps1 license-device` | Prints the current device ID and derived key. |
| `.\scripts\proxifyre.ps1 license-key <device-id>` | Prints the key for a supplied device ID. |
| `.\scripts\proxifyre.ps1 module-publish` | Publishes only the production NativeAOT module. |
| `.\scripts\proxifyre.ps1 patch-uu` | Creates a patched UU `local_proxy.dll` under `artifacts/uu-patch/<version>/`. Add `-Apply` to replace the installed DLL after creating a rollback backup, or `-Restore` to restore that backup. |
| `.\scripts\build-wfp.ps1 -Configuration Debug|Release` | Builds the WFP callout driver with the installed WDK into `artifacts/native/<Configuration>/`. |
| `.\scripts\install-wfp.ps1 -Configuration Debug|Release` | Installs or starts the WFP kernel service; development builds require test signing and a trusted signature. |
| `.\scripts\proxifyre.ps1 clean` | Cleans solution outputs plus repository-local build directories. |

Output locations:

| Path | Contents |
| --- | --- |
| `artifacts/bin/<Project>/<configuration>_win-x64/` | Normal .NET project outputs. |
| `artifacts/native/<Configuration>/` | `ProxiFyre.Module.dll`, `ProxiFyre.Probe.dll`, and `ProxiFyre.Wfp.sys` when built. |
| `artifacts/tmp/aot-test-host/` | Temporary renamed test hosts created by relay tests. |
| `artifacts/obj/` | Intermediate build output. |
| `release/proxifyre-win-x64.zip` | CI-staged Windows x64 package uploaded as the `proxifyre-win-x64` workflow artifact. The `release/` directory is ignored by Git. |
| `<app output>/runtime/<Configuration>/` | Timestamped module DLL copies prepared for injection. |
| `<app output>/dependencies/` | Cached WinpkFilter MSI and installer logs. |
| `<app output>/app-config.json` | UI runtime configuration. |
| `<app output>/UuPatchProfiles.json` | UU DLL hash, RVA fallback, and dynamic byte-signature catalog copied from `src/Shared`. |
| `<app output>/proxifyre-ui.log` | UI-side log. |
| `<app output>/proxifyre-core.log` | CLI or injected-module relay log. |
| `artifacts/uu-patch/<version>/local_proxy.dll` | Patch output for the matching UU `local_proxy.dll` version. The installer backup is written beside the installed DLL as `local_proxy.dll.uu-original.<hash>.bak`. |

Runtime requirements:

- Windows.
- .NET 10 SDK/runtime.
- Visual Studio C++ desktop build tools for NativeAOT publishing.
- WinpkFilter installed or installable.
- Administrator privileges for driver operations, packet filtering, and
  injection.
- Matching privileges with the running UU process for runtime memory patching.

## Focused Diagnostics

| Mode | What it validates | Extra requirements |
| --- | --- | --- |
| `tcp` | TCP relay path using a temporary injected WPF host and `curl.exe`; success requires a 2xx response. | Built main app, test host, module DLL, WinpkFilter, Administrator. |
| `udp` | UDP relay path using a STUN binding request from the injected host. | Same artifacts and privileges as TCP. |
| `uu` | UU process TCP listeners, UDP endpoints, and TCP connections. | A matching process for useful output. |
| `steam` | Steam WebHelper process network state. | Steam process for useful output. |
| `traffic-telemetry` | Named-pipe telemetry protocol, callback delivery, and the Medium-integrity security descriptor used across elevated/non-elevated processes. | No driver or Administrator requirement. |
| `packet-selftest` | Packet parsing, VLAN, TCP options/URG, UDP declared length, and IPv4/IPv6 fragment reassembly. | No driver or Administrator requirement. |
| `tcp-selftest` | Loopback TCP relay handshake, zero-window behavior, ACK/retransmission, bidirectional data, client FIN transition, and unavailable source-address fallback. | No driver or Administrator requirement. |
| `udp-selftest` | Loopback UDP forwarding and alternate response endpoint handling. | No driver or Administrator requirement. |
| `leigod-redirect` | Environment-specific Leigod WFP redirection demo. | Leigod/WFP environment and network access. |
| `inject` | Injects the configured module/probe into a running target PID. | Built AOT DLL and Administrator. |

There is no xUnit/NUnit test project. `TrafficTest` is the repository's
integration and regression harness.

## Invariants to Preserve

- Keep the current mode direct-only unless the requested change explicitly
  introduces proxy or service behavior.
- Do not add local TCP/UDP listener ports for direct relay.
- Preserve relay outbound bypass filters; removing them creates recursion.
- Do not enable WinpkFilter fragment cache or static PASS table churn in the
  userspace send-tunnel fallback. Kernel pass-cache updates are only valid for
  the WFP target-only path, which has explicit target flow ownership.
- If a captured outbound packet cannot be returned to its network adapter, restore every configured adapter to normal mode before terminating the filter loop so a relay failure cannot leave the machine offline.
- Preserve the outbound TCP fallback order: captured source plus interface, captured source only, then wildcard with no interface pinning. Retry only address, argument, or local route errors with a remaining fallback.
- Preserve `coreProcessName` exclusion to avoid relay loops in the injected
  process.
- Keep packet construction checksum-correct for both IPv4 and IPv6.
- Keep the AOT module's linked-source list synchronized when relay-core files
  are added, moved, or removed.
- Keep the module and UI message protocol backward-compatible unless both
  sides change together.
- Treat telemetry as optional; relay behavior must continue when the pipe is
  unavailable.
- Do not commit generated binaries, logs, runtime DLL copies, caches, or local
  `app-config.json`.
- Keep the Build artifact name `proxifyre-win-x64` and package name
  `proxifyre-win-x64.zip` stable; the Release workflow downloads them by name.
- Keep the required ZIP entries and NativeAOT Release outputs intact when
  changing build or staging behavior.
- Keep Release promotion manual through the successful `build_id` and
  `version` inputs. Do not implicitly publish a Release from a push.

## Known Limitations

- Proxy mode and Windows service mode are intentionally not implemented.
- Runtime relay operation is Windows-only and normally requires Administrator.
- The first TCP packet may pass normally if owner information is not yet
  available.
- TCP SYN-payload/TFO traffic is kept on the original pass-through path rather
  than partially relayed.
- The relay advertises MSS but does not negotiate SACK, timestamps, or window
  scaling on the synthetic client-facing TCP endpoint.
- Non-Ethernet link-layer media and IPv6 jumbograms are not modeled.
- Remote TCP urgent data is best effort because the managed socket API does not
  expose urgent pointer metadata symmetrically.
- UDP alternate responses are accepted from the same remote address with a
  changed source port; cross-address endpoint migration is rejected.
- The NDIS wrapper reads one packet per unsorted-read call.
- The maximum Ethernet frame handled by packet construction is 1514 bytes;
  larger UDP datagrams are split into IP fragments up to adapter MTU limits.
- The AOT module cannot migrate to a new process; changing `coreProcessName`
  requires loading the module into the new target.
- `ProxiFyre.Probe` is an investigation tool, not a production fallback.
- The Leigod redirect diagnostic depends on an external WFP/driver environment
  and is not a portable automated test.
- UU runtime patching requires either a matching SHA256 profile or a unique
  dynamic function-signature match, plus an already loaded module. The patch is
  lost when UU restarts and is intentionally not written to the installed DLL.
- UU process matching, local/private traffic handling, unsupported protocols,
  proxy-line availability, and region/health fallbacks remain outside the
  runtime patch.
