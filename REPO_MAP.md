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
|-- ProxiFyre.Module
|   `-- ModuleExports -> injected RelayService + telemetry client
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
| `README.md` | User-facing overview, requirements, build/run examples, configuration shape, and known limitations. |
| `ProxiFyre.sln` | Visual Studio solution for the four main projects. |
| `Directory.Build.props` | Enables centralized artifacts output under `artifacts/`. |
| `Directory.Build.targets` | Removes temporary `_wpftmp` output directories after WPF builds. |
| `global.json` | Pins the expected .NET SDK to `10.0.100` with latest-feature roll-forward. |
| `manifest.json` | Local version, source URL, and announcement metadata copied into application output. |
| `scripts/proxifyre.ps1` | Main PowerShell development wrapper for build, UI, run, tests, config, license, publishing, reset, and clean operations. |
| `.gitignore` | Excludes build output, logs, caches, local `app-config.json`, and temporary files. |
| `app-config.json` | Local runtime configuration. It is intentionally ignored by Git. |
| `LICENSE` | Repository license. |

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
  -> PacketView parse
  -> process owner lookup
  -> configured app match
  -> TCP/UDP direct relay
  -> outbound Socket to original destination
  -> response read from Socket
  -> synthetic IPv4/IPv6 packet
  -> SendPacketToMstcp
  -> original application socket
```

Important behavior:

- Only the adapter send path is tunneled. Incoming traffic normally stays on
  the Windows stack so process attribution remains available.
- Relay-created outbound socket flows are registered in a WinpkFilter static
  pass table, preventing the relay from recursively intercepting itself.
- Non-target TCP/UDP flows are classified from their first user-mode packet and
  then registered in the same kernel pass table with a bounded five-second TTL.
  Subsequent packets for those flows stay in the kernel; target flows remain
  tunneled and use the direct relay. A one-second maintenance wake handles TTL
  expiry even when no other packet reaches user mode.
- TCP interception starts on a SYN-only packet. The first packet passes
  normally when Windows has not yet published an owning process.
- TCP uses per-connection random initial sequence numbers, an MSS-bearing
  SYN-ACK, long-unwrapped sequence arithmetic, ACK-driven retransmission,
  client receive-window enforcement, bounded out-of-order buffering, and
  explicit half-close/FIN/RST states.
- UDP state is keyed by adapter, client address/port, and remote address/port.
  An unconnected remote socket is reused per relay key so a response from a
  changed source endpoint is preserved.
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
| `AppConfiguration.cs` | Loads and validates JSON configuration; normalizes `coreProcessName`; merges direct `apps` and legacy `proxies[].appNames`; saves sample/simple configurations; excludes the configured core process from relay matching. |
| `ConfigurationStore.cs` | Owns the config path, load-or-create behavior, change detection, atomic-ish save key tracking, and license-key preservation. |
| `DynamicAppConfiguration.cs` | Holds the current immutable configuration and publishes replacements using volatile reads/writes for live reloads. |

Supported configuration fields:

| Field | Meaning |
| --- | --- |
| `coreProcessName` | Process name used to select the AOT injection target. Defaults to `steamwebhelper.exe`. |
| `apps` | Direct application patterns. |
| `proxies[].appNames` | Legacy migration input. Other proxy fields are ignored. |
| `licenseKey` | Device-bound registration key stored in the configuration. |
| `moduleDllName` | DLL injected into the target. Defaults to `ProxiFyre.Module.dll`; the probe can be selected explicitly. |
| `enableFakeIpWhitelist` | Enables the special fake-IP DNS response path in `PacketFilterLoop`. |

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
| `NdisApi.cs` | Managed `NDISRD` wrapper. Opens the kernel device, issues `DeviceIoControl` requests, reads one packet at a time, sends packets to MSTCP or the adapter, manages adapter mode/events, MTUs, and VLAN metadata, resets queues, and builds adapter/source/destination-aware outbound bypass filters. |

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

### `PacketFiltering/`

| Path | Responsibility |
| --- | --- |
| `PacketFilterLoop.cs` | Central packet-processing loop. Configures adapters, watches WinpkFilter events, parses or reassembles packets, classifies outgoing TCP/UDP, performs process matching, redirects target flows, registers expiring kernel pass flows for classified non-target traffic, injects synthetic TCP/UDP/ICMP responses, fragments oversized UDP output, manages bypass filters, handles the fake-IP DNS path, computes checksums, and logs throttled diagnostics. |
| `OutboundPassFlowRegistry.cs` | Stores dynamically classified non-target flow keys with a bounded capacity and TTL, evicting the oldest key when full and returning expired entries for kernel filter-table removal. |
| `IpFragmentReassembler.cs` | Reassembles IPv4/IPv6 outgoing fragments with VLAN metadata, per-assembly limits, duplicate detection, overlap validation, and original-fragment preservation for transparent pass-through. |
| `PacketView.cs` | Zero-copy-ish `ref struct` over an Ethernet or VLAN-tagged frame. Parses IPv4/IPv6, skips supported IPv6 extension headers, exposes addresses, ports, TCP options/urgent pointer, UDP declared length, and payload spans. |
| `PacketWakeSignal.cs` | Auto-reset event used by relay sockets to wake the packet loop after traffic counters or injected packets change. |
| `PacketFilterReset.cs` | Reset utility for `--reset-filter`. Clears static filters, removes adapter events, resets adapter modes, and flushes queued packets. |

### `Process/`

| Path | Responsibility |
| --- | --- |
| `ProcessLookup.cs` | Refreshes Windows IPv4/IPv6 TCP and UDP owner tables, caches PID information with a short validity window, resolves process names and image paths, supports wildcard UDP binding fallback, and handles ambiguous TCP port ownership conservatively. |
| `ProcessMatcher.cs` | Implements application matching. Bare names use substring matching, complete `.exe` paths use exact path comparison, directory patterns use normalized path prefixes, and other path-like values retain legacy substring matching. |

### `Relay/`

| Path | Responsibility |
| --- | --- |
| `RelayService.cs` | Owns relay lifetime and task supervision. Starts/stops the packet loop and TCP/UDP relays, watches configuration changes, reports one-second traffic snapshots, and propagates unexpected filter failure. |
| `TcpDirectRelay.cs` | Tracks TCP connections by adapter and full four-tuple; connects outbound sockets; handles random ISN/MSS negotiation using the adapter MTU, long-unwrapped sequencing, retransmission, ACK processing, client windows, bounded out-of-order data, SYN payload bypass, urgent data best effort, half-close/FIN/RST, pending writes, deterministic failure cleanup, SNI probing, bypass registration, and maintenance cleanup. |
| `UdpDirectRelay.cs` | Tracks one unconnected outbound UDP socket per adapter/four-tuple with serialized creation/removal; handles bind fallback, owner/process validation, same-address alternate response ports, broadcast/multicast pass-through, DTLS SNI probing, ICMP error callbacks, response injection callbacks, traffic counters, and activity-based cleanup. |
| `TrafficCounter.cs` | Thread-safe cumulative upload/download counters and current-rate snapshot calculation. |

### `Telemetry/`

| Path | Responsibility |
| --- | --- |
| `TrafficTelemetryServer.cs` | UI-side named-pipe server. Accepts one same-user module client, reads newline-delimited snapshots, and invokes the UI callback. |

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
| `ApplicationRulesTab.xaml`, `ApplicationRulesTab.xaml.cs` | Searchable application-rule list with edit and remove actions. |
| `ApplicationRulesManager.cs` | Observable rule collection, filtering, sorting, duplicate checks, add/replace/remove operations, and conversion to configuration patterns. |
| `ConfiguredApplication.cs` | UI model for executable, directory, and custom rule entries. |
| `ApplicationRuleKind.cs` | Rule-kind enum used for sorting and presentation. |
| `FuzzyMatcher.cs` | Search matcher that ignores spaces, hyphens, and underscores and supports ordered character subsequences. |
| `IconLoader.cs` | Extracts and freezes executable icons for WPF display. |
| `RuleEditDialog.cs` | Modal editor for custom application rules. |
| `RegistrationDialog.cs` | Device-ID display and license-key validation dialog. |
| `RuntimeInfoTab.xaml`, `RuntimeInfoTab.xaml.cs` | Shows relay mode, protocols, module target, socket ownership hint, config path, and reload action. |
| `SettingsTab.xaml`, `SettingsTab.xaml.cs` | Displays license key and WinpkFilter status with install/uninstall action. |
| `SettingsViewModel.cs` | Observable presentation state for license and WinpkFilter controls. |
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
| `TrafficTelemetry.cs` | Defines the telemetry pipe name and compact `seq/up/down/upRate/downRate` line serialization and parsing. |

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
| `Diagnostics/PacketSelfTest.cs` | Driver-free parser, VLAN, TCP option/URG, UDP declared-length, IPv4/IPv6 fragment reassembly, and outbound pass-flow registry capacity/TTL checks. |
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
  `seq=<n> up=<bytes> down=<bytes> upRate=<bytes/s> downRate=<bytes/s>`.
- Delivery is best-effort and does not block relay operation.

### Traffic accounting

`TrafficCounter` increments upload bytes when payload is written to the
outbound socket and download bytes when payload is read from it. `RelayService`
samples cumulative totals once per second, calculates rates, and forwards the
snapshot to either the console or telemetry client.

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
| `.\scripts\proxifyre.ps1 clean` | Cleans solution outputs plus repository-local build directories. |

Output locations:

| Path | Contents |
| --- | --- |
| `artifacts/bin/<Project>/<configuration>_win-x64/` | Normal .NET project outputs. |
| `artifacts/native/<Configuration>/` | `ProxiFyre.Module.dll` and `ProxiFyre.Probe.dll`. |
| `artifacts/tmp/aot-test-host/` | Temporary renamed test hosts created by relay tests. |
| `artifacts/obj/` | Intermediate build output. |
| `<app output>/runtime/<Configuration>/` | Timestamped module DLL copies prepared for injection. |
| `<app output>/dependencies/` | Cached WinpkFilter MSI and installer logs. |
| `<app output>/app-config.json` | UI runtime configuration. |
| `<app output>/proxifyre-ui.log` | UI-side log. |
| `<app output>/proxifyre-core.log` | CLI or injected-module relay log. |

Runtime requirements:

- Windows.
- .NET 10 SDK/runtime.
- Visual Studio C++ desktop build tools for NativeAOT publishing.
- WinpkFilter installed or installable.
- Administrator privileges for driver operations, packet filtering, and
  injection.

## Focused Diagnostics

| Mode | What it validates | Extra requirements |
| --- | --- | --- |
| `tcp` | TCP relay path using a temporary injected WPF host and `curl.exe`; success requires a 2xx response. | Built main app, test host, module DLL, WinpkFilter, Administrator. |
| `udp` | UDP relay path using a STUN binding request from the injected host. | Same artifacts and privileges as TCP. |
| `uu` | UU process TCP listeners, UDP endpoints, and TCP connections. | A matching process for useful output. |
| `steam` | Steam WebHelper process network state. | Steam process for useful output. |
| `traffic-telemetry` | Named-pipe telemetry protocol and callbacks. | No driver or Administrator requirement. |
| `packet-selftest` | Packet parsing, VLAN, TCP options/URG, UDP declared length, and IPv4/IPv6 fragment reassembly. | No driver or Administrator requirement. |
| `tcp-selftest` | Loopback TCP relay handshake, zero-window behavior, ACK/retransmission, bidirectional data, and client FIN transition. | No driver or Administrator requirement. |
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
