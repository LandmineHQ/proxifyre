# ProxiFyre Repository Map

This document is the source of truth for the current architecture, runtime
flows, file ownership, protocols, build commands, and limitations.

## System Summary

ProxiFyre is a Windows-only .NET 10 WPF, NativeAOT, and WinDivert traffic
relay. The production data plane is WinDivert-only; WinpkFilter/NDISRD and the
previous custom WFP callout driver have been removed.

The relay uses two WinDivert layers:

- `WINDIVERT_LAYER_NETWORK` captures outbound TCP/UDP packets and injects
  modified or synthetic IPv4/IPv6 packets.
- `WINDIVERT_LAYER_FLOW` provides process ownership for established flows.
  `GetExtendedTcpTable` and `GetExtendedUdpTable` are the fallback for the
  initial SYN or first UDP datagram, where a flow event may not exist yet.

WinDivert's official `WinDivert.dll` and digitally signed `WinDivert64.sys`
are deployed as native assets. ProxiFyre does not enable test signing.

## Projects

| Project | Output | Responsibility |
| --- | --- | --- |
| `src/ProxiFyre/ProxiFyre.csproj` | WPF application and CLI | UI, configuration, module injection, WinDivert relay, telemetry, UU patch integration. |
| `src/ProxiFyre.Module/ProxiFyre.Module.csproj` | NativeAOT shared DLL | Injected relay host and linked relay/runtime sources. |
| `src/ProxiFyre.Probe/ProxiFyre.Probe.csproj` | Diagnostic NativeAOT DLL | Investigation-only API hook probe. |
| `src/TrafficTest/TrafficTest.csproj` | Console diagnostics | Packet, UDP relay, process, telemetry, and environment diagnostics. |
| `src/TrafficTestHost/TrafficTestHost.csproj` | Minimal WPF host | Injection target for runtime diagnostics. |

`src/Shared` is linked into multiple projects. It is not a standalone assembly.

## High-Level Architecture

```text
application TCP SYN
  -> WinDivert NETWORK outbound capture
  -> process attribution (FLOW + IP Helper fallback)
  -> TcpDirectRelay user-space TCP state machine
  -> real remote TCP socket
  -> synthetic TCP segment injected inbound through WinDivert

application UDP datagram
  -> WinDivert NETWORK outbound capture
  -> process attribution
  -> UdpDirectRelay pinned outbound UDP socket
  -> real remote UDP response
  -> synthetic IPv4/IPv6 UDP packet injected inbound through WinDivert
```

## Runtime Flows

### Startup

1. `Program.Main` starts the WPF UI or CLI.
2. The UI injects `ProxiFyre.Module.dll` into the target core process.
3. `AotModuleController` publishes `WinDivert.dll` and `WinDivert64.sys` next
   to the hashed runtime module DLL and passes that native directory in the
   module command.
4. The elevated UI opens the WinDivert NETWORK/FLOW handles and duplicates them
   into the target process. This avoids requiring the game/core process itself
   to run elevated.
5. `RelayService.Start` creates `WinDivertPacketRouter`.
6. The router receives the NETWORK handle with filter
   `outbound and !loopback and (tcp or udp)` and `FRAGMENTS` enabled.
7. A separate FLOW handle captures `ESTABLISHED` and `DELETED` events. Failure
   to open the flow handle degrades to process-table attribution.
8. `TcpDirectRelay` and `WinDivertUdpRelay` start their bounded state.

### TCP

1. The NETWORK loop parses an outbound IPv4/IPv6 TCP packet.
2. Existing relay connections are matched by the four-tuple and processed
   without a new process lookup.
3. For a new SYN, the router resolves the owner PID and checks the configured
   app patterns.
4. A matching SYN is dropped from the normal stack and registered with
   `TcpDirectRelay`.
5. `TcpDirectRelay` connects a real remote socket, owns sequence/window state,
   and forwards client payload.
6. Synthetic SYN-ACK, ACK, data, FIN, and RST segments are built by
   `WinDivertPacketBuilder` and injected as inbound packets.
7. Relay-owned outbound sockets are excluded by process identity and/or
   registered tuple, preventing recursion.

The initial TCP path is a packet-level state machine. It intentionally does not
use a local loopback listener.

### UDP

1. The NETWORK loop parses an outbound UDP datagram.
2. The owner PID is resolved from the FLOW tracker or the Windows UDP table.
3. `WinDivertUdpRelay` creates an `UdpRelayKey` and delegates to
   `UdpDirectRelay`.
4. `UdpDirectRelay` keeps one outbound socket per local endpoint, pins the
   captured interface index, and preserves the external source port across
   remote destinations.
5. The first datagram of a new session is sent synchronously before WinDivert
   consumes the original packet; later datagrams use the bounded send queue.
6. A remote response is accepted only from a registered endpoint and injected
   back to the application as a checksum-correct IPv4/IPv6 UDP packet.
7. The original outbound datagram is dropped only after a successful relay
   send or queued submission; failures pass the original packet through.

### DNS Fake-IP

When `enableFakeIpWhitelist` is enabled, matching DNS queries are handled by
`WinDivertDnsSpoofHandler`. The synthetic response is injected through the same
WinDivert inbound path as ordinary UDP responses.

### Configuration Reload

`RelayService` watches `app-config.json`, updates `DynamicAppConfiguration`,
and calls `WinDivertPacketRouter.ApplyConfiguration`. Existing TCP connections
and UDP targets whose process no longer matches are removed.

## WinDivert Runtime

| Path | Responsibility |
| --- | --- |
| `src/ProxiFyre/Network/WinDivertNative.cs` | Thin Cdecl P/Invoke layer, safe handles, queue parameters, native DLL resolution. |
| `src/ProxiFyre/Network/WinDivertAddress.cs` | Exact 80-byte `WINDIVERT_ADDRESS` layout and layer/event bit masks. |
| `src/ProxiFyre/Network/WinDivertPacketRouter.cs` | NETWORK receive loop, packet classification, pass-through, and lifecycle. |
| `src/ProxiFyre/Network/WinDivertFlowTracker.cs` | FLOW-layer PID association and stale-flow cleanup. |
| `src/ProxiFyre/Network/WinDivertPacketBuilder.cs` | Checksum-correct IPv4/IPv6 TCP and UDP packet construction. |
| `src/ProxiFyre/Network/WinDivertPacketInjector.cs` | Inbound packet injection and interface resolution. |
| `src/ProxiFyre/Network/WinDivertUdpRelay.cs` | UDP capture-to-`UdpDirectRelay` adapter. |
| `src/ProxiFyre/Network/WinDivertDnsSpoofHandler.cs` | Optional fake-IP DNS interception. |
| `src/ProxiFyre/Relay/TcpDirectRelay.cs` | Transparent user-space TCP state machine and remote socket I/O. |
| `src/ProxiFyre/Relay/UdpDirectRelay.cs` | Bounded UDP sessions, targets, response validation, and interface pinning. |
| `src/ProxiFyre/Relay/RelayService.cs` | Relay lifecycle, configuration reload, telemetry, and task supervision. |
| `src/ProxiFyre/Process/ProcessLookup.cs` | Windows TCP/UDP owner lookup and process metadata cache. |

`WinDivert.dll` and `WinDivert64.sys` are copied from the official
`Native.WinDivert` 2.2.2 NuGet package. `WinDivert-LICENSE.txt` contains the
required third-party license text. Their SHA-256 hashes are pinned before the
driver or userspace DLL is loaded.

## Build And Validation

```powershell
.\scripts\proxifyre.ps1 build
.\scripts\proxifyre.ps1 build -Configuration Release
.\scripts\proxifyre.ps1 package -Configuration Release
.\scripts\proxifyre.ps1 ui
.\scripts\proxifyre.ps1 run -Config .\app-config.json
.\scripts\proxifyre.ps1 test packet-selftest
.\scripts\proxifyre.ps1 test tcp-selftest
.\scripts\proxifyre.ps1 test udp-selftest
.\scripts\proxifyre.ps1 test windivert-probe
.\scripts\proxifyre.ps1 test windivert-tcp-probe
.\scripts\proxifyre.ps1 test windivert-bypass-probe
.\scripts\proxifyre.ps1 test <tcp|udp|uu|steam|traffic-telemetry> [-Detailed]
.\scripts\proxifyre.ps1 module-publish
.\scripts\proxifyre.ps1 clean
```

`packet-selftest`, `tcp-selftest`, and `udp-selftest` are driver-free and do
not require Administrator privileges. `packet-selftest` validates the
WinDivert address layout, packet builders, UU patch catalog, and UU
configuration round-trip.

Runtime TCP/UDP relay diagnostics require Windows, Administrator privileges,
and a compatible WinDivert driver/loading policy.

`package` consumes the Release build output and delegates to
`scripts/package-release.ps1`. That script owns the production file allowlist,
native hash/signature checks, exact archive-content validation, manifest/app
version consistency, and creation of `release/proxifyre-win-x64.zip`.

## Diagnostics

| Mode | Purpose |
| --- | --- |
| `tcp` | End-to-end relay diagnostic using the injected WPF host and `curl.exe`. |
| `udp` | End-to-end UDP relay diagnostic using STUN, with optional multi-flow latency sampling. |
| `traffic-telemetry` | Named-pipe telemetry verification without a driver. |
| `packet-selftest` | Packet parser, WinDivert layout, packet builders, UU config, and interface diagnostics. |
| `tcp-selftest` | Driver-free TCP handshake, payload, ACK, retransmission, close, and cleanup behavior. |
| `udp-selftest` | Driver-free UDP session behavior, source rejection, pinning, and reload cleanup. |
| `windivert-probe` | Opens the signed WinDivert NETWORK/FLOW handles and reports the driver version. |
| `windivert-tcp-probe` | Verifies synthetic SYN-ACK injection into a real socket without the full relay state machine. |
| `windivert-bypass-probe` | Verifies concurrent non-target HTTP/UDP pass-through while WinDivert is active. |

## Known Limitations

- WinDivert `NETWORK` packets do not contain a process ID. PID attribution is
  necessarily a correlation step and can race with process termination.
- The initial SYN or first UDP datagram falls back to the Windows owner table
  if a FLOW event is not available yet.
- Fragmented IP packets are captured with `FRAGMENTS` but currently pass
  through without relay reassembly; they are not silently split by the relay.
- WinDivert requires Administrator privileges to open the driver handle. The
  official driver is signed, but HVCI, Code Integrity policy, or EDR may still
  block it on a managed machine.
- The elevated UI must be able to duplicate the WinDivert handles into the
  target process. Protected processes or stricter process-access policy can
  still block this capability transfer.
- The duplicated handle gives the target process machine-wide outbound packet
  capture/injection capability. Only trusted target processes should be
  configured; full least-privilege isolation would require moving the data
  plane into a separate authenticated helper process.
- TCP and UDP response packets are synthetic. The relay does not preserve the
  remote server's original TCP options or IP TTL beyond protocol-correct
  values.
- The AOT module cannot migrate to a new process. Changing `coreProcessName`
  requires loading the module into the new target.
- UU runtime patching remains separate from the WinDivert relay data plane.

## Release Contract

The Windows Release artifact remains `proxifyre-win-x64.zip`. Required runtime
entries are:

`ProxiFyre.exe`, `ProxiFyre.dll`, `ProxiFyre.deps.json`,
`ProxiFyre.runtimeconfig.json`, `ProxiFyre.Module.dll`,
`WinDivert.dll`, `WinDivert64.sys`, `WinDivert-LICENSE.txt`,
`THIRD_PARTY_NOTICES.md`, `LICENSE`, `manifest.json`, and
`UuPatchProfiles.json`.

`README.md` and `UU_ACCELERATOR.md` are documentation-only and must not be
staged into the release ZIP. `ProxiFyre.Probe.dll` is diagnostic-only and is
also excluded from the production package.
