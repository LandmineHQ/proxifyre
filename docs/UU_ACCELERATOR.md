# UU Accelerator Handling

## Scope

This document describes how NetEase UU Game Booster handles accelerated
traffic and how ProxiFyre applies a runtime-only compatibility patch.

UU uses Windows Filtering Platform (WFP), not .NET WPF, for this path. The
installed UI is a 32-bit application and loads `local_proxy.dll` when a game
or application is actively accelerated.

## Analyzed Components

| Component | Role |
| --- | --- |
| `uu.exe` | UI, process selection, driver installation, and lifetime management. |
| `local_proxy.dll` | Parses application, domain, IP, port, and routing policy. Opens `\\.\uuwfp` and writes the selected process/proxy settings. |
| `uuwfp.sys` | Custom WFP callout driver. Intercepts selected TCP/UDP/ICMP flows and exchanges packet or connection events with `local_proxy.dll`. |
| `uunetfilter.sys` | Generic NetFilter2/NF3 redirect driver used by UU in some paths. It does not contain the domain whitelist policy. |

At the time of analysis, the active UU build was `6.18.3` with installation
directory `5247` and `local_proxy.dll` version `9.9.9.99`.

## Traffic Flow

1. `uu.exe` selects the accelerated application and starts the local proxy
   runtime.
2. `start_local_proxy` loads the UU configuration.
3. `local_proxy.dll` parses `tcp_whitelists`, `udp_whitelists`,
   `process_domain_restriction`, `ip_port_hijack`, and related policy.
4. Per-flow logic first checks whether the owning process is accepted by the
   UU process ACL.
5. TCP and UDP paths then evaluate process-domain restrictions, destination
   IP/port rules, ban lists, browser QUIC rules, and proxy selection.
6. `local_proxy.dll` writes values such as `proxy_pid`, `proxy_name`,
   `proxy_ip`, `proxy_port`, `u_on`, `i_on`, and `t_s_on` to
   `HKLM\SYSTEM\CurrentControlSet\Services\uuwfp\Parameters`.
7. The same module configures `uuwfp.sys` with control IOCTLs:

   | IOCTL | Purpose |
   | --- | --- |
   | `0x120004` | Read queued driver packet or ICMP events. |
   | `0x120008` | Set the driver signal event. |
   | `0x12000C` | Set remote proxy IP and port. |
   | `0x120010` | Set the `svchost` or DoSvc PID used by the driver. |
   | `0x120014` | Read a pending TCP SYN item. |
   | `0x120018` | Set the TCP SYN signal event. |
   | `0x12001C` | Complete or release a TCP SYN item. |

`uuwfp.sys` does not receive or parse domain names. It receives the process
and proxy endpoint state selected by `local_proxy.dll`.

## Runtime Patch

The UI does not modify the installed DLL. It opens the running UU process,
locates the loaded `local_proxy.dll`, temporarily changes the selected code
page protection, writes replacement stubs, flushes the instruction cache,
and restores the original page protection.

The patch preserves the UU process ACL check. It changes only the policy
checks that reject or divert traffic by domain, destination IP, destination
port, ban list, or browser QUIC rule.

For the supported `5247` profile, the runtime patch targets are:

| Function RVA | Purpose | Patched result |
| --- | --- | --- |
| `0x526C0` | TCP process-domain restriction | Return no restriction. |
| `0xB2A10` | UDP/TCP secondary domain restriction | Return no restriction. |
| `0x996A0` | Proxy ACL destination match | Treat every process-matched destination as a match. |
| `0x9A770` | TCP destination ban list | Return not banned. |
| `0x9A870` | UDP game ban list | Return not banned. |
| `0x994B0` | Browser QUIC block | Return not blocked. |
| `0x9DC80` | UDP destination/port block rules | Return not blocked. |

Each profile contains an exact source SHA256 as a fast path and a unique
function signature for every target. The patcher reads the PE `.text` section
and wildcards relocation-sensitive bytes in those signatures. If the installed
DLL is a newer build, ProxiFyre still locates the function when every target
signature remains unique and the bytes at the resolved address match either the
known original or known patched form. A missing or ambiguous signature fails
closed and does not write anything.

## UI Behavior

The Settings tab exposes a UU toggle:

- It scans running UU processes and looks for `local_proxy.dll`.
- It identifies whether each loaded module is original, partially patched, or
  already fully patched.
- It asks for confirmation before applying the runtime patch.
- If UU is elevated and ProxiFyre is not, enabling the toggle requests UAC
  approval and restarts the WPF UI elevated. The elevated instance waits for
  the old single-instance mutex, reads the persisted setting, and starts the
  monitor automatically.
- UAC is requested only when the persisted `enableUuWhitelistPatch` value is
  true, or when the user actively enables the toggle from a non-elevated UI.
- The enabled state is persisted as `enableUuWhitelistPatch` in
  `app-config.json`.
- While enabled, ProxiFyre checks the UU process every 3 seconds for the
  lifetime of the UI process. If UU was restarted or reloaded
  `local_proxy.dll`, the runtime patch is validated and reapplied
  automatically. An already patched module is left unchanged.
- It reports when UU is not running or when `local_proxy.dll` has not loaded
  yet.
- It reports an actionable error when the DLL hash or a function signature is
  unsupported.
- Turning the toggle off restores the original bytes in memory.
- If ProxiFyre exits normally after applying the patch in the current session,
  it restores the original bytes before closing. A forced termination skips
  this cleanup, but the patch still disappears when UU restarts.

The runtime patch is temporary. Restarting UU discards it. The
`local_proxy.dll` file and its Authenticode content remain unchanged.

No confirmation DLL or message channel is injected into UU. ProxiFyre can
read the loaded module path, file hash, executable bytes, and patch state
directly from the UU process, so the UI status is based on the live target
state rather than a separate in-process agent.

## Offline Patch Script

`scripts/patch-uu-whitelist.ps1` can produce an on-disk patched copy for
diagnostics or deployment. It uses the same exact-hash fast path and dynamic
function-signature matching as the WPF runtime patcher. The WPF UI uses the
runtime patcher and does not require the offline script.

## Limitations

- Dynamic signatures tolerate DLL layout and RVA changes when the target
  functions themselves remain unchanged.
- A function-body change can invalidate a signature; an updated profile must
  be added for that new function form.
- A signature must be unique in the executable sections. Ambiguous matches are
  rejected.
- Process matching remains mandatory; an unrecognized process is not
  accelerated.
- Localhost, private, broadcast, multicast, unsupported protocol, unavailable
  proxy line, and region/health fallback paths are outside this patch.
- Runtime patching requires access to the UU process. Protected processes or
  elevated UU instances can require ProxiFyre to run elevated as well.
