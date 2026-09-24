# UU Accelerator Handling

[简体中文](UU_ACCELERATOR.zh-CN.md)

## Scope

This document describes the UU compatibility path implemented by ProxiFyre:
the UU components involved, the policy values passed between them, the
functions that are patched, and the runtime mechanics used to patch only the
loaded `local_proxy.dll` image.

UU uses the Windows Filtering Platform (WFP) for this path. ProxiFyre applies
its compatibility patch from the WPF UI and does not modify the installed DLL,
its on-disk bytes, or its Authenticode signature.

## Components

| Component | Responsibility |
| --- | --- |
| `uu.exe` | UI, process selection, driver installation, and runtime lifetime management. |
| `local_proxy.dll` | Loads UU policy, selects the accelerated process and proxy endpoint, and configures the UU WFP driver. |
| `uuwfp.sys` | WFP callout driver. Intercepts selected TCP, UDP, and ICMP flows and exchanges packet or connection state with `local_proxy.dll`. |
| `uunetfilter.sys` | Generic NetFilter2/NF3 redirect path used by some UU modes. It does not own the domain whitelist policy. |

The installed UI is a 32-bit process. `local_proxy.dll` is loaded into the UU
process when acceleration starts. The current installation directory names and
the spoofed file version are not reliable identity values: multiple UU builds
can report `local_proxy.dll` version `9.9.9.99`.

## Runtime Data Flow

1. `uu.exe` selects an application and starts the local proxy runtime.
2. `start_local_proxy` loads the UU policy and creates the local policy state.
3. `local_proxy.dll` parses process, domain, IP, port, protocol, and routing
   configuration.
4. Per-flow handling first checks the process ACL. An unrelated process is
   never made eligible by the compatibility patch.
5. After the process ACL accepts the owner, TCP and UDP paths evaluate
   process-domain restrictions, destination rules, ban lists, browser QUIC
   policy, and proxy selection.
6. `local_proxy.dll` writes the selected runtime values to
   `HKLM\SYSTEM\CurrentControlSet\Services\uuwfp\Parameters`.
7. The same module configures `uuwfp.sys` through control IOCTLs:

   | IOCTL | Operation |
   | --- | --- |
   | `0x120004` | Read queued driver packet or ICMP events. |
   | `0x120008` | Set the driver signal event. |
   | `0x12000C` | Set the remote proxy IP and port. |
   | `0x120010` | Set the `svchost` or DoSvc PID used by the driver. |
   | `0x120014` | Read a pending TCP SYN item. |
   | `0x120018` | Set the TCP SYN signal event. |
   | `0x12001C` | Complete or release a TCP SYN item. |

`uuwfp.sys` receives process and endpoint state, but it does not receive or
parse domain names. Domain and destination policy decisions are completed in
`local_proxy.dll` before the driver is configured.

## Policy Variables

The compatibility patch preserves the policy objects and only changes the
return value of the rejection checks. The main values involved are:

| Value | Purpose |
| --- | --- |
| `process_domain_restriction` | Enables or controls the process/domain restriction path. The patched functions return a neutral result for this check. |
| `tcp_whitelists` | TCP acceleration selectors consumed by the local proxy policy. |
| `udp_whitelists` | UDP acceleration selectors consumed by the local proxy policy. |
| `ip_port_hijack` | Destination IP/port routing or rewrite policy used when the flow is selected. |
| `proxy_pid` | PID of the selected local proxy process. |
| `proxy_name` | Executable or process name associated with the selected proxy. |
| `proxy_ip` | Remote proxy address handed to `uuwfp.sys`. |
| `proxy_port` | Remote proxy port handed to `uuwfp.sys`. |
| `u_on` | UU local proxy enable flag written through the service parameters. |
| `i_on` | IP/interface policy enable flag written through the service parameters. |
| `t_s_on` | TCP SYN handling flag written through the service parameters. |

These values remain owned by UU. ProxiFyre does not write them and does not
replace them with fixed values.

## Patched Functions

The patch targets seven `local_proxy.dll` policy functions. The names below are
stable ProxiFyre diagnostic identifiers, not exported DLL symbols. They
describe each target's caller-visible contract:

| Function | Current RVA | Patched return | Caller-visible effect |
| --- | ---: | --- | --- |
| `UuPatch_DisableTcpProcessDomainRestriction` | `0x526C0` | `false`, callee cleanup `8` | The TCP path reports no process-domain restriction. |
| `UuPatch_DisableUdpProcessDomainRestriction` | `0xB2A10` | `false`, callee cleanup `16` | The UDP path reports no process-domain restriction. |
| `UuPatch_TreatEveryDestinationAsProxyAclMatch` | `0x996A0` | `true`, callee cleanup `12` | Every destination that already passed process selection is treated as an ACL match. |
| `UuPatch_DisableTcpDestinationBanList` | `0x9A770` | `false`, callee cleanup `4` | TCP destinations are not rejected by the destination ban list. |
| `UuPatch_DisableUdpGameBanList` | `0x9A870` | `false`, callee cleanup `4` | UDP game destinations are not rejected by the game ban list. |
| `UuPatch_DisableBrowserQuicBlock` | `0x994B0` | `false`, callee cleanup `12` | Browser QUIC traffic is not blocked by this policy check. |
| `UuPatch_DisableUdpDestinationPortBlockRules` | `0x9DC80` | `false`, callee cleanup `4` | UDP destination and port block rules do not reject the flow. |

The replacement bytes are:

| Function | Original prefix | Replacement |
| --- | --- | --- |
| TCP process-domain restriction | `55 8B EC 6A FF` | `32 C0 C2 08 00` |
| UDP process-domain restriction | `55 8B EC 6A FF` | `32 C0 C2 10 00` |
| Proxy ACL destination match | `55 8B EC 6A FF` | `B0 01 C2 0C 00` |
| TCP destination ban list | `55 8B EC 83 EC` | `32 C0 C2 04 00` |
| UDP game ban list | `55 8B EC 83 EC` | `32 C0 C2 04 00` |
| Browser QUIC block | `55 8B EC 6A FF` | `32 C0 C2 0C 00` |
| UDP destination/port block rules | `55 8B EC 83 EC` | `32 C0 C2 04 00` |

The stubs use the target function's own return convention:

- `32 C0` is `xor al, al`, returning `false`.
- `B0 01` is `mov al, 1`, returning `true`.
- `C2 imm16` is a callee-cleaned return with the original argument width.

Every replacement is exactly five bytes long and replaces only the original
five-byte prefix. The rest of the function remains in memory but is never
reached.

## Patch Profile

Patch profiles are stored in `src/Shared/UuPatchProfiles.json`. The maintained
profile is `uu-5247`; its label records UU `6.18.3` and local proxy version
`9.9.9.99`. The signature family is also compatible with the `5248` function
bodies, which resolve to the same seven target RVAs.

Each profile contains:

| Field | Meaning |
| --- | --- |
| `key` | Stable profile identifier used in diagnostics and by the offline patch script. |
| `label` | Human-readable build description. |
| `version` | Metadata only. It is not used to decide compatibility. |
| `sha256` | Exact hash of the original supported `local_proxy.dll`. |
| `patchedSha256` | Exact hash of the matching offline-patched DLL. |
| `targets` | Ordered list of functions changed by this profile. |

Each target contains:

| Field | Meaning |
| --- | --- |
| `name` | Diagnostic name describing the policy check. |
| `rva` | Fixed offset used only when the source hash exactly matches the profile. |
| `signature` | Unique executable-code pattern with `??` wildcards for relocation-sensitive bytes. |
| `signatureOffset` | Offset from the signature match to the first patched byte. Current targets use `0`. |
| `original` | Expected bytes before applying the patch. |
| `patched` | Replacement bytes written at the same address. |

The current signatures wildcard absolute addresses and relative call targets.
This lets the same target functions be found after unrelated DLL layout changes
without guessing addresses.

## Function Resolution

The resolver reads the PE image and scans only executable sections.

1. Compute the SHA256 of `local_proxy.dll`.
2. If the hash exactly matches `sha256` or `patchedSha256`, select that profile.
   The signature is resolved first, and the stored RVA is available as a
   fallback for that exact image.
3. If the hash is unknown, test each complete profile without RVA fallback.
   Every target signature must match exactly once in an executable section.
4. Reject multiple matching profiles.
5. Validate that each resolved address contains either the known original or
   known patched bytes.
6. Reject the complete profile before writing if any target is missing,
   ambiguous, outside the image, or has unexpected bytes.

The live address is calculated as:

```text
module base address + resolved RVA
```

`fileVersion`, product version, installation directory, and the profile label
are not used as compatibility proof.

## Runtime Write Procedure

`UuRuntimePatcher` implements the memory patch:

1. Enumerate UU processes under the UU installation roots or with a matching
   `uu`/`uu_*` process name.
2. Find the loaded `local_proxy.dll` and read its loaded module path and base
   address.
3. Resolve and validate the complete profile against the on-disk PE image.
4. Read the live target bytes and classify each function as original or
   patched.
5. For `Apply`, suspend the target process and revalidate every target before
   changing any bytes.
6. Change the target page protection to `PAGE_EXECUTE_READWRITE`.
7. Write each replacement through `WriteProcessMemory`.
8. Flush the instruction cache with `FlushInstructionCache`.
9. Restore the previous page protection.
10. Resume the process. If a write fails, roll back the writes completed in
    that operation.

`Restore` uses the same procedure in reverse, replacing known patched bytes
with the stored original bytes. The installed DLL is never opened for writing.

## UI Monitoring

The Settings tab exposes the UU runtime patch through
`enableUuWhitelistPatch` in `app-config.json`.

- The UI reports whether `local_proxy.dll` is original, partially patched, or
  fully patched.
- Turning the switch on applies the patch after confirmation.
- Turning the switch off restores the original bytes in the live process.
- While enabled, ProxiFyre checks UU every three seconds and reapplies the
  patch after UU restarts or reloads `local_proxy.dll`.
- If UU is elevated and ProxiFyre is not, enabling the switch requests `runas`
  elevation before inspecting or changing UU memory.
- A normal UI shutdown restores the patch if that UI session applied it.

The same Settings tab exposes the `detailed` logging switch. It defaults to
off and is applied to the running relay without restarting it.

## Offline Patch Script

`scripts/patch-uu-whitelist.ps1` can create or install an on-disk patched copy
for diagnostics. It uses the same profile, exact-hash path, and dynamic
signature resolution as the runtime patcher.

The normal WPF runtime path does not use the offline script and does not
replace the installed DLL.

## Limitations

- A compatible build must preserve all seven target signatures and known
  original or patched bytes.
- A changed function body requires a new or updated profile.
- A signature must match exactly once in the executable sections.
- Process ACL validation remains mandatory.
- Localhost, private, broadcast, multicast, unsupported protocol, unavailable
  proxy line, and region/health fallback paths are outside this patch.
- Runtime patching requires access to the UU process. Protected processes or an
  elevated UU instance can require ProxiFyre to run elevated as well.
- Restarting UU discards the patch from memory. The installed DLL remains
  unchanged.
