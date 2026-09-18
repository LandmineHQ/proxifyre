# ProxiFyre

ProxiFyre is a Windows-only .NET 10 WPF direct traffic relay for selected
applications. It identifies outbound IPv4/IPv6 TCP and UDP traffic by process,
relays matching traffic through an injected NativeAOT module, and injects
responses back to the application without opening local listening ports.

The UI also provides optional runtime compatibility patching for UU's
`local_proxy.dll` whitelist. Architecture and implementation details are in
`REPO_MAP.md` and `docs/UU_ACCELERATOR.md`.

## Build

### Requirements

- Windows 10 or Windows 11, x64.
- .NET 10 SDK.
- Visual Studio Build Tools with the C++ desktop workload for NativeAOT.
- PowerShell.
- WDK only when building the optional WFP driver.

### Commands

From the repository root, build Debug:

```powershell
.\scripts\proxifyre.ps1 build
```

Build Release:

```powershell
.\scripts\proxifyre.ps1 build -Configuration Release
```

The wrapper publishes the NativeAOT module, probe, and test host before
building the managed solution. Main outputs are written to:

- `artifacts/bin/ProxiFyre/<debug|release>_win-x64/`
- `artifacts/native/<Debug|Release>/`
