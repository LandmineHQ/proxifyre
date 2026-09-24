# ProxiFyre

ProxiFyre is a Windows-only .NET 10 WPF direct traffic relay for selected
applications. It identifies outbound IPv4/IPv6 TCP and UDP traffic by process,
relays matching traffic through an injected NativeAOT module, and injects
responses back to the application without opening local listening ports.

## UU Accelerator Patch

The UI provides optional runtime compatibility patching for UU's
`local_proxy.dll` policy checks. The patch changes only the loaded process
image, preserves UU process matching and the installed DLL signature, and uses
validated function signatures to support compatible UU builds.

- [English implementation reference](docs/UU_ACCELERATOR.md)
- [简体中文实现说明](docs/UU_ACCELERATOR.zh-CN.md)

The repository architecture map is in `REPO_MAP.md`.

## Build

### Requirements

- Windows 10 or Windows 11, x64.
- .NET 10 SDK.
- Visual Studio Build Tools with the C++ desktop workload for NativeAOT.
- PowerShell.
- Administrator privileges for the signed WinDivert driver.

### Commands

From the repository root, build Debug:

```powershell
.\scripts\proxifyre.ps1 build
```

Build and package Release:

```powershell
.\scripts\proxifyre.ps1 build -Configuration Release
.\scripts\proxifyre.ps1 package -Configuration Release
```

The wrapper publishes the NativeAOT module, probe, and test host, then builds
the managed solution. Main outputs are written to:

- `artifacts/bin/ProxiFyre/<debug|release>_win-x64/`
- `artifacts/native/<Debug|Release>/`
- `release/proxifyre-win-x64.zip`
