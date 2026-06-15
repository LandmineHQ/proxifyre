# ProxiFyre

ProxiFyre is now a C#/.NET 10 WPF application with the UI and relay core in `src/ProxiFyre`. The old C++/CLI, native `socksify`, `netlib`, and service-oriented project structure has been removed from the runnable codebase.

The current implementation is direct mode only:

- Add applications by executable name, full executable path, or install directory.
- Intercept matching traffic with WinpkFilter.
- Forward selected traffic from the relay module to the original destination.
- Inject responses back to the selected application without opening local TCP or UDP listener ports.
- Configure the AOT module target process name through `coreProcessName`. The default is `steamwebhelper.exe`.

Implemented protocols:

- IPv4 TCP direct relay.
- IPv4 UDP direct relay.
- IPv6 TCP direct relay.
- IPv6 UDP direct relay.

Proxy mode and Windows service mode are intentionally not implemented yet.

## Requirements

- Windows.
- .NET 10 SDK or runtime.
- Visual Studio Build Tools with C++ desktop build tools, because the relay module is published as a NativeAOT DLL.
- WinpkFilter installed and running.
- Administrator privileges, because the app opens the WinpkFilter driver and configures adapter tunnel mode.

No `ndisapi.dll` is required. The app installs/checks the WinpkFilter 3.6.2.1 MSI for the kernel driver and talks to the `NDISRD` device directly from C#.

## Layout

```text
.
├── ProxiFyre.sln
├── Directory.Build.props
├── global.json
├── README.md
├── LICENSE
├── artifacts/
│   ├── bin/
│   └── obj/
├── scripts/
│   └── proxifyre.ps1
└── src/
    ├── ProxiFyre/
        ├── Configuration/
        ├── Native/
        ├── Network/
        ├── PacketFiltering/
        ├── Process/
        ├── Relay/
        └── UI/
    ├── ProxiFyre.Module/
        └── ModuleExports.cs
    ├── TrafficTest/
        ├── Curl/
        ├── Diagnostics/
        ├── Stun/
        └── Program.cs
    └── Shared/
        ├── LicenseKey.cs
        └── ModuleMessageProtocol.cs
```

## Build

```powershell
.\scripts\proxifyre.ps1 build
```

or:

```powershell
dotnet build
```

## UI

Run without arguments to open the WPF UI:

```powershell
.\scripts\proxifyre.ps1 ui
```

The UI stores its app list in `app-config.json` next to the built executable. Add an executable name such as `chrome.exe`, browse to a full executable path, or browse to a directory, then load the module from the window.

The UI builds and loads `ProxiFyre.Module.dll` as a NativeAOT DLL. It selects the target process by `coreProcessName`; if several processes have the same name, the lowest PID is used. After the AOT DLL is loaded, it remains in the target process until that process exits. The UI sends run, stop, and reload commands through Windows messages.

## CLI

Run the relay from an elevated terminal:

```powershell
.\scripts\proxifyre.ps1 run -Config .\app-config.json
```

Generate a sample config:

```powershell
.\scripts\proxifyre.ps1 init-config -Config .\app-config.json
```

Add one application:

```powershell
.\scripts\proxifyre.ps1 add-app chrome.exe -Config .\app-config.json
```

Print this machine's device ID and license key:

```powershell
.\scripts\proxifyre.ps1 license-device
```

Print a license key for a supplied device ID:

```powershell
.\scripts\proxifyre.ps1 license-key <device-id>
```

## Focused tests

Run a TCP relay diagnostic with curl:

```powershell
.\scripts\proxifyre.ps1 test tcp
.\scripts\proxifyre.ps1 test tcp -Detailed -- --url https://steamcommunity.com/
```

Run a UDP relay diagnostic with STUN:

```powershell
.\scripts\proxifyre.ps1 test udp
.\scripts\proxifyre.ps1 test udp -Detailed -- --stun-host stun.cloudflare.com --stun-port 3478
```

The TCP and UDP tests start a minimal WPF test host, copy it as `steamwebhelper.exe`, and inject `ProxiFyre.Module.dll` into that exact PID. The test loader does not choose a real Steam WebHelper process even if Steam is running.

Inspect UU or Steam process ports and connections:

```powershell
.\scripts\proxifyre.ps1 test uu
.\scripts\proxifyre.ps1 test steam
```

Normal relay runs keep logs compact and only record when a configured application starts a TCP or UDP connection. Use `-Detailed` on the script, or `--detailed` on the executable, when packet-level relay diagnostics are needed.

## Configuration

Minimal shape:

```json
{
  "coreProcessName": "steamwebhelper.exe",
  "apps": [
    "chrome.exe",
    "C:\\Program Files\\SomeApp\\SomeApp.exe",
    "C:\\Games\\SomeGame\\"
  ]
}
```

The `proxifyre-ui` style is also accepted for easier migration:

```json
{
  "proxies": [
    {
      "appNames": ["firefox.exe"],
      "supportedProtocols": ["TCP", "UDP"]
    }
  ]
}
```

Only `appNames` are used from `proxies` entries. Proxy endpoint, authentication, and protocol fields are ignored by this direct-only build.

The WPF executable is built as a Windows app, so launching the UI does not open a separate console window. When loaded from the UI, the NativeAOT module is injected into the process named by `coreProcessName`, which defaults to `steamwebhelper.exe`.

Matching rules:

- A pattern without `/` or `\` matches the process executable name, case-insensitively.
- A full `.exe` path matches that executable path, case-insensitively.
- A directory path with a trailing slash, or an existing directory path, matches processes under that directory by path prefix.
- Other patterns containing `/` or `\` keep the legacy path-substring behavior.
- The loaded module excludes its host process traffic to avoid relay loops.

## Notes

- IPv6 extension headers are parsed for hop-by-hop, routing, and destination options. Fragmented packets are passed through.
- TCP ownership is resolved from the Windows TCP owner table. A brand-new connection may pass through normally if Windows has not published ownership for the first packet yet.
- UDP ownership is resolved from the Windows UDP owner table by local endpoint, with wildcard-bind fallback.
- The relay module does not open local TCP or UDP listener ports. It still creates outbound sockets to the original destination, so firewall prompts should be limited to normal outbound network access.
