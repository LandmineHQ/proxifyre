# ProxiFyre

ProxiFyre is now a C#/.NET 10 WPF application with the UI and relay core in `src/ProxiFyre`. The old C++/CLI, native `socksify`, `netlib`, and service-oriented project structure has been removed from the runnable codebase.

The current implementation is direct mode only:

- Add applications by executable name or full path.
- Intercept matching traffic with WinpkFilter.
- Redirect the selected application's packets into the C# process.
- Re-send the traffic directly from `ProxiFyre.exe` to the original destination.
- Configure the core process name used for self-exclusion. The default is `steamwebhelper.exe`.

Implemented protocols:

- IPv4 TCP direct relay.
- IPv4 UDP direct relay.
- IPv6 TCP direct relay.
- IPv6 UDP direct relay.

Proxy mode and Windows service mode are intentionally not implemented yet.

## Requirements

- Windows.
- .NET 10 SDK or runtime.
- WinpkFilter installed and running.
- `ndisapi.dll` loadable by `ProxiFyre.exe` through the system path or placed next to the executable.
- Administrator privileges, because the app opens the WinpkFilter driver and configures adapter tunnel mode.

No C++ compiler or C++ build tools are required.

## Layout

```text
.
├── ProxiFyre.sln
├── global.json
├── README.md
├── LICENSE
└── src/
    └── ProxiFyre/
        ├── Configuration/
        ├── Native/
        ├── Network/
        ├── PacketFiltering/
        ├── Process/
        ├── Relay/
        └── UI/
```

## Build

```powershell
.\proxifyre.ps1 build
```

or:

```powershell
dotnet build
```

## UI

Run without arguments to open the WPF UI:

```powershell
.\proxifyre.ps1 ui
```

The UI stores its app list in `app-config.json` next to the built executable. Add an executable name such as `chrome.exe`, or browse to a full executable path, then start the direct relay from the window.

## CLI

Run the relay from an elevated terminal:

```powershell
.\proxifyre.ps1 run -Config .\app-config.json
```

Generate a sample config:

```powershell
.\proxifyre.ps1 init-config -Config .\app-config.json
```

Add one application:

```powershell
.\proxifyre.ps1 add-app chrome.exe -Config .\app-config.json
```

## Configuration

Minimal shape:

```json
{
  "coreProcessName": "steamwebhelper.exe",
  "apps": [
    "chrome.exe",
    "C:\\Program Files\\SomeApp\\SomeApp.exe"
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

The WPF executable is built as a Windows app, so launching the UI does not open a separate console window. When started from the UI, the core is copied and launched under `coreProcessName`, which defaults to `steamwebhelper.exe`.

Matching rules:

- A pattern without `/` or `\` matches the process executable name, case-insensitively.
- A pattern with `/` or `\` matches the executable path, case-insensitively.
- `ProxiFyre.exe` excludes its own process traffic to avoid relay loops.

## Notes

- IPv6 extension headers are parsed for hop-by-hop, routing, and destination options. Fragmented packets are passed through.
- TCP ownership is resolved from the Windows TCP owner table. A brand-new connection may pass through normally if Windows has not published ownership for the first packet yet.
- UDP ownership is resolved from the Windows UDP owner table by local endpoint, with wildcard-bind fallback.
- Windows Firewall may require an allow rule for `ProxiFyre.exe`, because redirected traffic is delivered to local TCP and UDP listeners inside the process.
