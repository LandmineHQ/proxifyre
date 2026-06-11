# ProxiFyre

ProxiFyre is now a C#/.NET 10 WPF application with the UI and relay core in `src/ProxiFyre`. The old C++/CLI, native `socksify`, `netlib`, and service-oriented project structure has been removed from the runnable codebase.

The current implementation is direct mode only:

- Add applications by executable name, full executable path, or install directory.
- Intercept matching traffic with WinpkFilter.
- Forward selected traffic from the C# relay core to the original destination.
- Inject responses back to the selected application without opening local TCP or UDP listener ports.
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
- Administrator privileges, because the app opens the WinpkFilter driver and configures adapter tunnel mode.

No C++ compiler or C++ build tools are required.
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
    └── TrafficTest/
        ├── Curl/
        ├── Infrastructure/
        ├── Models/
        ├── Options/
        ├── Stun/
        └── Program.cs
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

The UI stores its app list in `app-config.json` next to the built executable. Add an executable name such as `chrome.exe`, browse to a full executable path, or browse to a directory, then start the direct relay from the window.

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

## Focused traffic test

Use the isolated curl test when browser traffic is too noisy to diagnose:

```powershell
.\scripts\proxifyre.ps1 test
```

The test starts a temporary `proxifyre-test-core.exe` and writes a narrow config for the current test mode. TCP curl modes only match `curl.exe`, disable curl proxy environment variables, and request a known target. IPv4 curl modes use Bing. The IPv6 curl mode uses `ipv6.test-ipv6.com`, because `www.bing.com` may not return an AAAA record on every resolver. UDP STUN modes only match `TrafficTest.exe` and send a STUN binding request to `stun.l.google.com:19302`.

```powershell
.\scripts\proxifyre.ps1 test curl-ipv4
.\scripts\proxifyre.ps1 test curl-http-ipv4
.\scripts\proxifyre.ps1 test curl-ipv6
.\scripts\proxifyre.ps1 test stun-ipv4
.\scripts\proxifyre.ps1 test stun-ipv6
.\scripts\proxifyre.ps1 test curl-ipv4 -Detailed
```

Normal core runs keep logs compact and only record when a configured application starts a TCP or UDP connection. Use `-Detailed` on the script, or `--detailed` on the executable, when packet-level relay diagnostics are needed.

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

The WPF executable is built as a Windows app, so launching the UI does not open a separate console window. When started from the UI, the core is copied and launched under `coreProcessName`, which defaults to `steamwebhelper.exe`.

Matching rules:

- A pattern without `/` or `\` matches the process executable name, case-insensitively.
- A full `.exe` path matches that executable path, case-insensitively.
- A directory path with a trailing slash, or an existing directory path, matches processes under that directory by path prefix.
- Other patterns containing `/` or `\` keep the legacy path-substring behavior.
- `ProxiFyre.exe` excludes its own process traffic to avoid relay loops.

## Notes

- IPv6 extension headers are parsed for hop-by-hop, routing, and destination options. Fragmented packets are passed through.
- TCP ownership is resolved from the Windows TCP owner table. A brand-new connection may pass through normally if Windows has not published ownership for the first packet yet.
- UDP ownership is resolved from the Windows UDP owner table by local endpoint, with wildcard-bind fallback.
- The relay core does not open local TCP or UDP listener ports. It still creates outbound sockets to the original destination, so firewall prompts should be limited to normal outbound network access.
