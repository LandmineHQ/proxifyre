namespace TrafficTest;

internal static class TestHelp
{
    public static bool TryRun(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (args.Length == 0)
        {
            return false;
        }

        if (!IsHelp(args[0]))
        {
            return false;
        }

        var topic = args.Length > 1 ? args[1] : string.Empty;
        Print(topic);
        return true;
    }

    public static void Print(string? topic = null)
    {
        switch (topic?.Trim().ToLowerInvariant())
        {
            case "curl":
                PrintCurl();
                break;
            case "stun":
                PrintStun();
                break;
            case "license":
                PrintLicense();
                break;
            case "":
            case null:
                PrintOverview();
                break;
            default:
                Console.Error.WriteLine($"Unknown help topic '{topic}'.");
                Console.WriteLine();
                PrintOverview();
                break;
        }
    }

    private static void PrintOverview()
    {
        Console.WriteLine("TrafficTest usage:");
        Console.WriteLine("  proxifyre.ps1 test [mode] [-Detailed] [-- <test args>]");
        Console.WriteLine("  proxifyre.ps1 test help [curl|stun|license]");
        Console.WriteLine();
        Console.WriteLine("Modes:");
        Console.WriteLine("  curl-ipv4             HTTPS curl over IPv4");
        Console.WriteLine("  curl-ipv6             HTTPS curl over IPv6");
        Console.WriteLine("  curl-http-ipv4        HTTP curl over IPv4");
        Console.WriteLine("  curl-large-ipv4       Large HTTPS download over IPv4");
        Console.WriteLine("  curl-large-ipv6       Large HTTPS download over IPv6");
        Console.WriteLine("  stun-ipv4             Single UDP STUN relay test over IPv4");
        Console.WriteLine("  stun-ipv6             Single UDP STUN relay test over IPv6");
        Console.WriteLine("  stun-bench-ipv4       Direct vs relay STUN latency benchmark over IPv4");
        Console.WriteLine("  stun-bench-ipv6       Direct vs relay STUN latency benchmark over IPv6");
        Console.WriteLine("  stun-scan-ipv4        Direct STUN server scan over IPv4");
        Console.WriteLine("  stun-scan-ipv6        Direct STUN server scan over IPv6");
        Console.WriteLine("  stun-relay-scan-ipv4  Relay STUN server scan over IPv4");
        Console.WriteLine("  stun-relay-scan-ipv6  Relay STUN server scan over IPv6");
        Console.WriteLine("  license-device        Print this machine device ID and license key");
        Console.WriteLine("  license-key           Print license key for a supplied device ID");
        Console.WriteLine();
        Console.WriteLine("Common option:");
        Console.WriteLine("  --detailed, --verbose Echo core packet logs and include detailed summaries.");
        Console.WriteLine();
        Console.WriteLine("More help:");
        Console.WriteLine("  proxifyre.ps1 test help curl");
        Console.WriteLine("  proxifyre.ps1 test help stun");
        Console.WriteLine("  proxifyre.ps1 test help license");
    }

    private static void PrintCurl()
    {
        Console.WriteLine("Curl test modes:");
        Console.WriteLine("  curl-ipv4 | curl-ipv6 | curl-http-ipv4 | curl-large-ipv4 | curl-large-ipv6");
        Console.WriteLine();
        Console.WriteLine("Curl-only args:");
        Console.WriteLine("  --curl-url <url>       Override the mode's default target URL.");
        Console.WriteLine("  --curl-option <arg>    Append one curl argument; can be repeated.");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  proxifyre.ps1 test curl-ipv4 -Detailed -- --curl-url https://steamcommunity.com/app/3658790/workshop/");
        Console.WriteLine("  proxifyre.ps1 test curl-ipv4 -- --curl-option --insecure --curl-url https://example.com/");
    }

    private static void PrintStun()
    {
        Console.WriteLine("STUN test modes:");
        Console.WriteLine("  stun-ipv4 | stun-ipv6");
        Console.WriteLine("  stun-bench-ipv4 | stun-bench-ipv6");
        Console.WriteLine("  stun-scan-ipv4 | stun-scan-ipv6");
        Console.WriteLine("  stun-relay-scan-ipv4 | stun-relay-scan-ipv6");
        Console.WriteLine();
        Console.WriteLine("STUN target args:");
        Console.WriteLine("  --stun-host <host>           Override host for stun-ipv4/stun-ipv6/stun-bench-*.");
        Console.WriteLine("  --stun-port <port>           Override port; use together with --stun-host.");
        Console.WriteLine("  --stun <host:port>           Add a scan candidate; can be repeated.");
        Console.WriteLine();
        Console.WriteLine("STUN timing args:");
        Console.WriteLine("  --samples <count>            Sample count for stun-bench-*.");
        Console.WriteLine("  --preflight-samples <count>  Probe count for preflight and scan modes.");
        Console.WriteLine("  --interval-ms <ms>           Delay between STUN samples.");
        Console.WriteLine("  --timeout-ms <ms>            Timeout for each STUN request.");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  proxifyre.ps1 test stun-ipv4 -- --stun-host stun.cloudflare.com --stun-port 3478");
        Console.WriteLine("  proxifyre.ps1 test stun-bench-ipv4 -- --samples 10 --timeout-ms 2000");
        Console.WriteLine("  proxifyre.ps1 test stun-scan-ipv4 -- --stun stun.cloudflare.com:3478 --stun stun.nextcloud.com:443");
    }

    private static void PrintLicense()
    {
        Console.WriteLine("License helper modes:");
        Console.WriteLine("  license-device");
        Console.WriteLine("  license-key <device-id>");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  proxifyre.ps1 test license-device");
        Console.WriteLine("  proxifyre.ps1 test license-key 0123456789abcdef");
    }

    private static bool IsHelp(string value)
    {
        return value.Equals("help", StringComparison.OrdinalIgnoreCase)
            || value.Equals("--help", StringComparison.OrdinalIgnoreCase)
            || value.Equals("-h", StringComparison.OrdinalIgnoreCase)
            || value.Equals("/?", StringComparison.OrdinalIgnoreCase);
    }
}
