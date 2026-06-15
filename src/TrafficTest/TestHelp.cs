namespace TrafficTest;

internal static class TestHelp
{
    public static bool TryRun(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (args.Length == 0)
        {
            Print();
            return true;
        }

        if (!IsHelp(args[0]))
        {
            return false;
        }

        Print(args.Length > 1 ? args[1] : null);
        return true;
    }

    public static void Print(string? topic = null)
    {
        switch (topic?.Trim().ToLowerInvariant())
        {
            case "tcp":
                PrintTcp();
                break;
            case "udp":
                PrintUdp();
                break;
            case "uu":
                PrintProcessDiagnostic("UU", "uu.exe");
                break;
            case "steam":
                PrintProcessDiagnostic("Steam", "steamwebhelper.exe");
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
        Console.WriteLine("  proxifyre.ps1 test <tcp|udp|uu|steam> [-Detailed] [-- <test args>]");
        Console.WriteLine();
        Console.WriteLine("Modes:");
        Console.WriteLine("  tcp    HTTPS curl relay diagnostic");
        Console.WriteLine("  udp    UDP STUN relay diagnostic");
        Console.WriteLine("  uu     UU process ports and connections");
        Console.WriteLine("  steam  Steam WebHelper process ports and connections");
        Console.WriteLine();
        Console.WriteLine("More help:");
        Console.WriteLine("  proxifyre.ps1 test help tcp");
        Console.WriteLine("  proxifyre.ps1 test help udp");
        Console.WriteLine("  proxifyre.ps1 test help uu");
        Console.WriteLine("  proxifyre.ps1 test help steam");
    }

    private static void PrintTcp()
    {
        Console.WriteLine("TCP test:");
        Console.WriteLine("  proxifyre.ps1 test tcp [-Detailed] [-- --url <url> --ipv4|--ipv6]");
        Console.WriteLine("  Starts a WPF test host renamed to steamwebhelper.exe and injects the AOT module into that PID.");
        Console.WriteLine();
        Console.WriteLine("Args:");
        Console.WriteLine("  --url <url>          Target URL. Defaults to https://www.bing.com/.");
        Console.WriteLine("  --ipv4               Force IPv4. Default.");
        Console.WriteLine("  --ipv6               Force IPv6.");
        Console.WriteLine("  --curl-option <arg>  Append one curl argument; can be repeated.");
    }

    private static void PrintUdp()
    {
        Console.WriteLine("UDP test:");
        Console.WriteLine("  proxifyre.ps1 test udp [-Detailed] [-- --stun-host <host> --stun-port <port> --ipv4|--ipv6]");
        Console.WriteLine("  Starts a WPF test host renamed to steamwebhelper.exe and injects the AOT module into that PID.");
        Console.WriteLine();
        Console.WriteLine("Args:");
        Console.WriteLine("  --stun-host <host>   STUN host. Defaults to stun.l.google.com.");
        Console.WriteLine("  --stun-port <port>   STUN port. Defaults to 19302.");
        Console.WriteLine("  --timeout-ms <ms>    STUN response timeout. Defaults to 1500.");
        Console.WriteLine("  --ipv4               Force IPv4. Default.");
        Console.WriteLine("  --ipv6               Force IPv6.");
    }

    private static void PrintProcessDiagnostic(string label, string defaultProcessName)
    {
        Console.WriteLine($"{label} process diagnostic:");
        Console.WriteLine($"  proxifyre.ps1 test {label.ToLowerInvariant()} [-- --process-name <name> --duration-ms <ms> --json]");
        Console.WriteLine();
        Console.WriteLine("Args:");
        Console.WriteLine($"  --process-name <name>  Process name. Defaults to {defaultProcessName}.");
        Console.WriteLine("  --duration-ms <ms>     Sampling duration. Defaults to 1000.");
        Console.WriteLine("  --interval-ms <ms>     Sampling interval. Defaults to 250.");
        Console.WriteLine("  --json                 Print JSON.");
    }

    private static bool IsHelp(string value)
    {
        return value.Equals("help", StringComparison.OrdinalIgnoreCase)
            || value.Equals("--help", StringComparison.OrdinalIgnoreCase)
            || value.Equals("-h", StringComparison.OrdinalIgnoreCase)
            || value.Equals("/?", StringComparison.OrdinalIgnoreCase);
    }
}
