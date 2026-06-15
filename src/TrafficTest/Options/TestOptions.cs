using System.Net.Sockets;

namespace TrafficTest;

internal sealed record TestOptions(
    string Mode,
    TestKind Kind,
    string? CurlArguments,
    bool Detailed,
    string StunHost,
    int StunPort,
    AddressFamily StunAddressFamily,
    int StunTimeoutMilliseconds,
    string? CurlUrl = null,
    string[]? CurlOptions = null)
{
    public static TestOptions Parse(string[] args)
    {
        if (args.Length == 0)
        {
            throw new ArgumentException("test requires a mode: tcp, udp, uu, or steam.");
        }

        var mode = args[0].Trim().ToLowerInvariant();
        return mode switch
        {
            "tcp" => ParseTcp(args.Skip(1).ToArray()),
            "udp" => ParseUdp(args.Skip(1).ToArray()),
            _ => throw new ArgumentException($"Unknown test mode '{args[0]}'. Supported modes: tcp, udp, uu, steam.")
        };
    }

    private static TestOptions ParseTcp(string[] args)
    {
        var detailed = false;
        var useIpv6 = false;
        string? curlUrl = null;
        var curlOptions = new List<string>();

        for (var i = 0; i < args.Length; i++)
        {
            if (IsDetailed(args[i]))
            {
                detailed = true;
                continue;
            }

            if (args[i].Equals("--ipv6", StringComparison.OrdinalIgnoreCase))
            {
                useIpv6 = true;
                continue;
            }

            if (args[i].Equals("--ipv4", StringComparison.OrdinalIgnoreCase))
            {
                useIpv6 = false;
                continue;
            }

            if (CliOptions.TryReadValue(args, ref i, "--url", out var urlValue)
                || CliOptions.TryReadValue(args, ref i, "--curl-url", out urlValue))
            {
                curlUrl = urlValue;
                continue;
            }

            if (CliOptions.TryReadValue(args, ref i, "--curl-option", out var curlOptionValue))
            {
                curlOptions.Add(curlOptionValue);
                continue;
            }

            throw new ArgumentException($"Unknown tcp test option '{args[i]}'.");
        }

        var common = "--http1.1 --noproxy \"*\" --proxy \"\" --connect-timeout 8 --max-time 20 -L -sS -o NUL -w \"status=%{http_code} bytes=%{size_download} remote=%{remote_ip} time=%{time_total}\\n\"";
        var curlOptionText = curlOptions.Count == 0
            ? string.Empty
            : " " + string.Join(" ", curlOptions.Select(ProcessRunner.QuoteArgument));
        var familyArg = useIpv6 ? "--ipv6" : "--ipv4";
        var defaultUrl = useIpv6 ? "https://ipv6.test-ipv6.com/" : "https://www.bing.com/";
        var effectiveUrl = curlUrl ?? defaultUrl;
        return new TestOptions(
            "tcp",
            TestKind.Curl,
            $"{familyArg} {common}{curlOptionText} {ProcessRunner.QuoteArgument(effectiveUrl)}",
            detailed,
            string.Empty,
            0,
            AddressFamily.Unspecified,
            1500,
            effectiveUrl,
            curlOptions.ToArray());
    }

    private static TestOptions ParseUdp(string[] args)
    {
        var detailed = false;
        var addressFamily = AddressFamily.InterNetwork;
        var stunHost = "stun.l.google.com";
        var stunPort = 19302;
        var timeoutMilliseconds = 1500;

        for (var i = 0; i < args.Length; i++)
        {
            if (IsDetailed(args[i]))
            {
                detailed = true;
                continue;
            }

            if (args[i].Equals("--ipv6", StringComparison.OrdinalIgnoreCase))
            {
                addressFamily = AddressFamily.InterNetworkV6;
                continue;
            }

            if (args[i].Equals("--ipv4", StringComparison.OrdinalIgnoreCase))
            {
                addressFamily = AddressFamily.InterNetwork;
                continue;
            }

            if (CliOptions.TryReadValue(args, ref i, "--stun-host", out var hostValue))
            {
                stunHost = hostValue;
                continue;
            }

            if (CliOptions.TryReadValue(args, ref i, "--stun-port", out var portValue))
            {
                stunPort = CliOptions.ParsePositiveInt("--stun-port", portValue);
                continue;
            }

            if (CliOptions.TryReadValue(args, ref i, "--timeout-ms", out var timeoutValue))
            {
                timeoutMilliseconds = CliOptions.ParsePositiveInt("--timeout-ms", timeoutValue);
                continue;
            }

            throw new ArgumentException($"Unknown udp test option '{args[i]}'.");
        }

        return new TestOptions(
            "udp",
            TestKind.Stun,
            null,
            detailed,
            stunHost,
            stunPort,
            addressFamily,
            timeoutMilliseconds);
    }

    private static bool IsDetailed(string value)
    {
        return value.Equals("--detailed", StringComparison.OrdinalIgnoreCase)
            || value.Equals("--verbose", StringComparison.OrdinalIgnoreCase);
    }
}
