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
    int StunSamples = 20,
    int StunPreflightSamples = 3,
    int StunIntervalMilliseconds = 100,
    int StunTimeoutMilliseconds = 1500,
    string? CurlUrl = null,
    string[]? CurlOptions = null,
    string[]? StunCandidates = null)
{
    public bool RequiresStunEndPoint => Kind is TestKind.Stun or TestKind.StunBenchmark;

    public static TestOptions Parse(string[] args)
    {
        var mode = "curl-ipv4";
        var detailed = false;
        string? stunHost = null;
        int? stunPort = null;
        int? samples = null;
        int? preflightSamples = null;
        int? intervalMilliseconds = null;
        int? timeoutMilliseconds = null;
        string? curlUrl = null;
        var curlOptions = new List<string>();
        var stunCandidates = new List<string>();

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (string.Equals(arg, "--verbose", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "--detailed", StringComparison.OrdinalIgnoreCase))
            {
                detailed = true;
                continue;
            }

            if (TryReadOptionValue(args, ref i, arg, "--stun-host", out var hostValue))
            {
                stunHost = hostValue;
                continue;
            }

            if (TryReadOptionValue(args, ref i, arg, "--curl-url", out var curlUrlValue))
            {
                curlUrl = curlUrlValue;
                continue;
            }

            if (TryReadOptionValue(args, ref i, arg, "--curl-option", out var curlOptionValue))
            {
                curlOptions.Add(curlOptionValue);
                continue;
            }

            if (TryReadOptionValue(args, ref i, arg, "--stun-port", out var portValue))
            {
                stunPort = ParsePositiveInt("--stun-port", portValue);
                continue;
            }

            if (TryReadOptionValue(args, ref i, arg, "--samples", out var samplesValue))
            {
                samples = ParsePositiveInt("--samples", samplesValue);
                continue;
            }

            if (TryReadOptionValue(args, ref i, arg, "--preflight-samples", out var preflightSamplesValue))
            {
                preflightSamples = ParsePositiveInt("--preflight-samples", preflightSamplesValue);
                continue;
            }

            if (TryReadOptionValue(args, ref i, arg, "--interval-ms", out var intervalValue))
            {
                intervalMilliseconds = ParseNonNegativeInt("--interval-ms", intervalValue);
                continue;
            }

            if (TryReadOptionValue(args, ref i, arg, "--timeout-ms", out var timeoutValue))
            {
                timeoutMilliseconds = ParsePositiveInt("--timeout-ms", timeoutValue);
                continue;
            }

            if (TryReadOptionValue(args, ref i, arg, "--stun", out var stunValue))
            {
                stunCandidates.Add(stunValue);
                if (TryParseStunTarget(stunValue, out var parsedHost, out var parsedPort))
                {
                    stunHost ??= parsedHost;
                    stunPort ??= parsedPort;
                }

                continue;
            }

            if (arg.StartsWith("-", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unknown option '{arg}'.");
            }

            if (!arg.StartsWith("-", StringComparison.Ordinal))
            {
                mode = arg;
            }
        }

        var common = "--http1.1 --noproxy \"*\" --proxy \"\" --connect-timeout 8 --max-time 20 -L -sS -o NUL -w \"status=%{http_code} bytes=%{size_download} remote=%{remote_ip} time=%{time_total}\\n\"";
        var largeCommon = "--http1.1 --noproxy \"*\" --proxy \"\" --connect-timeout 8 --max-time 90 --limit-rate 1M -L -sS -o NUL -w \"status=%{http_code} bytes=%{size_download} remote=%{remote_ip} time=%{time_total}\\n\"";
        var normalizedMode = mode.ToLowerInvariant();
        var curlOptionText = curlOptions.Count == 0
            ? string.Empty
            : " " + string.Join(" ", curlOptions.Select(QuoteArgument));
        var defaults = normalizedMode switch
        {
            "curl-ipv4" => new TestOptions(mode, TestKind.Curl, $"--ipv4 {common}{curlOptionText} {QuoteArgument(curlUrl ?? "https://www.bing.com/")}", detailed, string.Empty, 0, AddressFamily.Unspecified),
            "curl-ipv6" => new TestOptions(mode, TestKind.Curl, $"--ipv6 {common}{curlOptionText} {QuoteArgument(curlUrl ?? "https://ipv6.test-ipv6.com/")}", detailed, string.Empty, 0, AddressFamily.Unspecified),
            "curl-http-ipv4" => new TestOptions(mode, TestKind.Curl, $"--ipv4 {common}{curlOptionText} {QuoteArgument(curlUrl ?? "http://www.bing.com/")}", detailed, string.Empty, 0, AddressFamily.Unspecified),
            "curl-large-ipv4" => new TestOptions(mode, TestKind.Curl, $"--ipv4 {largeCommon}{curlOptionText} {QuoteArgument(curlUrl ?? "https://speed.cloudflare.com/__down?bytes=26214400")}", detailed, string.Empty, 0, AddressFamily.Unspecified),
            "curl-large-ipv6" => new TestOptions(mode, TestKind.Curl, $"--ipv6 {largeCommon}{curlOptionText} {QuoteArgument(curlUrl ?? "https://speed.cloudflare.com/__down?bytes=26214400")}", detailed, string.Empty, 0, AddressFamily.Unspecified),
            "stun-ipv4" => new TestOptions(mode, TestKind.Stun, null, detailed, "stun.l.google.com", 19302, AddressFamily.InterNetwork),
            "stun-ipv6" => new TestOptions(mode, TestKind.Stun, null, detailed, "stun.l.google.com", 19302, AddressFamily.InterNetworkV6),
            "stun-bench-ipv4" => new TestOptions(mode, TestKind.StunBenchmark, null, detailed, "stun.l.google.com", 19302, AddressFamily.InterNetwork),
            "stun-bench-ipv6" => new TestOptions(mode, TestKind.StunBenchmark, null, detailed, "stun.l.google.com", 19302, AddressFamily.InterNetworkV6),
            "stun-series-ipv4" => new TestOptions(mode, TestKind.StunSeriesChild, null, detailed, "stun.l.google.com", 19302, AddressFamily.InterNetwork),
            "stun-series-ipv6" => new TestOptions(mode, TestKind.StunSeriesChild, null, detailed, "stun.l.google.com", 19302, AddressFamily.InterNetworkV6),
            "stun-scan-ipv4" => new TestOptions(mode, TestKind.StunScan, null, detailed, string.Empty, 0, AddressFamily.InterNetwork),
            "stun-scan-ipv6" => new TestOptions(mode, TestKind.StunScan, null, detailed, string.Empty, 0, AddressFamily.InterNetworkV6),
            "stun-relay-scan-ipv4" => new TestOptions(mode, TestKind.StunRelayScan, null, detailed, string.Empty, 0, AddressFamily.InterNetwork),
            "stun-relay-scan-ipv6" => new TestOptions(mode, TestKind.StunRelayScan, null, detailed, string.Empty, 0, AddressFamily.InterNetworkV6),
            _ => throw new ArgumentException($"Unknown test mode '{mode}'. Supported modes: curl-ipv4, curl-ipv6, curl-http-ipv4, curl-large-ipv4, curl-large-ipv6, stun-ipv4, stun-ipv6, stun-bench-ipv4, stun-bench-ipv6, stun-scan-ipv4, stun-scan-ipv6, stun-relay-scan-ipv4, stun-relay-scan-ipv6.")
        };

        if (defaults.RequiresStunEndPoint && string.IsNullOrWhiteSpace(stunHost) != !stunPort.HasValue)
        {
            throw new ArgumentException("--stun-host and --stun-port must be supplied together.");
        }

        return defaults with
        {
            StunHost = stunHost ?? defaults.StunHost,
            StunPort = stunPort ?? defaults.StunPort,
            StunSamples = samples ?? defaults.StunSamples,
            StunPreflightSamples = preflightSamples ?? defaults.StunPreflightSamples,
            StunIntervalMilliseconds = intervalMilliseconds ?? defaults.StunIntervalMilliseconds,
            StunTimeoutMilliseconds = timeoutMilliseconds ?? defaults.StunTimeoutMilliseconds,
            CurlUrl = curlUrl,
            CurlOptions = curlOptions.ToArray(),
            StunCandidates = stunCandidates.ToArray()
        };
    }

    public static bool TryParseStunTarget(string value, out string host, out int port)
    {
        host = string.Empty;
        port = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        var separator = trimmed.LastIndexOf(':');
        if (separator <= 0 || separator == trimmed.Length - 1)
        {
            return false;
        }

        var hostPart = trimmed[..separator].Trim();
        if (hostPart.StartsWith("[", StringComparison.Ordinal) && hostPart.EndsWith("]", StringComparison.Ordinal))
        {
            hostPart = hostPart[1..^1];
        }

        if (string.IsNullOrWhiteSpace(hostPart)
            || !int.TryParse(trimmed[(separator + 1)..], out var parsedPort)
            || parsedPort <= 0
            || parsedPort > ushort.MaxValue)
        {
            return false;
        }

        host = hostPart;
        port = parsedPort;
        return true;
    }

    private static bool TryReadOptionValue(string[] args, ref int index, string arg, string optionName, out string value)
    {
        value = string.Empty;
        if (arg.Equals(optionName, StringComparison.OrdinalIgnoreCase))
        {
            if (index + 1 >= args.Length)
            {
                throw new ArgumentException($"{optionName} requires a value.");
            }

            value = args[++index];
            return true;
        }

        var prefix = optionName + "=";
        if (arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            value = arg[prefix.Length..];
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException($"{optionName} requires a value.");
            }

            return true;
        }

        return false;
    }

    private static int ParsePositiveInt(string optionName, string value)
    {
        if (!int.TryParse(value, out var parsed) || parsed <= 0)
        {
            throw new ArgumentException($"{optionName} requires a positive integer.");
        }

        return parsed;
    }

    private static int ParseNonNegativeInt(string optionName, string value)
    {
        if (!int.TryParse(value, out var parsed) || parsed < 0)
        {
            throw new ArgumentException($"{optionName} requires a non-negative integer.");
        }

        return parsed;
    }

    private static string QuoteArgument(string argument)
    {
        if (argument.Length == 0)
        {
            return "\"\"";
        }

        return argument.Any(char.IsWhiteSpace) || argument.Contains('"', StringComparison.Ordinal)
            ? "\"" + argument.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\""
            : argument;
    }
}
