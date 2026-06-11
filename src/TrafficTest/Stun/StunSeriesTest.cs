using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace TrafficTest;

internal static class StunSeriesTest
{
    public static async Task<int> RunChildAsync(TestOptions options, CancellationToken cancellationToken)
    {
        var childEndPoint = await StunClient.ResolveEndPointAsync(options.StunHost, options.StunPort, options.StunAddressFamily, cancellationToken);
        var childProbe = await RunProbeAsync("direct child preflight", options, childEndPoint, cancellationToken);
        if (!childProbe.Success)
        {
            Console.WriteLine($"Skipping STUN series because child preflight failed: {childProbe.Error}");
            return 1;
        }

        var childSeries = await RunAsync("direct child", options, childEndPoint, cancellationToken);
        Console.WriteLine(childSeries.ToMachineLine());
        return childSeries.HasSamples ? 0 : 1;
    }

    public static async Task<StunSeriesResult> RunNamedDirectAsync(
        string directAlias,
        TestOptions options,
        CancellationToken cancellationToken)
    {
        var args = BuildChildSeriesArguments(options);
        Console.WriteLine($"Direct baseline process: {Path.GetFileName(directAlias)}");
        Console.WriteLine($"Running named direct baseline: {directAlias} {args}");
        using var child = ProcessRunner.Start(directAlias, args, Path.GetDirectoryName(directAlias)!, redirect: true);

        var outputLines = new List<string>();
        var stdoutTask = ProcessRunner.CaptureChildLinesAsync(child.StandardOutput, outputLines, echoPrefix: "direct>");
        var stderrTask = ProcessRunner.CaptureChildLinesAsync(child.StandardError, outputLines, echoPrefix: "direct!");
        await child.WaitForExitAsync(cancellationToken);
        await Task.WhenAll(stdoutTask, stderrTask);

        if (child.ExitCode != 0)
        {
            Console.WriteLine($"Named direct baseline failed with exit code {child.ExitCode}.");
            return StunSeriesResult.Create("direct baseline", [], 1);
        }

        var machineLine = outputLines.LastOrDefault(line => line.StartsWith("STUN_SERIES_RESULT ", StringComparison.Ordinal));
        if (machineLine is null || !StunSeriesResult.TryParseMachineLine("direct baseline", machineLine, out var result))
        {
            Console.WriteLine("Named direct baseline did not emit a parseable STUN_SERIES_RESULT line.");
            return StunSeriesResult.Create("direct baseline", [], 1);
        }

        Console.WriteLine($"  direct baseline parsed: {result}");
        return result;
    }

    public static async Task<StunProbeResult> RunProbeAsync(
        string label,
        TestOptions options,
        IPEndPoint stunEndPoint,
        CancellationToken cancellationToken)
    {
        Console.WriteLine($"STUN preflight: {label}");
        Console.WriteLine($"STUN target: {stunEndPoint}");

        string? lastError = null;
        for (var i = 0; i < options.StunPreflightSamples; i++)
        {
            var started = Stopwatch.GetTimestamp();
            var response = await StunClient.SendBindingRequestAsync(stunEndPoint, options.StunAddressFamily, options.StunTimeoutMilliseconds, cancellationToken);
            var elapsed = Stopwatch.GetElapsedTime(started);
            if (response.Success)
            {
                Console.WriteLine($"  preflight #{i + 1}: success {elapsed.TotalMilliseconds:F2} ms mapped={response.MappedEndPoint}");
                return new StunProbeResult(true, null);
            }

            lastError = response.Error;
            Console.WriteLine($"  preflight #{i + 1}: failed {response.Error}");
            if (i + 1 < options.StunPreflightSamples)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(options.StunIntervalMilliseconds), cancellationToken);
            }
        }

        return new StunProbeResult(false, lastError);
    }

    public static async Task<StunSeriesResult> RunAsync(
        string label,
        TestOptions options,
        IPEndPoint stunEndPoint,
        CancellationToken cancellationToken)
    {
        var appPattern = ProcessIdentity.GetCurrentExecutableName();
        Console.WriteLine($"STUN latency series: {label}");
        Console.WriteLine($"Configured app patterns: {appPattern}");
        Console.WriteLine($"STUN target: {stunEndPoint}");

        var samples = new List<double>(options.StunSamples);
        var failures = 0;
        for (var i = 0; i < options.StunSamples; i++)
        {
            var started = Stopwatch.GetTimestamp();
            var response = await StunClient.SendBindingRequestAsync(stunEndPoint, options.StunAddressFamily, options.StunTimeoutMilliseconds, cancellationToken);
            var elapsed = Stopwatch.GetElapsedTime(started);
            if (response.Success)
            {
                samples.Add(elapsed.TotalMilliseconds);
                Console.WriteLine($"  #{i + 1:00}: {elapsed.TotalMilliseconds,7:F2} ms mapped={response.MappedEndPoint} bytes={response.ResponseBytes}");
            }
            else
            {
                failures++;
                Console.WriteLine($"  #{i + 1:00}: failed {response.Error}");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(options.StunIntervalMilliseconds), cancellationToken);
        }

        var result = StunSeriesResult.Create(label, samples, failures);
        Console.WriteLine($"  {result}");
        return result;
    }

    public static void PrintBenchmarkSummary(StunSeriesResult direct, StunSeriesResult relay)
    {
        Console.WriteLine("stun latency comparison:");
        Console.WriteLine($"  direct: {direct}");
        Console.WriteLine($"  relay : {relay}");
        if (direct.HasSamples && relay.HasSamples)
        {
            Console.WriteLine($"  delta : avg={relay.AverageMs - direct.AverageMs:F2} ms p95={relay.P95Ms - direct.P95Ms:F2} ms");
        }
    }

    private static string BuildChildSeriesArguments(TestOptions options)
    {
        var arguments = new List<string>
        {
            options.StunAddressFamily == AddressFamily.InterNetwork ? "stun-series-ipv4" : "stun-series-ipv6",
            "--stun-host",
            options.StunHost,
            "--stun-port",
            options.StunPort.ToString(CultureInfo.InvariantCulture),
            "--samples",
            options.StunSamples.ToString(CultureInfo.InvariantCulture),
            "--preflight-samples",
            options.StunPreflightSamples.ToString(CultureInfo.InvariantCulture),
            "--interval-ms",
            options.StunIntervalMilliseconds.ToString(CultureInfo.InvariantCulture),
            "--timeout-ms",
            options.StunTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture)
        };

        if (options.Detailed)
        {
            arguments.Add("--detailed");
        }

        return string.Join(" ", arguments.Select(ProcessRunner.QuoteArgument));
    }
}
