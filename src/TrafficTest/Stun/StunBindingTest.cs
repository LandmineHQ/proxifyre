using System.Diagnostics;
using System.Net;

namespace TrafficTest;

internal static class StunBindingTest
{
    public static async Task<TestResult> RunAsync(TestOptions options, IPEndPoint stunEndPoint, CancellationToken cancellationToken)
    {
        var appPattern = ProcessIdentity.GetCurrentExecutableName();
        Console.WriteLine($"Test mode: {options.Mode}");
        Console.WriteLine($"Configured app patterns: {appPattern}");
        Console.WriteLine($"Running STUN binding request: {appPattern} -> {stunEndPoint}");

        var samples = new List<double>(options.StunIterations);
        IPEndPoint? mappedEndPoint = null;
        for (var iteration = 1; iteration <= options.StunIterations; iteration++)
        {
            var started = Stopwatch.GetTimestamp();
            var response = await StunClient.SendBindingRequestAsync(
                stunEndPoint,
                options.StunAddressFamily,
                options.StunTimeoutMilliseconds,
                cancellationToken,
                options.Detailed ? Console.WriteLine : null);
            var elapsed = Stopwatch.GetElapsedTime(started);
            if (!response.Success)
            {
                Console.WriteLine(
                    $"stun result[{iteration}/{options.StunIterations}]: failed error={response.Error} time={elapsed.TotalSeconds:F3}s");
                return new TestResult(false, string.Empty, response.Error ?? string.Empty);
            }

            mappedEndPoint = response.MappedEndPoint;
            samples.Add(elapsed.TotalMilliseconds);
            Console.WriteLine(
                $"stun result[{iteration}/{options.StunIterations}]: success mapped={response.MappedEndPoint} remote={response.RemoteEndPoint} bytes={response.ResponseBytes} time={elapsed.TotalSeconds:F3}s");
        }

        Console.WriteLine(
            $"stun summary: samples={samples.Count} avgMs={samples.Average():F2} minMs={samples.Min():F2} maxMs={samples.Max():F2}");
        return new TestResult(true, mappedEndPoint?.ToString() ?? string.Empty, string.Empty);
    }
}
