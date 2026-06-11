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

        var started = Stopwatch.GetTimestamp();
        var response = await StunClient.SendBindingRequestAsync(stunEndPoint, options.StunAddressFamily, options.StunTimeoutMilliseconds, cancellationToken);
        var elapsed = Stopwatch.GetElapsedTime(started);
        if (!response.Success)
        {
            Console.WriteLine($"stun result: failed error={response.Error} time={elapsed.TotalSeconds:F3}s");
            return new TestResult(false, string.Empty, response.Error ?? string.Empty);
        }

        Console.WriteLine($"stun result: success mapped={response.MappedEndPoint} remote={response.RemoteEndPoint} bytes={response.ResponseBytes} time={elapsed.TotalSeconds:F3}s");
        return new TestResult(true, response.MappedEndPoint?.ToString() ?? string.Empty, string.Empty);
    }
}
