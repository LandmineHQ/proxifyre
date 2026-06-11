using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace TrafficTest;

internal static class StunScanTest
{
    public static async Task<int> RunAsync(TestOptions options, CancellationToken cancellationToken)
    {
        Console.WriteLine($"STUN scan mode: {options.Mode}");
        Console.WriteLine($"Address family: {options.StunAddressFamily}");
        Console.WriteLine($"Probe attempts per server: {options.StunPreflightSamples}");
        Console.WriteLine($"Timeout per attempt: {options.StunTimeoutMilliseconds} ms");

        var configuredCandidates = options.StunCandidates ?? [];
        var candidates = configuredCandidates.Length > 0
            ? configuredCandidates
            : GetDefaultCandidates();
        var results = new List<StunScanResult>(candidates.Length);

        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var target = TestOptions.TryParseStunTarget(candidate, out var host, out var port)
                ? $"{host}:{port}"
                : candidate;

            if (string.IsNullOrWhiteSpace(host) || port <= 0)
            {
                Console.WriteLine($"  {target,-36} invalid target");
                results.Add(new StunScanResult(target, false, double.NaN, null, "Invalid STUN target."));
                continue;
            }

            IPEndPoint endPoint;
            try
            {
                endPoint = await StunClient.ResolveEndPointAsync(host, port, options.StunAddressFamily, cancellationToken);
            }
            catch (Exception ex) when (ex is SocketException or InvalidOperationException)
            {
                Console.WriteLine($"  {target,-36} resolve failed: {ex.Message}");
                results.Add(new StunScanResult(target, false, double.NaN, null, ex.Message));
                continue;
            }

            var samples = new List<double>(options.StunPreflightSamples);
            string? lastError = null;
            IPEndPoint? mappedEndPoint = null;
            for (var i = 0; i < options.StunPreflightSamples; i++)
            {
                var started = Stopwatch.GetTimestamp();
                var response = await StunClient.SendBindingRequestAsync(endPoint, options.StunAddressFamily, options.StunTimeoutMilliseconds, cancellationToken);
                var elapsed = Stopwatch.GetElapsedTime(started);
                if (response.Success)
                {
                    samples.Add(elapsed.TotalMilliseconds);
                    mappedEndPoint = response.MappedEndPoint;
                }
                else
                {
                    lastError = response.Error;
                }

                if (i + 1 < options.StunPreflightSamples)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(options.StunIntervalMilliseconds), cancellationToken);
                }
            }

            if (samples.Count > 0)
            {
                var average = samples.Average();
                Console.WriteLine($"  {target,-36} ok avg={average,7:F2} ms mapped={mappedEndPoint}");
                results.Add(new StunScanResult(target, true, average, mappedEndPoint, null));
            }
            else
            {
                Console.WriteLine($"  {target,-36} failed {lastError}");
                results.Add(new StunScanResult(target, false, double.NaN, null, lastError));
            }
        }

        var available = results
            .Where(result => result.Success)
            .OrderBy(result => result.AverageMs)
            .ToArray();
        Console.WriteLine("available STUN servers:");
        foreach (var result in available)
        {
            Console.WriteLine($"  {result.Target} avg={result.AverageMs:F2} ms mapped={result.MappedEndPoint}");
        }

        if (available.Length == 0)
        {
            Console.WriteLine("No available STUN servers found.");
            return 1;
        }

        Console.WriteLine($"fastest: {available[0].Target}");
        return 0;
    }

    private static string[] GetDefaultCandidates()
    {
        return
        [
            "stun.cloudflare.com:3478",
            "stun.nextcloud.com:443",
            "stun.nextcloud.com:3478",
            "stun.syncthing.net:3478",
            "stun.services.mozilla.com:3478",
            "stun.antisip.com:3478",
            "stun.ekiga.net:3478",
            "stun.sipgate.net:3478",
            "stun.sipnet.net:3478",
            "stun.ideasip.com:3478",
            "stun.voipbuster.com:3478",
            "stun.voipstunt.com:3478",
            "stun.voip.aebc.com:3478",
            "stun.counterpath.com:3478",
            "stun.1.google.com:19302",
            "stun.2.google.com:19302",
            "stun.3.google.com:19302",
            "stun.4.google.com:19302",
            "stun.l.google.com:19302"
        ];
    }
}
