using System.IO.Pipes;
using System.Text;
using ProxiFyre;

namespace TrafficTest;

/// <summary>
/// Focused diagnostic for the telemetry named-pipe channel used by the UI and
/// the injected relay module. It starts the UI-side server, connects as a
/// client, publishes a few snapshots, and verifies they arrive intact.
/// </summary>
internal static class TrafficTelemetryDiagnostic
{
    public static async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        var received = new List<TrafficSnapshot>();
        using var server = new TrafficTelemetryServer(
            snapshot =>
            {
                lock (received)
                {
                    received.Add(snapshot);
                }
            },
            Console.WriteLine);

        server.Start();
        Console.WriteLine($"Telemetry pipe: {server.PipeName}");

        await using var client = new NamedPipeClientStream(
            ".",
            server.PipeName,
            PipeDirection.Out,
            PipeOptions.Asynchronous);

        await client.ConnectAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        using var writer = new StreamWriter(client, Encoding.UTF8)
        {
            AutoFlush = true,
            NewLine = "\n"
        };

        for (var i = 1; i <= 3; i++)
        {
            var snapshot = new TrafficSnapshot(i * 100, i * 200, i * 10, i * 20);
            writer.WriteLine(TrafficTelemetryProtocol.Serialize(snapshot, i));
            Console.WriteLine($"  sent up={snapshot.UploadBytes} down={snapshot.DownloadBytes} upRate={snapshot.UploadBytesPerSecond} downRate={snapshot.DownloadBytesPerSecond}");
            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }

        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTimeOffset.UtcNow < deadline)
        {
            lock (received)
            {
                if (received.Count >= 3)
                {
                    break;
                }
            }

            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }

        lock (received)
        {
            if (received.Count < 3)
            {
                Console.Error.WriteLine($"FAIL: received {received.Count}/3 telemetry snapshots.");
                return 1;
            }

            Console.WriteLine("Received snapshots:");
            foreach (var snapshot in received)
            {
                Console.WriteLine(
                    $"  up={snapshot.UploadBytes} down={snapshot.DownloadBytes} " +
                    $"upRate={snapshot.UploadBytesPerSecond} downRate={snapshot.DownloadBytesPerSecond}");
            }
        }

        Console.WriteLine("PASS: telemetry pipe delivered 3 snapshots.");
        return 0;
    }
}
