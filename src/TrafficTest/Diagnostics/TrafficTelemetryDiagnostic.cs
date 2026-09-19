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
        var pipeName = $"ProxiFyre.Telemetry.Test.{Environment.ProcessId}.{Guid.NewGuid():N}";
        using var server = new TrafficTelemetryServer(
            snapshot =>
            {
                lock (received)
                {
                    received.Add(snapshot);
                }
            },
            Console.WriteLine,
            pipeName);

        Console.WriteLine($"Telemetry pipe: {server.PipeName}");
        using (var securityProbe = server.CreateServer())
        {
            if (!TrafficTelemetryServer.HasMediumIntegrityLabel(securityProbe.SafePipeHandle))
            {
                Console.Error.WriteLine(
                    "FAIL: telemetry pipe security descriptor is missing the medium integrity label.");
                return 1;
            }

            if (!TrafficTelemetryServer.HasCurrentUserFullControl(securityProbe.SafePipeHandle))
            {
                Console.Error.WriteLine(
                    "FAIL: telemetry pipe DACL does not grant the current user full control.");
                return 1;
            }
        }

        server.Start();

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
            var snapshot = new TrafficSnapshot(
                i * 100,
                i * 200,
                i * 10,
                i * 20,
                i * 60,
                i * 120,
                i * 6,
                i * 12,
                i * 40,
                i * 80,
                i * 4,
                i * 8);
            writer.WriteLine(TrafficTelemetryProtocol.Serialize(snapshot, i));
            Console.WriteLine(
                $"  sent up={snapshot.UploadBytes} down={snapshot.DownloadBytes} " +
                $"tcpUp={snapshot.TcpUploadBytes} tcpDown={snapshot.TcpDownloadBytes} " +
                $"udpUp={snapshot.UdpUploadBytes} udpDown={snapshot.UdpDownloadBytes}");
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
                    $"tcpUp={snapshot.TcpUploadBytes} tcpDown={snapshot.TcpDownloadBytes} " +
                    $"udpUp={snapshot.UdpUploadBytes} udpDown={snapshot.UdpDownloadBytes}");
            }

            for (var i = 0; i < received.Count; i++)
            {
                var expected = (i + 1);
                var snapshot = received[i];
                if (snapshot.TcpUploadBytes != expected * 60
                    || snapshot.TcpDownloadBytes != expected * 120
                    || snapshot.UdpUploadBytes != expected * 40
                    || snapshot.UdpDownloadBytes != expected * 80)
                {
                    Console.Error.WriteLine(
                        $"FAIL: protocol telemetry counters were not preserved for snapshot {expected}.");
                    return 1;
                }
            }
        }

        Console.WriteLine("PASS: telemetry pipe delivered 3 snapshots.");
        return 0;
    }
}
