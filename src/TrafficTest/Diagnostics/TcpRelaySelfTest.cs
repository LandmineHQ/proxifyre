using System.Net;
using System.Net.Sockets;
using ProxiFyre;

namespace TrafficTest;

internal static class TcpRelaySelfTest
{
    public static async Task<int> RunAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var injections = new List<TcpSegment>();
        var injectionLock = new object();

        using var relay = new TcpDirectRelay();
        relay.SetPacketInjector((_, segment) =>
        {
            lock (injectionLock)
            {
                injections.Add(segment);
            }
        });
        relay.SetOutboundBypass(_ => { }, _ => { });
        using var relayCancellation = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
        relay.Start(relayCancellation.Token);

        Socket? serverSocket = null;
        try
        {
            const ushort clientPort = 40123;
            const uint clientInitialSequence = 1000;
            var target = new DirectRelayTarget(
                IPAddress.Loopback,
                (ushort)serverPort,
                DateTimeOffset.UtcNow,
                ClientAddress: IPAddress.Loopback,
                ClientPort: clientPort,
                AdapterHandle: IntPtr.Zero,
                LinkHeader: new byte[]
                {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x08, 0x00
                });
            var flowKey = new TcpRelayKey(
                IntPtr.Zero,
                IPAddress.Loopback,
                IPAddress.Loopback,
                clientPort,
                (ushort)serverPort);
            var acceptedTask = listener.AcceptSocketAsync(timeout.Token).AsTask();
            relay.RegisterSyn(
                flowKey,
                new TcpClientKey(IPAddress.Loopback, clientPort),
                target,
                clientInitialSequence,
                65535,
                timeout.Token);

            serverSocket = await acceptedTask.ConfigureAwait(false);
            var synAck = await WaitForAsync(
                injections,
                injectionLock,
                segment => (segment.Flags & (PacketView.TcpFlagSyn | PacketView.TcpFlagAck))
                    == (PacketView.TcpFlagSyn | PacketView.TcpFlagAck),
                timeout.Token).ConfigureAwait(false);
            Assert(synAck.AcknowledgmentNumber == clientInitialSequence + 1, "TCP SYN-ACK acknowledgement is incorrect.");
            Assert(synAck.Payload.Length == 0, "TCP SYN-ACK unexpectedly contains payload.");
            Assert(synAck.Options.Length >= 4, "TCP SYN-ACK did not advertise MSS.");

            var serverInitialSequence = synAck.SequenceNumber;
            var clientNextSequence = clientInitialSequence + 1u;
            relay.TryGetConnection(flowKey, out var connection);
            connection.SendClientSegment(new TcpSegment(
                clientNextSequence,
                serverInitialSequence + 1u,
                PacketView.TcpFlagAck,
                0,
                0,
                ReadOnlyMemory<byte>.Empty,
                ReadOnlyMemory<byte>.Empty));

            var clientPayload = "hello"u8.ToArray();
            connection.SendClientSegment(new TcpSegment(
                clientNextSequence,
                serverInitialSequence + 1u,
                PacketView.TcpFlagPsh | PacketView.TcpFlagAck,
                0,
                0,
                clientPayload,
                ReadOnlyMemory<byte>.Empty));
            var receivedClientPayload = new byte[clientPayload.Length];
            await ReadExactAsync(serverSocket, receivedClientPayload, timeout.Token).ConfigureAwait(false);
            Assert(receivedClientPayload.SequenceEqual(clientPayload), "Client payload was not forwarded to the test server.");
            await WaitForAsync(
                injections,
                injectionLock,
                segment => segment.AcknowledgmentNumber == clientNextSequence + (uint)clientPayload.Length
                    && (segment.Flags & PacketView.TcpFlagAck) != 0,
                timeout.Token).ConfigureAwait(false);

            var serverPayload = "world"u8.ToArray();
            var clientDataEnd = clientNextSequence + (uint)clientPayload.Length;
            await serverSocket.SendAsync(serverPayload, SocketFlags.None, timeout.Token).ConfigureAwait(false);
            await Task.Delay(250, timeout.Token).ConfigureAwait(false);
            lock (injectionLock)
            {
                Assert(
                    !injections.Any(segment => segment.Payload.Span.SequenceEqual(serverPayload)),
                    "TCP relay sent data despite a zero client receive window.");
            }

            connection.SendClientSegment(new TcpSegment(
                clientDataEnd,
                serverInitialSequence + 1u,
                PacketView.TcpFlagAck,
                65535,
                0,
                ReadOnlyMemory<byte>.Empty,
                ReadOnlyMemory<byte>.Empty));
            var serverData = await WaitForAsync(
                injections,
                injectionLock,
                segment => segment.Payload.Span.SequenceEqual(serverPayload),
                timeout.Token).ConfigureAwait(false);

            for (var i = 0; i < 3; i++)
            {
                connection.SendClientSegment(new TcpSegment(
                    clientDataEnd,
                    serverInitialSequence + 1u,
                    PacketView.TcpFlagAck,
                    65535,
                    0,
                    ReadOnlyMemory<byte>.Empty,
                    ReadOnlyMemory<byte>.Empty));
            }

            await WaitUntilAsync(
                () =>
                {
                    lock (injectionLock)
                    {
                        return injections.Count(segment => segment.Payload.Span.SequenceEqual(serverPayload)) >= 2;
                    }
                },
                timeout.Token).ConfigureAwait(false);

            while (serverSocket.Available > 0)
            {
                var discard = new byte[Math.Min(serverSocket.Available, 1024)];
                _ = await serverSocket.ReceiveAsync(discard, SocketFlags.None, timeout.Token).ConfigureAwait(false);
            }

            connection.SendClientSegment(new TcpSegment(
                clientDataEnd,
                serverData.SequenceNumber + (uint)serverData.Payload.Length,
                PacketView.TcpFlagAck,
                65535,
                0,
                ReadOnlyMemory<byte>.Empty,
                ReadOnlyMemory<byte>.Empty));

            var clientFinSequence = clientDataEnd;
            connection.SendClientSegment(new TcpSegment(
                clientFinSequence,
                serverInitialSequence + 1u + (uint)serverPayload.Length,
                PacketView.TcpFlagFin | PacketView.TcpFlagAck,
                65535,
                0,
                ReadOnlyMemory<byte>.Empty,
                ReadOnlyMemory<byte>.Empty));
            await WaitForAsync(
                injections,
                injectionLock,
                segment => segment.AcknowledgmentNumber == clientFinSequence + 1
                    && (segment.Flags & PacketView.TcpFlagAck) != 0,
                timeout.Token).ConfigureAwait(false);
            Console.WriteLine("PASS: TCP relay handshake, bidirectional data, ACK/retransmission, and client FIN transition.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAIL: {ex}");
            return 1;
        }
        finally
        {
            serverSocket?.Dispose();
            listener.Stop();
        }
    }

    private static async Task<TcpSegment> WaitForAsync(
        List<TcpSegment> injections,
        object injectionLock,
        Func<TcpSegment, bool> predicate,
        CancellationToken cancellationToken,
        Func<string>? diagnostic = null)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (injectionLock)
            {
                var match = injections.FirstOrDefault(predicate);
                if (match != default)
                {
                    return match;
                }
            }

            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException(
            diagnostic is null
                ? "Timed out waiting for an injected TCP segment."
                : $"Timed out waiting for an injected TCP segment. {diagnostic()}");
    }

    private static async Task ReadExactAsync(Socket socket, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await socket.ReceiveAsync(buffer.AsMemory(offset), SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("Remote stream closed before all expected bytes arrived.");
            }

            offset += read;
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (condition())
            {
                return;
            }

            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException("Timed out waiting for the TCP relay condition.");
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
