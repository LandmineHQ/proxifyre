using System.Net;
using System.Net.NetworkInformation;
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

            return true;
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
                0,
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

            connection.SendClientSegment(new TcpSegment(
                clientNextSequence,
                serverInitialSequence + 1000u,
                PacketView.TcpFlagAck,
                65535,
                0,
                ReadOnlyMemory<byte>.Empty,
                ReadOnlyMemory<byte>.Empty));
            Assert(!connection.IsClosed, "TCP relay closed after an ACK for unsent data.");

            connection.SendClientSegment(new TcpSegment(
                clientInitialSequence,
                serverInitialSequence + 1u,
                PacketView.TcpFlagRst | PacketView.TcpFlagAck,
                0,
                0,
                ReadOnlyMemory<byte>.Empty,
                ReadOnlyMemory<byte>.Empty));
            Assert(!connection.IsClosed, "TCP relay accepted an out-of-window stale RST.");

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
            await TestUnavailableSourceAddressFallbackAsync(timeout.Token).ConfigureAwait(false);
            await TestOutboundFlowCleanupAfterConnectFailureAsync(timeout.Token).ConfigureAwait(false);
            Console.WriteLine("PASS: TCP relay handshake, bidirectional data, ACK/retransmission, client FIN transition, local-address fallback, and failed-connect cleanup.");
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

    private static async Task TestUnavailableSourceAddressFallbackAsync(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var synAckReceived = new TaskCompletionSource<TcpSegment>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var registeredFlows = new List<RelayOutboundFlow>();
        var logLines = new List<string>();
        var registeredFlowLock = new object();
        var logLock = new object();
        const int interfaceIndex = 19;
        var unavailableSourceAddress = FindUnavailableIpv4Address();

        using var relay = new TcpDirectRelay(
            log: message =>
            {
                lock (logLock)
                {
                    logLines.Add(message);
                }
            },
            detailedLogging: true);
        relay.SetPacketInjector((_, segment) =>
        {
            if ((segment.Flags & (PacketView.TcpFlagSyn | PacketView.TcpFlagAck))
                == (PacketView.TcpFlagSyn | PacketView.TcpFlagAck))
            {
                synAckReceived.TrySetResult(segment);
            }

            return true;
        });
        relay.SetOutboundBypass(
            flow =>
            {
                lock (registeredFlowLock)
                {
                    registeredFlows.Add(flow);
                }
            },
            _ => { });

        using var relayCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        relay.Start(relayCancellation.Token);

        Socket? serverSocket = null;
        try
        {
            const ushort clientPort = 40223;
            const uint clientInitialSequence = 2000;
            var target = new DirectRelayTarget(
                IPAddress.Loopback,
                (ushort)serverPort,
                DateTimeOffset.UtcNow,
                ClientAddress: unavailableSourceAddress,
                ClientPort: clientPort,
                AdapterHandle: IntPtr.Zero,
                InterfaceIndex: interfaceIndex);
            var attempts = TcpDirectRelay.TcpRelayConnection.CreateConnectAttempts(
                target,
                AddressFamily.InterNetwork);
            Assert(attempts.Count == 3, "TCP fallback did not plan all three connection attempts.");
            Assert(
                attempts[0].BindEndPoint.Address.Equals(unavailableSourceAddress)
                && attempts[0].PinInterface,
                "TCP fallback did not try the captured source address with interface pinning first.");
            Assert(
                attempts[1].BindEndPoint.Address.Equals(unavailableSourceAddress)
                && !attempts[1].PinInterface,
                "TCP fallback did not try the captured source address without interface pinning second.");
            Assert(
                attempts[2].BindEndPoint.Address.Equals(IPAddress.Any)
                && !attempts[2].PinInterface,
                "TCP fallback did not use the wildcard address last.");

            var flowKey = new TcpRelayKey(
                IntPtr.Zero,
                0,
                unavailableSourceAddress,
                IPAddress.Loopback,
                clientPort,
                (ushort)serverPort);

            var acceptedTask = listener.AcceptSocketAsync(cancellationToken).AsTask();
            relay.RegisterSyn(
                flowKey,
                new TcpClientKey(unavailableSourceAddress, clientPort),
                target,
                clientInitialSequence,
                65535,
                cancellationToken);

            serverSocket = await acceptedTask.ConfigureAwait(false);
            var synAck = await synAckReceived.Task
                .WaitAsync(TimeSpan.FromSeconds(5), cancellationToken)
                .ConfigureAwait(false);
            Assert(
                synAck.AcknowledgmentNumber == clientInitialSequence + 1,
                "TCP fallback SYN-ACK acknowledgement is incorrect.");

            lock (registeredFlowLock)
            {
                Assert(
                    registeredFlows.Any(flow =>
                        flow.RemoteAddress.Equals(IPAddress.Loopback)
                        && flow.RemotePort == serverPort
                        && !flow.LocalAddress.Equals(IPAddress.Any)),
                    "TCP relay did not register the actual local endpoint after address fallback.");
            }

            lock (logLock)
            {
                Assert(
                    logLines.Any(line => line.Contains("pinInterface=True", StringComparison.Ordinal)),
                    "TCP fallback did not report the source-address/interface attempt.");
                Assert(
                    logLines.Any(line => line.Contains("pinInterface=False", StringComparison.Ordinal)),
                    "TCP fallback did not report the source-address-only attempt.");
            }
        }
        finally
        {
            serverSocket?.Dispose();
            listener.Stop();
        }
    }

    private static async Task TestOutboundFlowCleanupAfterConnectFailureAsync(CancellationToken cancellationToken)
    {
        var portProbe = new TcpListener(IPAddress.Loopback, 0);
        portProbe.Start();
        var closedPort = ((IPEndPoint)portProbe.LocalEndpoint).Port;
        portProbe.Stop();

        var registeredCount = 0;
        var unregisteredCount = 0;
        using var relay = new TcpDirectRelay(log: _ => { });
        relay.SetPacketInjector((_, _) => true);
        relay.SetOutboundBypass(
            _ => Interlocked.Increment(ref registeredCount),
            _ =>
            {
                Interlocked.Increment(ref unregisteredCount);
                throw new InvalidOperationException("Simulated outbound bypass cleanup failure.");
            });

        using var relayCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        relay.Start(relayCancellation.Token);

        const ushort clientPort = 40224;
        var clientAddress = IPAddress.Loopback;
        var target = new DirectRelayTarget(
            IPAddress.Loopback,
            (ushort)closedPort,
            DateTimeOffset.UtcNow,
            ClientAddress: clientAddress,
            ClientPort: clientPort,
            AdapterHandle: IntPtr.Zero);
        var flowKey = new TcpRelayKey(
            IntPtr.Zero,
            0,
            clientAddress,
            IPAddress.Loopback,
            clientPort,
            (ushort)closedPort);

        relay.RegisterSyn(
            flowKey,
            new TcpClientKey(clientAddress, clientPort),
            target,
            3000,
            65535,
            cancellationToken);

        await WaitUntilAsync(
            () => Volatile.Read(ref registeredCount) == 1
                && Volatile.Read(ref unregisteredCount) == 1
                && relay.ConnectionCount == 0,
            cancellationToken).ConfigureAwait(false);
        Assert(
            TcpRelayConnectionErrorsAreClassified(),
            "TCP outbound address error classification is incorrect.");
    }

    private static bool TcpRelayConnectionErrorsAreClassified()
    {
        return TcpDirectRelay.TcpRelayConnection.IsRetryableOutboundAddressError(SocketError.AddressNotAvailable)
            && TcpDirectRelay.TcpRelayConnection.IsRetryableOutboundAddressError(SocketError.NetworkUnreachable)
            && !TcpDirectRelay.TcpRelayConnection.IsRetryableOutboundAddressError(SocketError.ConnectionRefused);
    }

    private static IPAddress FindUnavailableIpv4Address()
    {
        var localAddresses = NetworkInterface.GetAllNetworkInterfaces()
            .SelectMany(networkInterface => networkInterface.GetIPProperties().UnicastAddresses)
            .Select(unicast => unicast.Address)
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
            .ToHashSet();

        for (var host = 1; host < 255; host++)
        {
            var candidate = IPAddress.Parse($"192.0.2.{host}");
            if (!localAddresses.Contains(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("Could not find an unavailable TEST-NET-1 source address.");
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
