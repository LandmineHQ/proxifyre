using System.Net;
using System.Net.Sockets;
using ProxiFyre;

namespace TrafficTest;

internal static class UdpRelaySelfTest
{
    public static async Task<int> RunAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var relay = new UdpDirectRelay(log: _ => { });
        using var remoteA = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using var remoteB = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using var remoteC = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using var remoteAlternate = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        remoteA.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        remoteB.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        remoteC.Bind(new IPEndPoint(IPAddress.Parse("127.0.0.2"), 0));
        remoteAlternate.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        var responseSource = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
        var responsePayload = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var crossAddressSource = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
        var alternateSource = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
        relay.SetResponseInjector((_, remoteEndPoint, payload) =>
        {
            if (remoteEndPoint.Address.Equals(IPAddress.Parse("127.0.0.2")))
            {
                crossAddressSource.TrySetResult(remoteEndPoint);
            }
            else if (remoteEndPoint.Port == ((IPEndPoint)remoteAlternate.LocalEndPoint!).Port)
            {
                alternateSource.TrySetResult(remoteEndPoint);
            }
            else
            {
                responseSource.TrySetResult(remoteEndPoint);
                responsePayload.TrySetResult(payload.ToArray());
            }

            return true;
        });
        relay.SetOutboundBypass(_ => { }, _ => { });
        relay.Start(timeout.Token);

        try
        {
            var remoteEndPointA = (IPEndPoint)remoteA.LocalEndPoint!;
            var remoteEndPointB = (IPEndPoint)remoteB.LocalEndPoint!;
            var clientEndPoint = new IPEndPoint(IPAddress.Loopback, 40234);
            var keyA = new UdpRelayKey(
                IntPtr.Zero,
                0,
                clientEndPoint.Address,
                (ushort)clientEndPoint.Port,
                remoteEndPointA.Address,
                (ushort)remoteEndPointA.Port);
            var keyB = new UdpRelayKey(
                IntPtr.Zero,
                0,
                clientEndPoint.Address,
                (ushort)clientEndPoint.Port,
                remoteEndPointB.Address,
                (ushort)remoteEndPointB.Port);
            var targetA = new DirectRelayTarget(
                remoteEndPointA.Address,
                (ushort)remoteEndPointA.Port,
                DateTimeOffset.UtcNow,
                ClientAddress: clientEndPoint.Address,
                ClientPort: (ushort)clientEndPoint.Port,
                AdapterHandle: IntPtr.Zero,
                LinkHeader: new byte[]
                {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x08, 0x00
                });
            var targetB = targetA with
            {
                RemoteAddress = remoteEndPointB.Address,
                RemotePort = (ushort)remoteEndPointB.Port
            };

            var requestPayload = "request"u8.ToArray();
            await relay.SendToRemoteAsync(
                keyA,
                targetA,
                requestPayload,
                remoteEndPointA.Address,
                (ushort)remoteEndPointA.Port).ConfigureAwait(false);

            var requestA = await ReceiveAsync(remoteA, timeout.Token).ConfigureAwait(false);
            Assert(requestA.ReceivedBytes == requestPayload.Length, "UDP request length mismatch.");
            Assert(
                requestA.Payload.AsSpan().SequenceEqual(requestPayload),
                "UDP request payload mismatch.");

            await relay.SendToRemoteAsync(
                keyB,
                targetB,
                requestPayload,
                remoteEndPointB.Address,
                (ushort)remoteEndPointB.Port).ConfigureAwait(false);
            var requestB = await ReceiveAsync(remoteB, timeout.Token).ConfigureAwait(false);
            Assert(
                requestB.RemoteEndPoint.Port == requestA.RemoteEndPoint.Port,
                "UDP relay did not preserve one external source port across remote destinations.");

            var replyPayload = "reply-from-b"u8.ToArray();
            await remoteB.SendToAsync(
                replyPayload,
                SocketFlags.None,
                requestA.RemoteEndPoint,
                timeout.Token).ConfigureAwait(false);

            var injectedSource = await responseSource.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            var injectedPayload = await responsePayload.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            Assert(injectedSource.Port == remoteEndPointB.Port, "UDP relay did not preserve the actual response source endpoint.");
            Assert(injectedPayload.SequenceEqual(replyPayload), "UDP response payload mismatch.");

            var alternateReply = "reply-from-alternate-port"u8.ToArray();
            await remoteAlternate.SendToAsync(
                alternateReply,
                SocketFlags.None,
                requestA.RemoteEndPoint,
                timeout.Token).ConfigureAwait(false);
            var injectedAlternateSource = await alternateSource.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            Assert(
                injectedAlternateSource.Address.Equals(IPAddress.Loopback),
                "UDP relay did not preserve a same-address alternate response port.");

            var crossAddressReply = "reply-from-c"u8.ToArray();
            await remoteC.SendToAsync(
                crossAddressReply,
                SocketFlags.None,
                requestA.RemoteEndPoint,
                timeout.Token).ConfigureAwait(false);
            var injectedCrossAddressSource = await crossAddressSource.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            Assert(
                injectedCrossAddressSource.Address.Equals(IPAddress.Parse("127.0.0.2")),
                "UDP relay did not accept an open-policy response from a different remote address.");

            relay.Remove(keyA);
            Assert(
                !relay.TryGetTarget(keyA, out _) && relay.TryGetTarget(keyB, out _),
                "Removing one UDP target unexpectedly removed another target in the same session.");
            await relay.SendToRemoteAsync(
                keyB,
                targetB,
                requestPayload,
                remoteEndPointB.Address,
                (ushort)remoteEndPointB.Port).ConfigureAwait(false);
            var secondRequestB = await ReceiveAsync(remoteB, timeout.Token).ConfigureAwait(false);
            Assert(
                secondRequestB.RemoteEndPoint.Port == requestA.RemoteEndPoint.Port,
                "UDP relay changed the external source port after removing another target.");

            var unavailableTarget = targetA with
            {
                ClientPort = 40235,
                AdapterHandle = new IntPtr(1),
                InterfaceIndex = 0
            };
            var unavailableKey = new UdpRelayKey(
                unavailableTarget.AdapterHandle,
                0,
                unavailableTarget.ClientAddress!,
                unavailableTarget.ClientPort,
                unavailableTarget.RemoteAddress,
                unavailableTarget.RemotePort);
            Assert(
                !relay.TrySubmit(
                    unavailableKey,
                    unavailableTarget,
                    requestPayload,
                    unavailableTarget.RemoteAddress,
                    unavailableTarget.RemotePort,
                    out _),
                "UDP relay did not fail closed when the interface index was unavailable.");

            relay.ApplyConfiguration(new AppConfiguration
            {
                Apps = [],
                CoreProcessName = AppConfiguration.DefaultCoreProcessName
            });
            Assert(
                !relay.TryGetTarget(keyA, out _) && !relay.TryGetTarget(keyB, out _),
                "UDP relay did not evict existing flows after a configuration reload.");

            Console.WriteLine("PASS: UDP relay preserves client flow and external ports, accepts open-policy remote endpoints, fails closed without an interface index, and honors configuration reloads.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAIL: {ex}");
            return 1;
        }
    }

    private static async Task<(byte[] Payload, IPEndPoint RemoteEndPoint, int ReceivedBytes)> ReceiveAsync(
        Socket socket,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[128];
        EndPoint source = new IPEndPoint(IPAddress.Any, 0);
        var result = await socket.ReceiveFromAsync(
            buffer,
            SocketFlags.None,
            source,
            cancellationToken).ConfigureAwait(false);
        return (
            buffer.AsSpan(0, result.ReceivedBytes).ToArray(),
            (IPEndPoint)result.RemoteEndPoint,
            result.ReceivedBytes);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
