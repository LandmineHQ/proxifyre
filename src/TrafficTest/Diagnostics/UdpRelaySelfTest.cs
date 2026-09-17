using System.Net;
using System.Net.Sockets;
using ProxiFyre;

namespace TrafficTest;

internal static class UdpRelaySelfTest
{
    public static async Task<int> RunAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var relay = new UdpDirectRelay();
        using var remoteA = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using var remoteB = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        remoteA.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        remoteB.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        var responseSource = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
        var responsePayload = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        relay.SetResponseInjector((_, remoteEndPoint, payload) =>
        {
            responseSource.TrySetResult(remoteEndPoint);
            responsePayload.TrySetResult(payload.ToArray());
        });
        relay.SetOutboundBypass(_ => { }, _ => { });
        relay.Start(timeout.Token);

        try
        {
            var remoteEndPointA = (IPEndPoint)remoteA.LocalEndPoint!;
            var remoteEndPointB = (IPEndPoint)remoteB.LocalEndPoint!;
            var clientEndPoint = new IPEndPoint(IPAddress.Loopback, 40234);
            var key = new UdpRelayKey(
                IntPtr.Zero,
                clientEndPoint.Address,
                (ushort)clientEndPoint.Port,
                remoteEndPointA.Address,
                (ushort)remoteEndPointA.Port);
            var target = new DirectRelayTarget(
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

            var requestPayload = "request"u8.ToArray();
            await relay.SendToRemoteAsync(
                key,
                target,
                requestPayload,
                remoteEndPointA.Address,
                (ushort)remoteEndPointA.Port).ConfigureAwait(false);

            var requestBuffer = new byte[128];
            EndPoint requestSource = new IPEndPoint(IPAddress.Any, 0);
            remoteA.ReceiveTimeout = 5000;
            var request = await Task.Run(
                () =>
                {
                    var received = remoteA.ReceiveFrom(requestBuffer, SocketFlags.None, ref requestSource);
                    return (ReceivedBytes: received, RemoteEndPoint: requestSource);
                },
                timeout.Token).ConfigureAwait(false);
            Assert(request.ReceivedBytes == requestPayload.Length, "UDP request length mismatch.");
            Assert(
                requestBuffer.AsSpan(0, request.ReceivedBytes).SequenceEqual(requestPayload),
                "UDP request payload mismatch.");

            var replyPayload = "reply-from-b"u8.ToArray();
            await remoteB.SendToAsync(
                replyPayload,
                SocketFlags.None,
                request.RemoteEndPoint,
                timeout.Token).ConfigureAwait(false);

            var injectedSource = await responseSource.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            var injectedPayload = await responsePayload.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            Assert(injectedSource.Port == remoteEndPointB.Port, "UDP relay did not preserve the actual response source endpoint.");
            Assert(injectedPayload.SequenceEqual(replyPayload), "UDP response payload mismatch.");
            Console.WriteLine("PASS: UDP relay preserves client flow and accepts a response from an alternate endpoint.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAIL: {ex}");
            return 1;
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
