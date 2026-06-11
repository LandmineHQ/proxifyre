using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace TrafficTest;

internal static class StunClient
{
    private const uint StunMagicCookie = 0x2112A442;

    public static async Task<IPEndPoint> ResolveEndPointAsync(
        string host,
        int port,
        AddressFamily addressFamily,
        CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(host, addressFamily, cancellationToken);
        var address = addresses.FirstOrDefault(address => address.AddressFamily == addressFamily)
            ?? throw new InvalidOperationException($"No {addressFamily} address found for STUN host {host}.");
        return new IPEndPoint(address, port);
    }

    public static async Task<StunResult> SendBindingRequestAsync(
        IPEndPoint remoteEndPoint,
        AddressFamily addressFamily,
        int timeoutMilliseconds,
        CancellationToken cancellationToken)
    {
        using var socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(addressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(IPAddress.Any, 0)
            : new IPEndPoint(IPAddress.IPv6Any, 0));

        var request = CreateStunBindingRequest();
        await socket.SendToAsync(request, SocketFlags.None, remoteEndPoint, cancellationToken);

        var buffer = new byte[1500];
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMilliseconds(timeoutMilliseconds));
        try
        {
            var received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, CreateAnyEndPoint(addressFamily), timeout.Token);
            if (received.RemoteEndPoint is not IPEndPoint responseEndPoint)
            {
                return StunResult.Fail("Response endpoint was not an IP endpoint.");
            }

            if (!TryParseStunBindingResponse(buffer.AsSpan(0, received.ReceivedBytes), request.AsSpan(8, 12), out var mappedEndPoint, out var parseError))
            {
                return StunResult.Fail(parseError);
            }

            return StunResult.Ok(mappedEndPoint, responseEndPoint, received.ReceivedBytes);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return StunResult.Fail("Timed out waiting for STUN response.");
        }
    }

    private static EndPoint CreateAnyEndPoint(AddressFamily addressFamily)
    {
        return addressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(IPAddress.Any, 0)
            : new IPEndPoint(IPAddress.IPv6Any, 0);
    }

    private static byte[] CreateStunBindingRequest()
    {
        var request = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(0, 2), 0x0001);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2, 2), 0);
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4, 4), StunMagicCookie);
        RandomNumberGenerator.Fill(request.AsSpan(8, 12));
        return request;
    }

    private static bool TryParseStunBindingResponse(
        ReadOnlySpan<byte> response,
        ReadOnlySpan<byte> transactionId,
        out IPEndPoint? mappedEndPoint,
        out string error)
    {
        mappedEndPoint = null;
        error = string.Empty;

        if (response.Length < 20)
        {
            error = $"STUN response too short: {response.Length} bytes.";
            return false;
        }

        var messageType = BinaryPrimitives.ReadUInt16BigEndian(response[..2]);
        if (messageType != 0x0101)
        {
            error = $"Unexpected STUN message type 0x{messageType:X4}.";
            return false;
        }

        var messageLength = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(2, 2));
        if (response.Length < 20 + messageLength)
        {
            error = $"Truncated STUN response: length={response.Length}, declared={messageLength}.";
            return false;
        }

        var magicCookie = BinaryPrimitives.ReadUInt32BigEndian(response.Slice(4, 4));
        if (magicCookie != StunMagicCookie)
        {
            error = $"Unexpected STUN magic cookie 0x{magicCookie:X8}.";
            return false;
        }

        if (!response.Slice(8, 12).SequenceEqual(transactionId))
        {
            error = "STUN transaction ID mismatch.";
            return false;
        }

        var attributes = response.Slice(20, messageLength);
        var offset = 0;
        while (offset + 4 <= attributes.Length)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(attributes.Slice(offset, 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(attributes.Slice(offset + 2, 2));
            offset += 4;
            if (offset + length > attributes.Length)
            {
                error = "Truncated STUN attribute.";
                return false;
            }

            var value = attributes.Slice(offset, length);
            if ((type == 0x0020 && TryParseXorMappedAddress(value, transactionId, out mappedEndPoint))
                || (type == 0x0001 && TryParseMappedAddress(value, out mappedEndPoint)))
            {
                return true;
            }

            offset += Align4(length);
        }

        error = "STUN response did not include MAPPED-ADDRESS or XOR-MAPPED-ADDRESS.";
        return false;
    }

    private static bool TryParseMappedAddress(ReadOnlySpan<byte> value, out IPEndPoint? endPoint)
    {
        endPoint = null;
        if (value.Length < 4 || value[0] != 0)
        {
            return false;
        }

        var family = value[1];
        var port = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(2, 2));
        if (family == 0x01 && value.Length >= 8)
        {
            endPoint = new IPEndPoint(new IPAddress(value.Slice(4, 4)), port);
            return true;
        }

        if (family == 0x02 && value.Length >= 20)
        {
            endPoint = new IPEndPoint(new IPAddress(value.Slice(4, 16)), port);
            return true;
        }

        return false;
    }

    private static bool TryParseXorMappedAddress(
        ReadOnlySpan<byte> value,
        ReadOnlySpan<byte> transactionId,
        out IPEndPoint? endPoint)
    {
        endPoint = null;
        if (value.Length < 4 || value[0] != 0)
        {
            return false;
        }

        var family = value[1];
        var port = (ushort)(BinaryPrimitives.ReadUInt16BigEndian(value.Slice(2, 2)) ^ (StunMagicCookie >> 16));
        Span<byte> cookieBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(cookieBytes, StunMagicCookie);

        if (family == 0x01 && value.Length >= 8)
        {
            Span<byte> address = stackalloc byte[4];
            value.Slice(4, 4).CopyTo(address);
            for (var i = 0; i < address.Length; i++)
            {
                address[i] ^= cookieBytes[i];
            }

            endPoint = new IPEndPoint(new IPAddress(address), port);
            return true;
        }

        if (family == 0x02 && value.Length >= 20)
        {
            Span<byte> address = stackalloc byte[16];
            value.Slice(4, 16).CopyTo(address);
            for (var i = 0; i < 4; i++)
            {
                address[i] ^= cookieBytes[i];
            }

            for (var i = 0; i < transactionId.Length; i++)
            {
                address[4 + i] ^= transactionId[i];
            }

            endPoint = new IPEndPoint(new IPAddress(address), port);
            return true;
        }

        return false;
    }

    private static int Align4(int value)
    {
        return (value + 3) & ~3;
    }
}
