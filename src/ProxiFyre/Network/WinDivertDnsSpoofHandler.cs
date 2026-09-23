using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxiFyre;

internal static class WinDivertDnsSpoofHandler
{
    private static long _lastLogTick;

    public static bool TryHandle(
        PacketView packet,
        uint interfaceIndex,
        uint subInterfaceIndex,
        ProcessInfo process,
        WinDivertPacketInjector injector,
        Action<string> log,
        TimeProvider timeProvider)
    {
        if (!packet.IsUdp
            || packet.DestinationPort is not (53 or 5353)
            || packet.UdpPayload.Length < 12)
        {
            return false;
        }

        var payload = packet.UdpPayload;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
        if (questionCount == 0 || (flags & 0x8000) != 0)
        {
            return false;
        }

        var offset = 12;
        var domain = new StringBuilder();
        while (offset < payload.Length)
        {
            var length = payload[offset];
            if (length == 0)
            {
                offset++;
                break;
            }

            if ((length & 0xC0) != 0
                || length > 63
                || offset + 1 + length > payload.Length)
            {
                return false;
            }

            if (domain.Length > 0)
            {
                domain.Append('.');
            }

            domain.Append(Encoding.ASCII.GetString(payload.Slice(offset + 1, length)));
            offset += 1 + length;
        }

        if (offset + 4 > payload.Length)
        {
            return false;
        }

        var queryType = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
        offset += 4;
        var queryDomain = domain.ToString();
        if ((queryType is not (1 or 28))
            || !queryDomain.StartsWith("fakeip-", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var firstDot = queryDomain.IndexOf('.');
        if (firstDot < 0)
        {
            return false;
        }

        var parts = queryDomain[..firstDot].Split('-');
        if (parts.Length != 5
            || !IPAddress.TryParse(
                $"{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}",
                out var fakeIp))
        {
            return false;
        }

        var response = BuildResponse(payload, queryType, offset, fakeIp);
        var target = new DirectRelayTarget(
            packet.DestinationAddress,
            packet.DestinationPort,
            timeProvider.GetUtcNow(),
            process.ProcessId,
            process.Name,
            process.Path,
            MatchedPattern: string.Empty,
            packet.SourceAddress,
            packet.SourcePort,
            new IntPtr(interfaceIndex),
            AdapterMtu: 1500,
            InterfaceIndex: (int)interfaceIndex,
            SubInterfaceIndex: subInterfaceIndex,
            WireAddressFamily: (ushort)(packet.AddressFamily == AddressFamily.InterNetwork ? 2 : 23),
            ProcessStartTimeUtcTicks: process.StartTimeUtcTicks);
        var injected = injector.InjectUdpResponse(
            target,
            new IPEndPoint(packet.DestinationAddress, packet.DestinationPort),
            response);
        if (!injected)
        {
            return false;
        }

        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastLogTick);
        if (now - last >= 1000
            && Interlocked.CompareExchange(ref _lastLogTick, now, last) == last)
        {
            log(
                $"[DNS SPOOF] {queryDomain} type={queryType} -> {fakeIp} processId={process.ProcessId}");
        }

        return true;
    }

    private static byte[] BuildResponse(
        ReadOnlySpan<byte> query,
        ushort queryType,
        int questionEnd,
        IPAddress fakeIp)
    {
        var questionLength = questionEnd - 12;
        var addressLength = queryType == 1 ? 4 : 16;
        var response = new byte[12 + questionLength + 12 + addressLength];
        BinaryPrimitives.WriteUInt16BigEndian(
            response.AsSpan(0, 2),
            BinaryPrimitives.ReadUInt16BigEndian(query[..2]));
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 1);
        query.Slice(12, questionLength).CopyTo(response.AsSpan(12));

        var answerOffset = 12 + questionLength;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(answerOffset, 2), 0xC00C);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(answerOffset + 2, 2), queryType);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(answerOffset + 4, 2), 1);
        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(answerOffset + 6, 4), 60);
        BinaryPrimitives.WriteUInt16BigEndian(
            response.AsSpan(answerOffset + 10, 2),
            (ushort)addressLength);

        if (queryType == 1)
        {
            fakeIp.GetAddressBytes().CopyTo(response.AsSpan(answerOffset + 12, 4));
        }
        else
        {
            Span<byte> mapped = stackalloc byte[16];
            mapped[10] = 0xFF;
            mapped[11] = 0xFF;
            fakeIp.GetAddressBytes().CopyTo(mapped[12..]);
            mapped.CopyTo(response.AsSpan(answerOffset + 12, 16));
        }

        return response;
    }
}
