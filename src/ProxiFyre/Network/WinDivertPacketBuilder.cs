using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace ProxiFyre;

internal static class WinDivertPacketBuilder
{
    private const int MaxIpv4PacketLength = ushort.MaxValue;
    private const int MaxIpv6PayloadLength = ushort.MaxValue;

    public static byte[] BuildUdpResponse(
        IPAddress sourceAddress,
        ushort sourcePort,
        IPAddress destinationAddress,
        ushort destinationPort,
        ReadOnlySpan<byte> payload)
    {
        EnsureSameAddressFamily(sourceAddress, destinationAddress);
        var maxPayloadLength = sourceAddress.AddressFamily == AddressFamily.InterNetwork
            ? 65507
            : 65527;
        if (payload.Length > maxPayloadLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payload),
                payload.Length,
                $"UDP payload exceeds the {maxPayloadLength}-byte limit for {sourceAddress.AddressFamily}.");
        }

        return sourceAddress.AddressFamily == AddressFamily.InterNetwork
            ? BuildIpv4Udp(
                sourceAddress,
                sourcePort,
                destinationAddress,
                destinationPort,
                payload)
            : BuildIpv6Udp(
                sourceAddress,
                sourcePort,
                destinationAddress,
                destinationPort,
                payload);
    }

    public static IReadOnlyList<byte[]> BuildUdpFragments(
        IPAddress sourceAddress,
        ushort sourcePort,
        IPAddress destinationAddress,
        ushort destinationPort,
        ReadOnlySpan<byte> payload,
        int mtu)
    {
        EnsureSameAddressFamily(sourceAddress, destinationAddress);
        var maxPayloadLength = sourceAddress.AddressFamily == AddressFamily.InterNetwork
            ? 65507
            : 65527;
        if (payload.Length > maxPayloadLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payload),
                payload.Length,
                $"UDP payload exceeds the {maxPayloadLength}-byte limit for {sourceAddress.AddressFamily}.");
        }

        if (mtu <= 0)
        {
            mtu = 1500;
        }

        var ipHeaderLength = sourceAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        if (ipHeaderLength + 8 + payload.Length <= mtu)
        {
            return [BuildUdpResponse(
                sourceAddress,
                sourcePort,
                destinationAddress,
                destinationPort,
                payload)];
        }

        var udp = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(0, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(4, 2), checked((ushort)udp.Length));
        payload.CopyTo(udp.AsSpan(8));
        var checksum = ComputeTransportChecksum(
            sourceAddress,
            destinationAddress,
            PacketView.ProtocolUdp,
            udp);
        BinaryPrimitives.WriteUInt16BigEndian(
            udp.AsSpan(6, 2),
            checksum == 0 ? (ushort)0xFFFF : checksum);

        return sourceAddress.AddressFamily == AddressFamily.InterNetwork
            ? BuildIpv4UdpFragments(
                sourceAddress,
                destinationAddress,
                udp,
                mtu)
            : BuildIpv6UdpFragments(
                sourceAddress,
                destinationAddress,
                udp,
                mtu);
    }

    public static byte[] BuildTcpSegment(
        IPAddress sourceAddress,
        ushort sourcePort,
        IPAddress destinationAddress,
        ushort destinationPort,
        TcpSegment segment)
    {
        EnsureSameAddressFamily(sourceAddress, destinationAddress);
        if (segment.Options.Length % 4 != 0 || segment.Options.Length > 40)
        {
            throw new ArgumentOutOfRangeException(
                nameof(segment),
                "TCP options must be 4-byte aligned and no longer than 40 bytes.");
        }

        return sourceAddress.AddressFamily == AddressFamily.InterNetwork
            ? BuildIpv4Tcp(
                sourceAddress,
                sourcePort,
                destinationAddress,
                destinationPort,
                segment)
            : BuildIpv6Tcp(
                sourceAddress,
                sourcePort,
                destinationAddress,
                destinationPort,
                segment);
    }

    public static byte[] BuildUdpError(
        IPAddress remoteAddress,
        ushort remotePort,
        IPAddress clientAddress,
        ushort clientPort,
        ReadOnlySpan<byte> originalPayload,
        SocketError socketError)
    {
        EnsureSameAddressFamily(remoteAddress, clientAddress);
        return remoteAddress.AddressFamily == AddressFamily.InterNetwork
            ? BuildIpv4UdpError(
                remoteAddress,
                remotePort,
                clientAddress,
                clientPort,
                originalPayload,
                socketError)
            : BuildIpv6UdpError(
                remoteAddress,
                remotePort,
                clientAddress,
                clientPort,
                originalPayload,
                socketError);
    }

    private static byte[] BuildIpv4Udp(
        IPAddress sourceAddress,
        ushort sourcePort,
        IPAddress destinationAddress,
        ushort destinationPort,
        ReadOnlySpan<byte> payload)
    {
        var packet = new byte[20 + 8 + payload.Length];
        var ip = packet.AsSpan(0, 20);
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)packet.Length);
        ip[8] = 64;
        ip[9] = PacketView.ProtocolUdp;
        sourceAddress.GetAddressBytes().CopyTo(ip.Slice(12, 4));
        destinationAddress.GetAddressBytes().CopyTo(ip.Slice(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(
            ip.Slice(10, 2),
            ComputeOnesComplement(ip));

        var udp = packet.AsSpan(20);
        BinaryPrimitives.WriteUInt16BigEndian(udp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(4, 2), (ushort)udp.Length);
        payload.CopyTo(udp[8..]);
        var checksum = ComputeTransportChecksum(
            sourceAddress,
            destinationAddress,
            PacketView.ProtocolUdp,
            udp);
        BinaryPrimitives.WriteUInt16BigEndian(
            udp.Slice(6, 2),
            checksum == 0 ? (ushort)0xFFFF : checksum);
        return packet;
    }

    private static byte[] BuildIpv6Udp(
        IPAddress sourceAddress,
        ushort sourcePort,
        IPAddress destinationAddress,
        ushort destinationPort,
        ReadOnlySpan<byte> payload)
    {
        var packet = new byte[40 + 8 + payload.Length];
        var ip = packet.AsSpan(0, 40);
        ip[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), (ushort)(8 + payload.Length));
        ip[6] = PacketView.ProtocolUdp;
        ip[7] = 64;
        sourceAddress.GetAddressBytes().CopyTo(ip.Slice(8, 16));
        destinationAddress.GetAddressBytes().CopyTo(ip.Slice(24, 16));

        var udp = packet.AsSpan(40);
        BinaryPrimitives.WriteUInt16BigEndian(udp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(4, 2), (ushort)udp.Length);
        payload.CopyTo(udp[8..]);
        var checksum = ComputeTransportChecksum(
            sourceAddress,
            destinationAddress,
            PacketView.ProtocolUdp,
            udp);
        BinaryPrimitives.WriteUInt16BigEndian(
            udp.Slice(6, 2),
            checksum == 0 ? (ushort)0xFFFF : checksum);
        return packet;
    }

    private static IReadOnlyList<byte[]> BuildIpv4UdpFragments(
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ReadOnlySpan<byte> udp,
        int mtu)
    {
        var maximumFragmentData = Math.Max(8, (mtu - 20) & ~7);
        var identification = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
        var fragments = new List<byte[]>();
        var offset = 0;
        while (offset < udp.Length)
        {
            var fragmentDataLength = Math.Min(maximumFragmentData, udp.Length - offset);
            var moreFragments = offset + fragmentDataLength < udp.Length;
            var packet = new byte[20 + fragmentDataLength];
            var ip = packet.AsSpan(0, 20);
            ip[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)packet.Length);
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), identification);
            BinaryPrimitives.WriteUInt16BigEndian(
                ip.Slice(6, 2),
                (ushort)(((offset / 8) & 0x1FFF) | (moreFragments ? 0x2000 : 0)));
            ip[8] = 64;
            ip[9] = PacketView.ProtocolUdp;
            sourceAddress.GetAddressBytes().CopyTo(ip.Slice(12, 4));
            destinationAddress.GetAddressBytes().CopyTo(ip.Slice(16, 4));
            BinaryPrimitives.WriteUInt16BigEndian(
                ip.Slice(10, 2),
                ComputeOnesComplement(ip));
            udp.Slice(offset, fragmentDataLength).CopyTo(packet.AsSpan(20));
            fragments.Add(packet);
            offset += fragmentDataLength;
        }

        return fragments;
    }

    private static IReadOnlyList<byte[]> BuildIpv6UdpFragments(
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ReadOnlySpan<byte> udp,
        int mtu)
    {
        var maximumFragmentData = Math.Max(8, (mtu - 48) & ~7);
        Span<byte> identificationBytes = stackalloc byte[4];
        RandomNumberGenerator.Fill(identificationBytes);
        var identification = BinaryPrimitives.ReadUInt32BigEndian(identificationBytes);
        var fragments = new List<byte[]>();
        var offset = 0;
        while (offset < udp.Length)
        {
            var fragmentDataLength = Math.Min(maximumFragmentData, udp.Length - offset);
            var moreFragments = offset + fragmentDataLength < udp.Length;
            var packet = new byte[40 + 8 + fragmentDataLength];
            var ip = packet.AsSpan(0, 40);
            ip[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(
                ip.Slice(4, 2),
                (ushort)(8 + fragmentDataLength));
            ip[6] = 44;
            ip[7] = 64;
            sourceAddress.GetAddressBytes().CopyTo(ip.Slice(8, 16));
            destinationAddress.GetAddressBytes().CopyTo(ip.Slice(24, 16));
            var fragment = packet.AsSpan(40, 8);
            fragment[0] = PacketView.ProtocolUdp;
            BinaryPrimitives.WriteUInt16BigEndian(
                fragment.Slice(2, 2),
                (ushort)(((offset / 8) << 3) | (moreFragments ? 1 : 0)));
            BinaryPrimitives.WriteUInt32BigEndian(fragment.Slice(4, 4), identification);
            udp.Slice(offset, fragmentDataLength).CopyTo(packet.AsSpan(48));
            fragments.Add(packet);
            offset += fragmentDataLength;
        }

        return fragments;
    }

    private static byte[] BuildIpv4Tcp(
        IPAddress sourceAddress,
        ushort sourcePort,
        IPAddress destinationAddress,
        ushort destinationPort,
        TcpSegment segment)
    {
        var headerLength = 20 + segment.Options.Length;
        var packetLength = 20 + headerLength + segment.Payload.Length;
        if (packetLength > MaxIpv4PacketLength)
        {
            throw new ArgumentOutOfRangeException(nameof(segment), "TCP segment exceeds the IPv4 packet limit.");
        }

        var packet = new byte[packetLength];
        var ip = packet.AsSpan(0, 20);
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)packetLength);
        ip[8] = 64;
        ip[9] = PacketView.ProtocolTcp;
        sourceAddress.GetAddressBytes().CopyTo(ip.Slice(12, 4));
        destinationAddress.GetAddressBytes().CopyTo(ip.Slice(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), ComputeOnesComplement(ip));

        var tcp = packet.AsSpan(20);
        WriteTcpHeader(
            tcp,
            sourcePort,
            destinationPort,
            headerLength,
            segment);
        var checksum = ComputeTransportChecksum(
            sourceAddress,
            destinationAddress,
            PacketView.ProtocolTcp,
            tcp);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(16, 2), checksum);
        return packet;
    }

    private static byte[] BuildIpv6Tcp(
        IPAddress sourceAddress,
        ushort sourcePort,
        IPAddress destinationAddress,
        ushort destinationPort,
        TcpSegment segment)
    {
        var headerLength = 20 + segment.Options.Length;
        var payloadLength = headerLength + segment.Payload.Length;
        if (payloadLength > MaxIpv6PayloadLength)
        {
            throw new ArgumentOutOfRangeException(nameof(segment), "TCP segment exceeds the IPv6 packet limit.");
        }

        var packet = new byte[40 + payloadLength];
        var ip = packet.AsSpan(0, 40);
        ip[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), (ushort)payloadLength);
        ip[6] = PacketView.ProtocolTcp;
        ip[7] = 64;
        sourceAddress.GetAddressBytes().CopyTo(ip.Slice(8, 16));
        destinationAddress.GetAddressBytes().CopyTo(ip.Slice(24, 16));

        var tcp = packet.AsSpan(40);
        WriteTcpHeader(
            tcp,
            sourcePort,
            destinationPort,
            headerLength,
            segment);
        var checksum = ComputeTransportChecksum(
            sourceAddress,
            destinationAddress,
            PacketView.ProtocolTcp,
            tcp);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(16, 2), checksum);
        return packet;
    }

    private static void WriteTcpHeader(
        Span<byte> tcp,
        ushort sourcePort,
        ushort destinationPort,
        int headerLength,
        TcpSegment segment)
    {
        BinaryPrimitives.WriteUInt16BigEndian(tcp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(4, 4), segment.SequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(8, 4), segment.AcknowledgmentNumber);
        tcp[12] = (byte)((headerLength / 4) << 4);
        tcp[13] = segment.Flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(14, 2), segment.Window);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(18, 2), segment.UrgentPointer);
        segment.Options.Span.CopyTo(tcp.Slice(20));
        segment.Payload.Span.CopyTo(tcp.Slice(headerLength));
    }

    private static byte[] BuildIpv4UdpError(
        IPAddress remoteAddress,
        ushort remotePort,
        IPAddress clientAddress,
        ushort clientPort,
        ReadOnlySpan<byte> originalPayload,
        SocketError socketError)
    {
        var quoteLength = Math.Min(8, originalPayload.Length);
        var original = new byte[20 + 8 + quoteLength];
        var originalIp = original.AsSpan(0, 20);
        originalIp[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(
            originalIp.Slice(2, 2),
            (ushort)original.Length);
        originalIp[8] = 64;
        originalIp[9] = PacketView.ProtocolUdp;
        clientAddress.GetAddressBytes().CopyTo(originalIp.Slice(12, 4));
        remoteAddress.GetAddressBytes().CopyTo(originalIp.Slice(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(
            originalIp.Slice(10, 2),
            ComputeOnesComplement(originalIp));
        var originalUdp = original.AsSpan(20);
        BinaryPrimitives.WriteUInt16BigEndian(originalUdp[..2], clientPort);
        BinaryPrimitives.WriteUInt16BigEndian(originalUdp.Slice(2, 2), remotePort);
        BinaryPrimitives.WriteUInt16BigEndian(
            originalUdp.Slice(4, 2),
            (ushort)originalUdp.Length);
        originalPayload[..quoteLength].CopyTo(originalUdp[8..]);

        var (icmpType, icmpCode) = MapIpv4Icmp(socketError);
        var icmp = new byte[8 + original.Length];
        icmp[0] = icmpType;
        icmp[1] = icmpCode;
        original.CopyTo(icmp, 8);
        BinaryPrimitives.WriteUInt16BigEndian(
            icmp.AsSpan(2, 2),
            ComputeOnesComplement(icmp));

        var packet = new byte[20 + icmp.Length];
        var ip = packet.AsSpan(0, 20);
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)packet.Length);
        ip[8] = 64;
        ip[9] = 1;
        remoteAddress.GetAddressBytes().CopyTo(ip.Slice(12, 4));
        clientAddress.GetAddressBytes().CopyTo(ip.Slice(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(
            ip.Slice(10, 2),
            ComputeOnesComplement(ip));
        icmp.CopyTo(packet, 20);
        return packet;
    }

    private static byte[] BuildIpv6UdpError(
        IPAddress remoteAddress,
        ushort remotePort,
        IPAddress clientAddress,
        ushort clientPort,
        ReadOnlySpan<byte> originalPayload,
        SocketError socketError)
    {
        var quoteLength = Math.Min(8, originalPayload.Length);
        var original = new byte[40 + 8 + quoteLength];
        var originalIp = original.AsSpan(0, 40);
        originalIp[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(
            originalIp.Slice(4, 2),
            (ushort)(8 + quoteLength));
        originalIp[6] = PacketView.ProtocolUdp;
        originalIp[7] = 64;
        clientAddress.GetAddressBytes().CopyTo(originalIp.Slice(8, 16));
        remoteAddress.GetAddressBytes().CopyTo(originalIp.Slice(24, 16));
        var originalUdp = original.AsSpan(40);
        BinaryPrimitives.WriteUInt16BigEndian(originalUdp[..2], clientPort);
        BinaryPrimitives.WriteUInt16BigEndian(originalUdp.Slice(2, 2), remotePort);
        BinaryPrimitives.WriteUInt16BigEndian(
            originalUdp.Slice(4, 2),
            (ushort)originalUdp.Length);
        originalPayload[..quoteLength].CopyTo(originalUdp[8..]);

        var (icmpType, icmpCode) = MapIpv6Icmp(socketError);
        var icmp = new byte[8 + original.Length];
        icmp[0] = icmpType;
        icmp[1] = icmpCode;
        original.CopyTo(icmp, 8);
        BinaryPrimitives.WriteUInt16BigEndian(
            icmp.AsSpan(2, 2),
            ComputeTransportChecksum(
                remoteAddress,
                clientAddress,
                protocol: 58,
                icmp));

        var packet = new byte[40 + icmp.Length];
        var ip = packet.AsSpan(0, 40);
        ip[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), (ushort)icmp.Length);
        ip[6] = 58;
        ip[7] = 64;
        remoteAddress.GetAddressBytes().CopyTo(ip.Slice(8, 16));
        clientAddress.GetAddressBytes().CopyTo(ip.Slice(24, 16));
        icmp.CopyTo(packet, 40);
        return packet;
    }

    private static (byte Type, byte Code) MapIpv4Icmp(SocketError socketError)
    {
        return socketError switch
        {
            SocketError.NetworkUnreachable => (3, 0),
            SocketError.HostUnreachable => (3, 1),
            SocketError.ConnectionRefused => (3, 3),
            SocketError.MessageSize => (3, 4),
            _ => (3, 3)
        };
    }

    private static (byte Type, byte Code) MapIpv6Icmp(SocketError socketError)
    {
        return socketError switch
        {
            SocketError.MessageSize => (2, 0),
            SocketError.NetworkUnreachable => (1, 0),
            SocketError.HostUnreachable => (1, 3),
            SocketError.ConnectionRefused => (1, 4),
            _ => (1, 4)
        };
    }

    private static void EnsureSameAddressFamily(IPAddress sourceAddress, IPAddress destinationAddress)
    {
        if (sourceAddress.AddressFamily != destinationAddress.AddressFamily)
        {
            throw new InvalidOperationException("Source and destination address families do not match.");
        }
    }

    private static ushort ComputeTransportChecksum(
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        byte protocol,
        ReadOnlySpan<byte> transport)
    {
        uint sum = 0;
        sum = AddChecksumBytes(sum, sourceAddress.GetAddressBytes());
        sum = AddChecksumBytes(sum, destinationAddress.GetAddressBytes());
        if (sourceAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            sum += protocol;
            sum += (uint)transport.Length;
        }
        else
        {
            sum += (uint)(transport.Length >> 16);
            sum += (uint)(transport.Length & 0xFFFF);
            sum += protocol;
        }

        sum = AddChecksumBytes(sum, transport);
        return FoldChecksum(sum);
    }

    private static ushort ComputeOnesComplement(ReadOnlySpan<byte> data)
    {
        return FoldChecksum(AddChecksumBytes(0, data));
    }

    private static uint AddChecksumBytes(uint sum, ReadOnlySpan<byte> data)
    {
        var offset = 0;
        for (; offset + 1 < data.Length; offset += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
        }

        if (offset < data.Length)
        {
            sum += (uint)(data[offset] << 8);
        }

        return sum;
    }

    private static ushort FoldChecksum(uint sum)
    {
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }
}
