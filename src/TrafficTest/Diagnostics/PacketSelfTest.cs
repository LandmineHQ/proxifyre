using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using ProxiFyre;

namespace TrafficTest;

internal static class PacketSelfTest
{
    public static int Run()
    {
        try
        {
            TestUdpParsingAndDeclaredLength();
            TestVlanParsing();
            TestTcpOptionsAndUrgentPointer();
            TestIpv4FragmentReassembly();
            TestIpv6FragmentReassembly();
            TestOutboundPassFlowRegistry();
            TestWfpProtocolLayout();
            TestNetworkInterfaceIndexResolution();
            Console.WriteLine("PASS: packet parsing, VLAN, TCP fields, fragment reassembly, and interface index resolution.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAIL: {ex}");
            return 1;
        }
    }

    private static void TestUdpParsingAndDeclaredLength()
    {
        var payload = "udp-payload"u8.ToArray();
        var packet = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.10"),
            IPAddress.Parse("198.51.100.20"),
            PacketView.ProtocolUdp,
            12345,
            53,
            payload,
            declaredTransportLength: 8 + payload.Length);

        Assert(PacketView.TryParse(packet, packet.Length, out var view), "IPv4 UDP packet did not parse.");
        Assert(view.SourcePort == 12345, "UDP source port mismatch.");
        Assert(view.DestinationPort == 53, "UDP destination port mismatch.");
        Assert(view.UdpLength == 8 + payload.Length, "UDP declared length mismatch.");
        Assert(view.UdpPayload.SequenceEqual(payload), "UDP payload should use the declared UDP length.");
    }

    private static void TestVlanParsing()
    {
        var payload = "vlan"u8.ToArray();
        var basePacket = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.11"),
            IPAddress.Parse("198.51.100.21"),
            PacketView.ProtocolUdp,
            1000,
            2000,
            payload);
        var vlanPacket = new byte[basePacket.Length + 4];
        basePacket.AsSpan(0, 12).CopyTo(vlanPacket);
        BinaryPrimitives.WriteUInt16BigEndian(vlanPacket.AsSpan(12, 2), PacketView.EtherTypeVlan);
        BinaryPrimitives.WriteUInt16BigEndian(vlanPacket.AsSpan(14, 2), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(vlanPacket.AsSpan(16, 2), PacketView.EtherTypeIpv4);
        basePacket.AsSpan(14).CopyTo(vlanPacket.AsSpan(18));

        Assert(PacketView.TryParse(vlanPacket, vlanPacket.Length, out var view), "VLAN IPv4 packet did not parse.");
        Assert(view.LinkHeaderLength == 18, "VLAN link header length mismatch.");
        Assert(view.UdpPayload.SequenceEqual(payload), "VLAN UDP payload mismatch.");
    }

    private static void TestTcpOptionsAndUrgentPointer()
    {
        var packet = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.12"),
            IPAddress.Parse("198.51.100.22"),
            PacketView.ProtocolTcp,
            8080,
            443,
            [],
            tcpOptions: [2, 4, 0x05, 0xB4],
            tcpFlags: PacketView.TcpFlagUrg | PacketView.TcpFlagAck,
            urgentPointer: 7);

        Assert(PacketView.TryParse(packet, packet.Length, out var view), "IPv4 TCP packet did not parse.");
        Assert(view.TcpOptions.SequenceEqual(new byte[] { 2, 4, 0x05, 0xB4 }), "TCP options mismatch.");
        Assert(view.TcpUrgentPointer == 7, "TCP urgent pointer mismatch.");
        Assert((view.TcpFlags & PacketView.TcpFlagUrg) != 0, "TCP URG flag mismatch.");
    }

    private static void TestIpv4FragmentReassembly()
    {
        var payload = Enumerable.Range(0, 4000).Select(value => (byte)value).ToArray();
        var full = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.13"),
            IPAddress.Parse("198.51.100.23"),
            PacketView.ProtocolUdp,
            4000,
            5000,
            payload);
        var reassembler = new IpFragmentReassembler();
        ReassembledIpPacket? result = null;

        foreach (var fragment in FragmentIpv4(full, 1400))
        {
            var status = reassembler.Add(
                fragment,
                fragment.Length,
                IntPtr.Zero,
                1,
                0,
                out var candidate,
                out _);
            if (status == FragmentAddStatus.Complete)
            {
                result = candidate;
            }
        }

        Assert(result is not null, "IPv4 fragments were not reassembled.");
        Assert(PacketView.TryParse(result!.Frame, result.Length, out var view), "Reassembled IPv4 packet did not parse.");
        Assert(view.UdpPayload.SequenceEqual(payload), "Reassembled IPv4 UDP payload mismatch.");

        var invalidFragment = BuildIpv4Packet(
            IPAddress.Parse("192.0.2.14"),
            IPAddress.Parse("198.51.100.24"),
            PacketView.ProtocolUdp,
            4100,
            5100,
            [0x01]);
        BinaryPrimitives.WriteUInt16BigEndian(invalidFragment.AsSpan(20, 2), 0x2000);
        var invalidStatus = reassembler.Add(
            invalidFragment,
            invalidFragment.Length,
            IntPtr.Zero,
            1,
            0,
            out _,
            out var fragmentsToPass);
        Assert(invalidStatus == FragmentAddStatus.Invalid, "Invalid IPv4 fragment was not rejected.");
        Assert(
            fragmentsToPass is { Count: 1 }
                && fragmentsToPass[0].Frame.AsSpan(0, fragmentsToPass[0].Length).SequenceEqual(invalidFragment),
            "Invalid IPv4 fragment was not returned for transparent replay.");
    }

    private static void TestIpv6FragmentReassembly()
    {
        var payload = Enumerable.Range(0, 3000).Select(value => (byte)(value + 17)).ToArray();
        var full = BuildIpv6Packet(
            IPAddress.Parse("2001:db8::13"),
            IPAddress.Parse("2001:db8::23"),
            PacketView.ProtocolUdp,
            6000,
            7000,
            payload);
        var reassembler = new IpFragmentReassembler();
        ReassembledIpPacket? result = null;

        foreach (var fragment in FragmentIpv6(full, 1200))
        {
            var status = reassembler.Add(
                fragment,
                fragment.Length,
                IntPtr.Zero,
                1,
                0,
                out var candidate,
                out _);
            if (status == FragmentAddStatus.Complete)
            {
                result = candidate;
            }
        }

        Assert(result is not null, "IPv6 fragments were not reassembled.");
        Assert(PacketView.TryParse(result!.Frame, result.Length, out var view), "Reassembled IPv6 packet did not parse.");
        Assert(view.UdpPayload.SequenceEqual(payload), "Reassembled IPv6 UDP payload mismatch.");
    }

    private static void TestOutboundPassFlowRegistry()
    {
        var registry = new OutboundPassFlowRegistry(maxFlows: 2, ttl: TimeSpan.FromSeconds(10));
        var first = new RelayOutboundFlow(
            IntPtr.Zero,
            PacketView.ProtocolUdp,
            IPAddress.Loopback,
            IPAddress.Parse("198.51.100.30"),
            1000,
            2000);
        var second = new RelayOutboundFlow(
            IntPtr.Zero,
            PacketView.ProtocolUdp,
            IPAddress.Loopback,
            IPAddress.Parse("198.51.100.31"),
            1001,
            2001);
        var third = new RelayOutboundFlow(
            IntPtr.Zero,
            PacketView.ProtocolTcp,
            IPAddress.Loopback,
            IPAddress.Parse("198.51.100.32"),
            1002,
            2002);

        var now = DateTimeOffset.UnixEpoch;
        registry.Register(first, now);
        registry.Register(second, now.AddSeconds(1));
        registry.Register(third, now.AddSeconds(2));
        registry.Register(second, now.AddSeconds(6));
        Assert(registry.Count == 2, "Outbound pass flow registry exceeded its capacity.");
        Assert(
            registry.Snapshot().All(flow => !flow.Equals(first)),
            "Outbound pass flow registry did not evict the oldest flow.");
        Assert(
            registry.RemoveExpired(now.AddSeconds(13)),
            "Outbound pass flow registry did not expire stale flows.");
        Assert(registry.Count == 1, "Outbound pass flow registry removed a refreshed flow.");
        Assert(
            registry.Snapshot().Single().Equals(second),
            "Outbound pass flow registry retained the wrong flow after expiry.");
        Assert(
            registry.RemoveExpired(now.AddSeconds(17)),
            "Outbound pass flow registry did not expire the refreshed flow.");
        Assert(registry.Count == 0, "Outbound pass flow registry retained expired flows.");
    }

    private static void TestWfpProtocolLayout()
    {
        Assert(
            Marshal.SizeOf<WfpFlowEvent>() == 72,
            "WFP flow event layout does not match the native protocol.");
        Assert(
            Marshal.SizeOf<WfpVerdict>() == 16,
            "WFP verdict layout does not match the native protocol.");
    }

    private static void TestNetworkInterfaceIndexResolution()
    {
        var resolved = 0;
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!NetworkInterfaceIndexResolver.TryGetIndex(networkInterface, out var index))
            {
                continue;
            }

            Assert(index > 0, $"Network interface '{networkInterface.Name}' returned an invalid index.");
            resolved++;
        }

        Assert(resolved > 0, "No Windows network interface index could be resolved.");
    }

    private static byte[] BuildIpv4Packet(
        IPAddress source,
        IPAddress destination,
        byte protocol,
        ushort sourcePort,
        ushort destinationPort,
        byte[] payload,
        int? declaredTransportLength = null,
        byte[]? tcpOptions = null,
        byte tcpFlags = 0,
        ushort urgentPointer = 0)
    {
        var transportOptions = tcpOptions ?? [];
        var transportHeaderLength = protocol == PacketView.ProtocolTcp ? 20 + transportOptions.Length : 8;
        var declaredLength = declaredTransportLength ?? transportHeaderLength + payload.Length;
        var transportLength = declaredTransportLength is null
            ? declaredLength
            : declaredLength + 4;
        var packet = new byte[14 + 20 + transportLength];
        packet.AsSpan(0, 6).Fill(0x10);
        packet.AsSpan(6, 6).Fill(0x20);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(12, 2), PacketView.EtherTypeIpv4);
        var ip = packet.AsSpan(14, 20);
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)(20 + transportLength));
        ip[8] = 64;
        ip[9] = protocol;
        source.GetAddressBytes().CopyTo(ip.Slice(12, 4));
        destination.GetAddressBytes().CopyTo(ip.Slice(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), ComputeChecksum(ip));
        var transport = packet.AsSpan(34);
        BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(0, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(2, 2), destinationPort);
        if (protocol == PacketView.ProtocolUdp)
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                transport.Slice(4, 2),
                (ushort)declaredLength);
        }
        else
        {
            transport[12] = (byte)((transportHeaderLength / 4) << 4);
            transport[13] = tcpFlags;
            BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(14, 2), 65535);
            BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(18, 2), urgentPointer);
            transportOptions.CopyTo(transport.Slice(20));
        }

        payload.CopyTo(transport.Slice(transportHeaderLength));
        return packet;
    }

    private static byte[] BuildIpv6Packet(
        IPAddress source,
        IPAddress destination,
        byte protocol,
        ushort sourcePort,
        ushort destinationPort,
        byte[] payload)
    {
        var packet = new byte[14 + 40 + 8 + payload.Length];
        packet.AsSpan(0, 6).Fill(0x30);
        packet.AsSpan(6, 6).Fill(0x40);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(12, 2), PacketView.EtherTypeIpv6);
        var ip = packet.AsSpan(14, 40);
        ip[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), (ushort)(8 + payload.Length));
        ip[6] = protocol;
        ip[7] = 64;
        source.GetAddressBytes().CopyTo(ip.Slice(8, 16));
        destination.GetAddressBytes().CopyTo(ip.Slice(24, 16));
        var udp = packet.AsSpan(54);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(0, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(4, 2), (ushort)(8 + payload.Length));
        payload.CopyTo(udp.Slice(8));
        return packet;
    }

    private static IEnumerable<byte[]> FragmentIpv4(byte[] packet, int maxPayload)
    {
        const int ipOffset = 14;
        const int ipHeaderLength = 20;
        var ipPayload = packet.AsSpan(ipOffset + ipHeaderLength).ToArray();
        var identification = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ipOffset + 4, 2));
        for (var offset = 0; offset < ipPayload.Length; offset += maxPayload)
        {
            var length = Math.Min(maxPayload, ipPayload.Length - offset);
            var more = offset + length < ipPayload.Length;
            var fragment = new byte[ipOffset + ipHeaderLength + length];
            packet.AsSpan(0, ipOffset).CopyTo(fragment);
            var ip = fragment.AsSpan(ipOffset, ipHeaderLength);
            ip[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)(ipHeaderLength + length));
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), identification);
            BinaryPrimitives.WriteUInt16BigEndian(
                ip.Slice(6, 2),
                (ushort)((offset / 8) | (more ? 0x2000 : 0)));
            ip[8] = 64;
            ip[9] = packet[ipOffset + 9];
            packet.AsSpan(ipOffset + 12, 8).CopyTo(ip.Slice(12, 8));
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), ComputeChecksum(ip));
            ipPayload.AsSpan(offset, length).CopyTo(fragment.AsSpan(ipOffset + ipHeaderLength));
            yield return fragment;
        }
    }

    private static IEnumerable<byte[]> FragmentIpv6(byte[] packet, int maxPayload)
    {
        const int ipOffset = 14;
        const int ipHeaderLength = 40;
        var ipPayload = packet.AsSpan(ipOffset + ipHeaderLength).ToArray();
        var identification = 0x11223344u;
        for (var offset = 0; offset < ipPayload.Length; offset += maxPayload)
        {
            var length = Math.Min(maxPayload, ipPayload.Length - offset);
            var more = offset + length < ipPayload.Length;
            var fragment = new byte[ipOffset + ipHeaderLength + 8 + length];
            packet.AsSpan(0, ipOffset).CopyTo(fragment);
            var ip = fragment.AsSpan(ipOffset, ipHeaderLength);
            ip[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), (ushort)(8 + length));
            ip[6] = 44;
            ip[7] = 64;
            packet.AsSpan(ipOffset + 8, 32).CopyTo(ip.Slice(8, 32));
            var fragmentHeader = fragment.AsSpan(ipOffset + 40, 8);
            fragmentHeader[0] = packet[ipOffset + 6];
            BinaryPrimitives.WriteUInt16BigEndian(
                fragmentHeader.Slice(2, 2),
                (ushort)(((offset / 8) << 3) | (more ? 1 : 0)));
            BinaryPrimitives.WriteUInt32BigEndian(fragmentHeader.Slice(4, 4), identification);
            ipPayload.AsSpan(offset, length).CopyTo(fragment.AsSpan(ipOffset + 48));
            yield return fragment;
        }
    }

    private static ushort ComputeChecksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        for (var i = 0; i + 1 < data.Length; i += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
        }

        if ((data.Length & 1) != 0)
        {
            sum += (uint)(data[^1] << 8);
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
