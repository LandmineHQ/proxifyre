using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace ProxiFyre;

internal sealed unsafe class PacketInjector
{
    private readonly Func<IntPtr> _getDriverHandle;
    private readonly Func<AdapterPipelineSet?> _getAdapters;
    private readonly Action<string, string, TimeSpan> _logDetail;
    private long _mstcpSendSucceeded;
    private long _mstcpSendFailed;

    public PacketInjector(
        Func<IntPtr> getDriverHandle,
        Func<AdapterPipelineSet?> getAdapters,
        Action<string, string, TimeSpan> logDetail)
    {
        _getDriverHandle = getDriverHandle;
        _getAdapters = getAdapters;
        _logDetail = logDetail;
    }

    public long MstcpSendSucceeded => Interlocked.Read(ref _mstcpSendSucceeded);

    public long MstcpSendFailed => Interlocked.Read(ref _mstcpSendFailed);

    public bool InjectTcpSegmentToClient(DirectRelayTarget target, TcpSegment segment)
    {
        if (target.ClientAddress is null || target.ClientPort == 0)
        {
            _logDetail(
                $"TCP inject skipped because client endpoint is unknown app={target.AppLabel}",
                $"tcp-inject-no-client:{target.ProcessId}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        if (target.AdapterHandle == IntPtr.Zero)
        {
            _logDetail(
                $"TCP inject skipped because adapter is unknown app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"tcp-inject-no-adapter:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var clientAddress = NetworkAddress.Normalize(target.ClientAddress);
        var remoteAddress = NetworkAddress.Normalize(target.RemoteAddress);
        if (clientAddress.AddressFamily != remoteAddress.AddressFamily)
        {
            _logDetail(
                $"TCP inject skipped because address families differ app={target.AppLabel} client={clientAddress} remote={remoteAddress}",
                $"tcp-inject-family-mismatch:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        if (target.LinkHeader is not { Length: >= PacketView.EthernetHeaderLength }
            && (target.InboundEthernetSource is not { Length: 6 }
                || target.InboundEthernetDestination is not { Length: 6 }))
        {
            _logDetail(
                $"TCP inject skipped because ethernet addresses are unknown app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"tcp-inject-no-ethernet:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var payloadSpan = segment.Payload.Span;
        var optionSpan = segment.Options.Span;
        if (optionSpan.Length % 4 != 0 || optionSpan.Length > 40)
        {
            _logDetail(
                $"TCP inject skipped because options are invalid app={target.AppLabel} appLocal={target.ClientEndpoint} options={optionSpan.Length}",
                $"tcp-inject-invalid-options:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var linkHeaderLength = target.LinkHeader is { Length: >= PacketView.EthernetHeaderLength } linkHeader
            ? linkHeader.Length
            : PacketView.EthernetHeaderLength;
        var ipHeaderLength = clientAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        var tcpHeaderLength = 20 + optionSpan.Length;
        var packetLength = linkHeaderLength + ipHeaderLength + tcpHeaderLength + payloadSpan.Length;
        if (packetLength > NdisApi.MaxEtherFrame)
        {
            _logDetail(
                $"TCP inject skipped because packet is too large length={packetLength} app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"tcp-inject-too-large:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var buffer = default(NdisApi.IntermediateBuffer);
        buffer.AdapterOrListFlink = target.AdapterHandle;
        buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
        buffer.Dot1q = target.Dot1q;
        buffer.Length = (uint)packetLength;
        var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
        frame[..packetLength].Clear();
        WriteInboundLinkHeader(frame, target, linkHeaderLength);

        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv4);
            BuildIpv4TcpPacket(
                frame.Slice(linkHeaderLength),
                remoteAddress,
                clientAddress,
                target.RemotePort,
                target.ClientPort,
                segment.SequenceNumber,
                segment.AcknowledgmentNumber,
                segment.Flags,
                segment.Window,
                segment.UrgentPointer,
                optionSpan,
                payloadSpan);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv6);
            BuildIpv6TcpPacket(
                frame.Slice(linkHeaderLength),
                remoteAddress,
                clientAddress,
                target.RemotePort,
                target.ClientPort,
                segment.SequenceNumber,
                segment.AcknowledgmentNumber,
                segment.Flags,
                segment.Window,
                segment.UrgentPointer,
                optionSpan,
                payloadSpan);
        }

        if (!SendInjectedPacketToMstcp(&buffer))
        {
            _logDetail(
                $"TCP inject SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} length={packetLength} win32={NdisApi.LastWin32Error}",
                $"tcp-inject-send-failed:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        _logDetail(
            $"RESTORE TCP RECV flags={FormatTcpFlags(segment.Flags)} app={target.AppLabel} appLocal={target.ClientEndpoint} from={target.RemoteEndpoint} injectedBytes={payloadSpan.Length}",
            $"tcp-inject:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}:{segment.Flags}:{payloadSpan.Length > 0}",
            payloadSpan.Length > 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(2));
        return true;
    }

    public bool InjectUdpResponseToClient(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        ReadOnlyMemory<byte> payload)
    {
        if (target.ClientAddress is null || target.ClientPort == 0)
        {
            _logDetail(
                $"UDP inject skipped because client endpoint is unknown app={target.AppLabel} from={remoteEndPoint}",
                $"udp-inject-no-client:{target.ProcessId}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        if (target.AdapterHandle == IntPtr.Zero)
        {
            _logDetail(
                $"UDP inject skipped because adapter is unknown app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint}",
                $"udp-inject-no-adapter:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var clientAddress = NetworkAddress.Normalize(target.ClientAddress);
        var remoteAddress = NetworkAddress.Normalize(remoteEndPoint.Address);
        if (clientAddress.AddressFamily != remoteAddress.AddressFamily)
        {
            _logDetail(
                $"UDP inject skipped because address families differ app={target.AppLabel} client={clientAddress} remote={remoteAddress}",
                $"udp-inject-family-mismatch:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        if (target.LinkHeader is not { Length: >= PacketView.EthernetHeaderLength }
            && (target.InboundEthernetSource is not { Length: 6 }
                || target.InboundEthernetDestination is not { Length: 6 }))
        {
            _logDetail(
                $"UDP inject skipped because ethernet addresses are unknown app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint}",
                $"udp-inject-no-ethernet:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var payloadSpan = payload.Span;
        if (payloadSpan.Length > ushort.MaxValue - 8)
        {
            _logDetail(
                $"UDP inject skipped because datagram is too large length={payloadSpan.Length} app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"udp-inject-datagram-too-large:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var linkHeaderLength = target.LinkHeader is { Length: >= PacketView.EthernetHeaderLength } linkHeader
            ? linkHeader.Length
            : PacketView.EthernetHeaderLength;
        var ipHeaderLength = clientAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        _ = _getAdapters()!.TryGetMtu(target.AdapterHandle, out var mtu);
        var maxFramePayload = NdisApi.MaxEtherFrame - linkHeaderLength;
        var maxDatagramDataLength = Math.Max(
            8,
            Math.Min(mtu, maxFramePayload) - ipHeaderLength - 8);

        if (payloadSpan.Length > maxDatagramDataLength)
        {
            return InjectFragmentedUdpResponse(
                target,
                remoteEndPoint,
                clientAddress,
                remoteAddress,
                linkHeaderLength,
                ipHeaderLength,
                maxDatagramDataLength,
                payloadSpan);
        }

        var packetLength = linkHeaderLength + ipHeaderLength + 8 + payloadSpan.Length;
        var buffer = default(NdisApi.IntermediateBuffer);
        buffer.AdapterOrListFlink = target.AdapterHandle;
        buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
        buffer.Dot1q = target.Dot1q;
        buffer.Length = (uint)packetLength;
        var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
        frame[..packetLength].Clear();
        WriteInboundLinkHeader(frame, target, linkHeaderLength);

        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv4);
            BuildIpv4UdpPacket(
                frame.Slice(linkHeaderLength),
                remoteAddress,
                clientAddress,
                (ushort)remoteEndPoint.Port,
                target.ClientPort,
                payloadSpan);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv6);
            BuildIpv6UdpPacket(
                frame.Slice(linkHeaderLength),
                remoteAddress,
                clientAddress,
                (ushort)remoteEndPoint.Port,
                target.ClientPort,
                payloadSpan);
        }

        if (!SendInjectedPacketToMstcp(&buffer))
        {
            _logDetail(
                $"UDP inject SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint} length={packetLength} win32={NdisApi.LastWin32Error}",
                $"udp-inject-send-failed:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        _logDetail(
            $"RESTORE UDP RECV app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint} injectedBytes={payloadSpan.Length}",
            $"udp-inject:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
            TimeSpan.FromSeconds(2));
        return true;
    }

    public void InjectUdpErrorToClient(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        ReadOnlyMemory<byte> originalPayload,
        SocketError socketError)
    {
        if (target.ClientAddress is null || target.ClientPort == 0 || target.AdapterHandle == IntPtr.Zero)
        {
            return;
        }

        if (target.LinkHeader is not { Length: >= PacketView.EthernetHeaderLength }
            && (target.InboundEthernetSource is not { Length: 6 }
                || target.InboundEthernetDestination is not { Length: 6 }))
        {
            return;
        }

        var clientAddress = NetworkAddress.Normalize(target.ClientAddress);
        var remoteAddress = NetworkAddress.Normalize(remoteEndPoint.Address);
        if (clientAddress.AddressFamily != remoteAddress.AddressFamily)
        {
            return;
        }

        var linkHeaderLength = target.LinkHeader is { Length: >= PacketView.EthernetHeaderLength } linkHeader
            ? linkHeader.Length
            : PacketView.EthernetHeaderLength;
        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            var icmp = BuildIpv4IcmpError(
                clientAddress,
                target.ClientPort,
                remoteAddress,
                (ushort)remoteEndPoint.Port,
                originalPayload.Span,
                MapIpv4IcmpCode(socketError));
            InjectIcmpPacket(target, remoteAddress, clientAddress, PacketView.EtherTypeIpv4, linkHeaderLength, icmp);
            return;
        }

        var icmpv6 = BuildIpv6IcmpError(
            clientAddress,
            target.ClientPort,
            remoteAddress,
            (ushort)remoteEndPoint.Port,
            originalPayload.Span,
            MapIpv6IcmpCode(socketError));
        InjectIcmpPacket(target, remoteAddress, clientAddress, PacketView.EtherTypeIpv6, linkHeaderLength, icmpv6);
    }

    private static void WriteInboundLinkHeader(
        Span<byte> frame,
        DirectRelayTarget target,
        int linkHeaderLength)
    {
        if (target.LinkHeader is { Length: >= PacketView.EthernetHeaderLength } linkHeader)
        {
            linkHeader.AsSpan(6, 6).CopyTo(frame[..6]);
            linkHeader.AsSpan(0, 6).CopyTo(frame.Slice(6, 6));
            if (linkHeader.Length > 12)
            {
                linkHeader.AsSpan(12).CopyTo(frame.Slice(12));
            }

            return;
        }

        target.InboundEthernetDestination!.CopyTo(frame[..6]);
        target.InboundEthernetSource!.CopyTo(frame.Slice(6, 6));
    }

    private void InjectIcmpPacket(
        DirectRelayTarget target,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ushort etherType,
        int linkHeaderLength,
        byte[] icmpPayload)
    {
        var ipHeaderLength = sourceAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        var packetLength = linkHeaderLength + ipHeaderLength + icmpPayload.Length;
        if (packetLength > NdisApi.MaxEtherFrame)
        {
            return;
        }

        var buffer = default(NdisApi.IntermediateBuffer);
        buffer.AdapterOrListFlink = target.AdapterHandle;
        buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
        buffer.Dot1q = target.Dot1q;
        buffer.Length = (uint)packetLength;
        var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
        frame[..packetLength].Clear();
        WriteInboundLinkHeader(frame, target, linkHeaderLength);
        BinaryPrimitives.WriteUInt16BigEndian(frame.Slice(linkHeaderLength - 2, 2), etherType);
        var ip = frame.Slice(linkHeaderLength);
        if (sourceAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            ip[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)(20 + icmpPayload.Length));
            ip[8] = 64;
            ip[9] = 1;
            sourceAddress.GetAddressBytes().CopyTo(ip.Slice(12, 4));
            destinationAddress.GetAddressBytes().CopyTo(ip.Slice(16, 4));
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), ComputeOnesComplement(ip[..20]));
            icmpPayload.CopyTo(ip.Slice(20));
        }
        else
        {
            ip[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), (ushort)icmpPayload.Length);
            ip[6] = 58;
            ip[7] = 64;
            sourceAddress.GetAddressBytes().CopyTo(ip.Slice(8, 16));
            destinationAddress.GetAddressBytes().CopyTo(ip.Slice(24, 16));
            icmpPayload.CopyTo(ip.Slice(40));
        }

        if (!SendInjectedPacketToMstcp(&buffer))
        {
            _logDetail(
                $"ICMP inject SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} from={sourceAddress} win32={NdisApi.LastWin32Error}",
                $"icmp-inject-send-failed:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
        }
    }

    private static byte[] BuildIpv4IcmpError(
        IPAddress clientAddress,
        ushort clientPort,
        IPAddress remoteAddress,
        ushort remotePort,
        ReadOnlySpan<byte> originalPayload,
        byte code)
    {
        var quoteLength = Math.Min(8, originalPayload.Length);
        var originalLength = checked((ushort)(20 + 8 + Math.Min(originalPayload.Length, ushort.MaxValue - 28)));
        var original = new byte[20 + 8 + quoteLength];
        original[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(2, 2), originalLength);
        original[8] = 64;
        original[9] = PacketView.ProtocolUdp;
        clientAddress.GetAddressBytes().CopyTo(original.AsSpan(12, 4));
        remoteAddress.GetAddressBytes().CopyTo(original.AsSpan(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(
            original.AsSpan(10, 2),
            ComputeOnesComplement(original.AsSpan(0, 20)));
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(20, 2), clientPort);
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(22, 2), remotePort);
        BinaryPrimitives.WriteUInt16BigEndian(
            original.AsSpan(24, 2),
            (ushort)(8 + Math.Min(originalPayload.Length, ushort.MaxValue - 28)));
        originalPayload[..quoteLength].CopyTo(original.AsSpan(28));

        var icmp = new byte[8 + original.Length];
        icmp[0] = 3;
        icmp[1] = code;
        original.CopyTo(icmp, 8);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2, 2), ComputeOnesComplement(icmp));
        return icmp;
    }

    private static byte[] BuildIpv6IcmpError(
        IPAddress clientAddress,
        ushort clientPort,
        IPAddress remoteAddress,
        ushort remotePort,
        ReadOnlySpan<byte> originalPayload,
        byte code)
    {
        var quoteLength = Math.Min(8, originalPayload.Length);
        var original = new byte[40 + 8 + quoteLength];
        original[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(4, 2), (ushort)(8 + originalPayload.Length));
        original[6] = PacketView.ProtocolUdp;
        original[7] = 64;
        clientAddress.GetAddressBytes().CopyTo(original.AsSpan(8, 16));
        remoteAddress.GetAddressBytes().CopyTo(original.AsSpan(24, 16));
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(40, 2), clientPort);
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(42, 2), remotePort);
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(44, 2), (ushort)(8 + originalPayload.Length));
        originalPayload[..quoteLength].CopyTo(original.AsSpan(48));

        var icmp = new byte[8 + original.Length];
        icmp[0] = 1;
        icmp[1] = code;
        original.CopyTo(icmp, 8);
        var checksum = ComputeTransportChecksum(
            remoteAddress,
            clientAddress,
            58,
            icmp);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2, 2), checksum);
        return icmp;
    }

    private static byte MapIpv4IcmpCode(SocketError error)
    {
        return error switch
        {
            SocketError.ConnectionRefused => 3,
            SocketError.HostUnreachable => 1,
            SocketError.MessageSize => 4,
            _ => 0
        };
    }

    private static byte MapIpv6IcmpCode(SocketError error)
    {
        return error switch
        {
            SocketError.ConnectionRefused => 4,
            SocketError.HostUnreachable => 3,
            SocketError.MessageSize => 2,
            _ => 0
        };
    }

    private bool InjectFragmentedUdpResponse(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        IPAddress clientAddress,
        IPAddress remoteAddress,
        int linkHeaderLength,
        int ipHeaderLength,
        int maxDatagramDataLength,
        ReadOnlySpan<byte> payload)
    {
        var udpDatagram = new byte[8 + payload.Length];
        var success = true;
        BinaryPrimitives.WriteUInt16BigEndian(udpDatagram.AsSpan(0, 2), (ushort)remoteEndPoint.Port);
        BinaryPrimitives.WriteUInt16BigEndian(udpDatagram.AsSpan(2, 2), target.ClientPort);
        BinaryPrimitives.WriteUInt16BigEndian(udpDatagram.AsSpan(4, 2), checked((ushort)udpDatagram.Length));
        payload.CopyTo(udpDatagram.AsSpan(8));
        var checksum = ComputeUdpChecksum(remoteAddress, clientAddress, PacketView.ProtocolUdp, udpDatagram);
        BinaryPrimitives.WriteUInt16BigEndian(udpDatagram.AsSpan(6, 2), checksum);

        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            var maxFragmentData = Math.Max(8, maxDatagramDataLength & ~7);
            var identification = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
            var moreFragments = true;
            var offset = 0;
            while (moreFragments)
            {
                var fragmentLength = Math.Min(maxFragmentData, udpDatagram.Length - offset);
                moreFragments = offset + fragmentLength < udpDatagram.Length;
                var packetLength = linkHeaderLength + 20 + fragmentLength;
                var buffer = default(NdisApi.IntermediateBuffer);
                buffer.AdapterOrListFlink = target.AdapterHandle;
                buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
                buffer.Dot1q = target.Dot1q;
                buffer.Length = (uint)packetLength;
                var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
                frame[..packetLength].Clear();
                WriteInboundLinkHeader(frame, target, linkHeaderLength);
                BinaryPrimitives.WriteUInt16BigEndian(
                    frame.Slice(linkHeaderLength - 2, 2),
                    PacketView.EtherTypeIpv4);

                var ip = frame.Slice(linkHeaderLength, 20);
                ip[0] = 0x45;
                ip[1] = 0;
                BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)(20 + fragmentLength));
                BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), identification);
                BinaryPrimitives.WriteUInt16BigEndian(
                    ip.Slice(6, 2),
                    (ushort)((offset / 8) | (moreFragments ? 0x2000 : 0)));
                ip[8] = 64;
                ip[9] = PacketView.ProtocolUdp;
                remoteAddress.GetAddressBytes().CopyTo(ip.Slice(12, 4));
                clientAddress.GetAddressBytes().CopyTo(ip.Slice(16, 4));
                var ipChecksum = ComputeOnesComplement(ip);
                BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), ipChecksum);
                CopyIpv4UdpFragmentPayload(
                    frame,
                    linkHeaderLength,
                    udpDatagram.AsSpan(offset, fragmentLength));
                success &= SendInjectedUdpFragment(target, remoteEndPoint, &buffer);
                offset += fragmentLength;
            }

            return success;
        }

        var maxIpv6FragmentData = Math.Max(8, (maxDatagramDataLength - 8) & ~7);
        Span<byte> identificationBytes = stackalloc byte[4];
        RandomNumberGenerator.Fill(identificationBytes);
        var ipv6Identification = BinaryPrimitives.ReadUInt32BigEndian(identificationBytes);
        var ipv6MoreFragments = true;
        var ipv6Offset = 0;
        while (ipv6MoreFragments)
        {
            var fragmentLength = Math.Min(maxIpv6FragmentData, udpDatagram.Length - ipv6Offset);
            ipv6MoreFragments = ipv6Offset + fragmentLength < udpDatagram.Length;
            var packetLength = linkHeaderLength + 40 + 8 + fragmentLength;
            var buffer = default(NdisApi.IntermediateBuffer);
            buffer.AdapterOrListFlink = target.AdapterHandle;
            buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
            buffer.Dot1q = target.Dot1q;
            buffer.Length = (uint)packetLength;
            var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
            frame[..packetLength].Clear();
            WriteInboundLinkHeader(frame, target, linkHeaderLength);
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv6);

            var ipv6 = frame.Slice(linkHeaderLength, 40);
            ipv6[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(ipv6.Slice(4, 2), (ushort)(8 + fragmentLength));
            ipv6[6] = 44;
            ipv6[7] = 64;
            remoteAddress.GetAddressBytes().CopyTo(ipv6.Slice(8, 16));
            clientAddress.GetAddressBytes().CopyTo(ipv6.Slice(24, 16));

            var fragment = frame.Slice(linkHeaderLength + 40, 8);
            fragment[0] = PacketView.ProtocolUdp;
            BinaryPrimitives.WriteUInt16BigEndian(
                fragment.Slice(2, 2),
                (ushort)(((ipv6Offset / 8) << 3) | (ipv6MoreFragments ? 1 : 0)));
            BinaryPrimitives.WriteUInt32BigEndian(fragment.Slice(4, 4), ipv6Identification);
            udpDatagram.AsSpan(ipv6Offset, fragmentLength).CopyTo(frame.Slice(linkHeaderLength + 48));
            success &= SendInjectedUdpFragment(target, remoteEndPoint, &buffer);
            ipv6Offset += fragmentLength;
        }

        return success;
    }

    internal static void CopyIpv4UdpFragmentPayload(
        Span<byte> frame,
        int linkHeaderLength,
        ReadOnlySpan<byte> payload)
    {
        payload.CopyTo(frame.Slice(linkHeaderLength + 20, payload.Length));
    }

    private bool SendInjectedUdpFragment(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        NdisApi.IntermediateBuffer* buffer)
    {
        if (!SendInjectedPacketToMstcp(buffer))
        {
            _logDetail(
                $"UDP fragment SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint} length={buffer->Length} win32={NdisApi.LastWin32Error}",
                $"udp-fragment-send-failed:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        return true;
    }

    private bool SendInjectedPacketToMstcp(NdisApi.IntermediateBuffer* buffer)
    {
        var request = CreateRequest(buffer);
        if (!NdisApi.SendPacketToMstcp(_getDriverHandle(), ref request))
        {
            Interlocked.Increment(ref _mstcpSendFailed);
            return false;
        }

        Interlocked.Increment(ref _mstcpSendSucceeded);
        return true;
    }

    private static NdisApi.EthRequest CreateRequest(NdisApi.IntermediateBuffer* buffer)
    {
        return new NdisApi.EthRequest
        {
            AdapterHandle = buffer->AdapterOrListFlink,
            Buffer = (IntPtr)buffer
        };
    }

    private static void BuildIpv4UdpPacket(
        Span<byte> packet,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        ReadOnlySpan<byte> payload)
    {
        var totalLength = 20 + 8 + payload.Length;
        packet[0] = 0x45;
        packet[1] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(2, 2), (ushort)totalLength);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(4, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(6, 2), 0);
        packet[8] = 64;
        packet[9] = PacketView.ProtocolUdp;
        sourceAddress.GetAddressBytes().CopyTo(packet.Slice(12, 4));
        destinationAddress.GetAddressBytes().CopyTo(packet.Slice(16, 4));
        var ipChecksum = ComputeOnesComplement(packet[..20]);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(10, 2), ipChecksum);

        var udp = packet.Slice(20, 8 + payload.Length);
        BinaryPrimitives.WriteUInt16BigEndian(udp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(4, 2), (ushort)(8 + payload.Length));
        payload.CopyTo(udp[8..]);
        var checksum = ComputeUdpChecksum(sourceAddress, destinationAddress, PacketView.ProtocolUdp, udp);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(6, 2), checksum == 0 ? (ushort)0xFFFF : checksum);
    }

    private static void BuildIpv4TcpPacket(
        Span<byte> packet,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        uint sequenceNumber,
        uint acknowledgmentNumber,
        byte flags,
        ushort window,
        ushort urgentPointer,
        ReadOnlySpan<byte> options,
        ReadOnlySpan<byte> payload)
    {
        var tcpHeaderLength = 20 + options.Length;
        var totalLength = 20 + tcpHeaderLength + payload.Length;
        packet[0] = 0x45;
        packet[1] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(2, 2), (ushort)totalLength);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(4, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(6, 2), 0);
        packet[8] = 64;
        packet[9] = PacketView.ProtocolTcp;
        sourceAddress.GetAddressBytes().CopyTo(packet.Slice(12, 4));
        destinationAddress.GetAddressBytes().CopyTo(packet.Slice(16, 4));
        var ipChecksum = ComputeOnesComplement(packet[..20]);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(10, 2), ipChecksum);

        var tcp = packet.Slice(20, tcpHeaderLength + payload.Length);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(4, 4), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(8, 4), acknowledgmentNumber);
        tcp[12] = (byte)((tcpHeaderLength / 4) << 4);
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(14, 2), window);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(18, 2), urgentPointer);
        options.CopyTo(tcp.Slice(20, options.Length));
        payload.CopyTo(tcp.Slice(tcpHeaderLength));
        var checksum = ComputeTransportChecksum(sourceAddress, destinationAddress, PacketView.ProtocolTcp, tcp);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(16, 2), checksum);
    }

    private static void BuildIpv6UdpPacket(
        Span<byte> packet,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        ReadOnlySpan<byte> payload)
    {
        var payloadLength = 8 + payload.Length;
        packet[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(4, 2), (ushort)payloadLength);
        packet[6] = PacketView.ProtocolUdp;
        packet[7] = 64;
        sourceAddress.GetAddressBytes().CopyTo(packet.Slice(8, 16));
        destinationAddress.GetAddressBytes().CopyTo(packet.Slice(24, 16));

        var udp = packet.Slice(40, payloadLength);
        BinaryPrimitives.WriteUInt16BigEndian(udp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(4, 2), (ushort)payloadLength);
        payload.CopyTo(udp[8..]);
        var checksum = ComputeUdpChecksum(sourceAddress, destinationAddress, PacketView.ProtocolUdp, udp);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(6, 2), checksum == 0 ? (ushort)0xFFFF : checksum);
    }

    private static void BuildIpv6TcpPacket(
        Span<byte> packet,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        uint sequenceNumber,
        uint acknowledgmentNumber,
        byte flags,
        ushort window,
        ushort urgentPointer,
        ReadOnlySpan<byte> options,
        ReadOnlySpan<byte> payload)
    {
        var tcpHeaderLength = 20 + options.Length;
        var payloadLength = tcpHeaderLength + payload.Length;
        packet[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(4, 2), (ushort)payloadLength);
        packet[6] = PacketView.ProtocolTcp;
        packet[7] = 64;
        sourceAddress.GetAddressBytes().CopyTo(packet.Slice(8, 16));
        destinationAddress.GetAddressBytes().CopyTo(packet.Slice(24, 16));

        var tcp = packet.Slice(40, payloadLength);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(4, 4), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(8, 4), acknowledgmentNumber);
        tcp[12] = (byte)((tcpHeaderLength / 4) << 4);
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(14, 2), window);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(18, 2), urgentPointer);
        options.CopyTo(tcp.Slice(20, options.Length));
        payload.CopyTo(tcp.Slice(tcpHeaderLength));
        var checksum = ComputeTransportChecksum(sourceAddress, destinationAddress, PacketView.ProtocolTcp, tcp);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(16, 2), checksum);
    }

    private static ushort ComputeUdpChecksum(
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        byte protocol,
        ReadOnlySpan<byte> udpDatagram)
    {
        var checksum = ComputeTransportChecksum(sourceAddress, destinationAddress, protocol, udpDatagram);
        return checksum == 0 ? (ushort)0xFFFF : checksum;
    }

    private static ushort ComputeTransportChecksum(
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        byte protocol,
        ReadOnlySpan<byte> datagram)
    {
        uint sum = 0;
        var sourceBytes = sourceAddress.GetAddressBytes();
        var destinationBytes = destinationAddress.GetAddressBytes();
        sum = AddChecksumBytes(sum, sourceBytes);
        sum = AddChecksumBytes(sum, destinationBytes);
        if (sourceAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            sum += protocol;
            sum += (uint)datagram.Length;
        }
        else
        {
            sum += (uint)(datagram.Length >> 16);
            sum += (uint)(datagram.Length & 0xFFFF);
            sum += protocol;
        }

        sum = AddChecksumBytes(sum, datagram);
        return FoldChecksum(sum);
    }

    private static ushort ComputeOnesComplement(ReadOnlySpan<byte> data)
    {
        return FoldChecksum(AddChecksumBytes(0, data));
    }

    private static uint AddChecksumBytes(uint sum, ReadOnlySpan<byte> data)
    {
        var i = 0;
        for (; i + 1 < data.Length; i += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
        }

        if (i < data.Length)
        {
            sum += (uint)(data[i] << 8);
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

    private static string FormatTcpFlags(byte flags)
    {
        Span<char> chars = stackalloc char[8];
        var index = 0;
        if ((flags & 0x01) != 0) chars[index++] = 'F';
        if ((flags & 0x02) != 0) chars[index++] = 'S';
        if ((flags & 0x04) != 0) chars[index++] = 'R';
        if ((flags & 0x08) != 0) chars[index++] = 'P';
        if ((flags & 0x10) != 0) chars[index++] = 'A';
        if ((flags & 0x20) != 0) chars[index++] = 'U';
        if ((flags & 0x40) != 0) chars[index++] = 'E';
        if ((flags & 0x80) != 0) chars[index++] = 'C';
        return index == 0 ? "none" : new string(chars[..index]);
    }
}
