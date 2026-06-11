using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal ref struct PacketView
{
    public const int EthernetHeaderLength = 14;
    public const ushort EtherTypeIpv4 = 0x0800;
    public const ushort EtherTypeIpv6 = 0x86DD;
    public const byte ProtocolTcp = 6;
    public const byte ProtocolUdp = 17;
    public const byte TcpFlagFin = 0x01;
    public const byte TcpFlagSyn = 0x02;
    public const byte TcpFlagRst = 0x04;
    public const byte TcpFlagAck = 0x10;

    private readonly Span<byte> _frame;
    private readonly int _sourceAddressOffset;
    private readonly int _destinationAddressOffset;

    private PacketView(
        Span<byte> frame,
        int packetLength,
        AddressFamily addressFamily,
        byte protocol,
        int ipOffset,
        int ipHeaderLength,
        int transportOffset,
        int transportLength,
        int sourceAddressOffset,
        int destinationAddressOffset)
    {
        _frame = frame;
        PacketLength = packetLength;
        AddressFamily = addressFamily;
        Protocol = protocol;
        IpOffset = ipOffset;
        IpHeaderLength = ipHeaderLength;
        TransportOffset = transportOffset;
        TransportLength = transportLength;
        _sourceAddressOffset = sourceAddressOffset;
        _destinationAddressOffset = destinationAddressOffset;
    }

    public int PacketLength { get; private set; }

    public AddressFamily AddressFamily { get; }

    public byte Protocol { get; }

    public int IpOffset { get; }

    public int IpHeaderLength { get; }

    public int TransportOffset { get; }

    public int TransportLength { get; private set; }

    public bool IsTcp => Protocol == ProtocolTcp;

    public bool IsUdp => Protocol == ProtocolUdp;

    public IPAddress SourceAddress
    {
        get => ReadAddress(_sourceAddressOffset);
        set => WriteAddress(_sourceAddressOffset, value);
    }

    public IPAddress DestinationAddress
    {
        get => ReadAddress(_destinationAddressOffset);
        set => WriteAddress(_destinationAddressOffset, value);
    }

    public ushort SourcePort
    {
        get => BinaryPrimitives.ReadUInt16BigEndian(_frame.Slice(TransportOffset, 2));
        set => BinaryPrimitives.WriteUInt16BigEndian(_frame.Slice(TransportOffset, 2), value);
    }

    public ushort DestinationPort
    {
        get => BinaryPrimitives.ReadUInt16BigEndian(_frame.Slice(TransportOffset + 2, 2));
        set => BinaryPrimitives.WriteUInt16BigEndian(_frame.Slice(TransportOffset + 2, 2), value);
    }

    public byte TcpFlags => IsTcp ? _frame[TransportOffset + 13] : (byte)0;

    public int TcpHeaderLength => IsTcp ? (_frame[TransportOffset + 12] >> 4) * 4 : 0;

    public int TcpPayloadLength => IsTcp ? Math.Max(0, TransportLength - TcpHeaderLength) : 0;

    public bool IsSynOnly => IsTcp && (TcpFlags & (TcpFlagSyn | TcpFlagAck)) == TcpFlagSyn;

    public bool IsClosing => IsTcp && (TcpFlags & (TcpFlagFin | TcpFlagRst)) != 0;

    public TcpSessionKey Session => new(SourceAddress, DestinationAddress, SourcePort, DestinationPort);

    public UdpEndpointKey UdpEndpoint => new(SourceAddress, SourcePort);

    public TcpClientKey ClientKey => new(SourceAddress, SourcePort);

    public TcpClientKey DestinationClientKey => new(DestinationAddress, DestinationPort);

    public ReadOnlySpan<byte> UdpPayload
    {
        get
        {
            if (!IsUdp || TransportLength < 8)
            {
                return [];
            }

            return _frame.Slice(TransportOffset + 8, TransportLength - 8);
        }
    }

    public static bool TryParse(Span<byte> frame, int packetLength, out PacketView packet)
    {
        packet = default;

        if (packetLength < EthernetHeaderLength + 20 || frame.Length < packetLength)
        {
            return false;
        }

        var etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(12, 2));
        return etherType switch
        {
            EtherTypeIpv4 => TryParseIpv4(frame, packetLength, out packet),
            EtherTypeIpv6 => TryParseIpv6(frame, packetLength, out packet),
            _ => false
        };
    }

    public void SwapEthernetAddresses()
    {
        for (var i = 0; i < 6; i++)
        {
            (_frame[i], _frame[6 + i]) = (_frame[6 + i], _frame[i]);
        }
    }

    public void SwapIpAddresses()
    {
        var addressLength = AddressFamily == AddressFamily.InterNetwork ? 4 : 16;
        for (var i = 0; i < addressLength; i++)
        {
            (_frame[_sourceAddressOffset + i], _frame[_destinationAddressOffset + i]) =
                (_frame[_destinationAddressOffset + i], _frame[_sourceAddressOffset + i]);
        }
    }

    public bool TryPrependUdpPayload(ReadOnlySpan<byte> prefix)
    {
        if (!IsUdp || prefix.Length == 0)
        {
            return false;
        }

        if (PacketLength + prefix.Length > _frame.Length)
        {
            return false;
        }

        var payloadOffset = TransportOffset + 8;
        var payloadLength = TransportLength - 8;
        _frame.Slice(payloadOffset, payloadLength).CopyTo(_frame.Slice(payloadOffset + prefix.Length, payloadLength));
        prefix.CopyTo(_frame.Slice(payloadOffset, prefix.Length));

        PacketLength += prefix.Length;
        TransportLength += prefix.Length;
        WritePacketLengths();
        return true;
    }

    public bool TryRemoveUdpPayloadPrefix(int prefixLength)
    {
        if (!IsUdp || prefixLength <= 0 || TransportLength < 8 + prefixLength)
        {
            return false;
        }

        var payloadOffset = TransportOffset + 8;
        var remainingPayloadLength = TransportLength - 8 - prefixLength;
        _frame.Slice(payloadOffset + prefixLength, remainingPayloadLength)
            .CopyTo(_frame.Slice(payloadOffset, remainingPayloadLength));

        PacketLength -= prefixLength;
        TransportLength -= prefixLength;
        WritePacketLengths();
        return true;
    }

    public void RecalculateChecksums()
    {
        if (AddressFamily == AddressFamily.InterNetwork)
        {
            RecalculateIpv4HeaderChecksum();
        }

        RecalculateTransportChecksum();
    }

    private static bool TryParseIpv4(Span<byte> frame, int packetLength, out PacketView packet)
    {
        packet = default;
        var ipOffset = EthernetHeaderLength;
        var version = frame[ipOffset] >> 4;
        var ipHeaderLength = (frame[ipOffset] & 0x0F) * 4;
        if (version != 4 || ipHeaderLength < 20 || packetLength < ipOffset + ipHeaderLength)
        {
            return false;
        }

        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ipOffset + 2, 2));
        if (totalLength < ipHeaderLength || packetLength < ipOffset + totalLength)
        {
            return false;
        }

        var fragment = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ipOffset + 6, 2));
        if ((fragment & 0x3FFF) != 0)
        {
            return false;
        }

        var protocol = frame[ipOffset + 9];
        if (protocol is not (ProtocolTcp or ProtocolUdp))
        {
            return false;
        }

        var transportOffset = ipOffset + ipHeaderLength;
        var transportLength = totalLength - ipHeaderLength;
        if (!ValidateTransport(frame, transportOffset, transportLength, protocol))
        {
            return false;
        }

        packet = new PacketView(
            frame,
            ipOffset + totalLength,
            AddressFamily.InterNetwork,
            protocol,
            ipOffset,
            ipHeaderLength,
            transportOffset,
            transportLength,
            ipOffset + 12,
            ipOffset + 16);
        return true;
    }

    private static bool TryParseIpv6(Span<byte> frame, int packetLength, out PacketView packet)
    {
        packet = default;
        var ipOffset = EthernetHeaderLength;
        if (packetLength < ipOffset + 40 || frame[ipOffset] >> 4 != 6)
        {
            return false;
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ipOffset + 4, 2));
        var ipv6PacketLength = 40 + payloadLength;
        if (packetLength < ipOffset + ipv6PacketLength)
        {
            return false;
        }

        var nextHeader = frame[ipOffset + 6];
        var currentOffset = ipOffset + 40;
        var bytesRemaining = payloadLength;

        while (true)
        {
            if (nextHeader is ProtocolTcp or ProtocolUdp)
            {
                if (!ValidateTransport(frame, currentOffset, bytesRemaining, nextHeader))
                {
                    return false;
                }

                packet = new PacketView(
                    frame,
                    ipOffset + ipv6PacketLength,
                    AddressFamily.InterNetworkV6,
                    nextHeader,
                    ipOffset,
                    40,
                    currentOffset,
                    bytesRemaining,
                    ipOffset + 8,
                    ipOffset + 24);
                return true;
            }

            if (nextHeader == 44)
            {
                return false;
            }

            if (nextHeader is not (0 or 43 or 60))
            {
                return false;
            }

            if (bytesRemaining < 8)
            {
                return false;
            }

            var extensionLength = (frame[currentOffset + 1] + 1) * 8;
            if (bytesRemaining < extensionLength)
            {
                return false;
            }

            nextHeader = frame[currentOffset];
            currentOffset += extensionLength;
            bytesRemaining = (ushort)(bytesRemaining - extensionLength);
        }
    }

    private static bool ValidateTransport(Span<byte> frame, int transportOffset, int transportLength, byte protocol)
    {
        if (protocol == ProtocolTcp)
        {
            if (transportLength < 20 || frame.Length < transportOffset + 20)
            {
                return false;
            }

            var tcpHeaderLength = (frame[transportOffset + 12] >> 4) * 4;
            return tcpHeaderLength >= 20 && transportLength >= tcpHeaderLength;
        }

        if (protocol == ProtocolUdp)
        {
            if (transportLength < 8 || frame.Length < transportOffset + 8)
            {
                return false;
            }

            var udpLength = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(transportOffset + 4, 2));
            return udpLength >= 8 && udpLength <= transportLength;
        }

        return false;
    }

    private IPAddress ReadAddress(int offset)
    {
        return AddressFamily == AddressFamily.InterNetwork
            ? new IPAddress(_frame.Slice(offset, 4))
            : new IPAddress(_frame.Slice(offset, 16));
    }

    private void WriteAddress(int offset, IPAddress address)
    {
        address = NetworkAddress.Normalize(address);

        if (AddressFamily == AddressFamily.InterNetwork && address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            address = address.MapToIPv4();
        }
        else if (AddressFamily == AddressFamily.InterNetworkV6 && address.AddressFamily == AddressFamily.InterNetwork)
        {
            address = address.MapToIPv6();
        }

        address.GetAddressBytes().CopyTo(_frame.Slice(offset, AddressFamily == AddressFamily.InterNetwork ? 4 : 16));
    }

    private void WritePacketLengths()
    {
        if (AddressFamily == AddressFamily.InterNetwork)
        {
            BinaryPrimitives.WriteUInt16BigEndian(_frame.Slice(IpOffset + 2, 2), (ushort)(PacketLength - EthernetHeaderLength));
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(_frame.Slice(IpOffset + 4, 2), (ushort)(PacketLength - EthernetHeaderLength - 40));
        }

        if (IsUdp)
        {
            BinaryPrimitives.WriteUInt16BigEndian(_frame.Slice(TransportOffset + 4, 2), (ushort)TransportLength);
        }
    }

    private void RecalculateIpv4HeaderChecksum()
    {
        _frame[IpOffset + 10] = 0;
        _frame[IpOffset + 11] = 0;
        var checksum = ComputeOnesComplement(_frame.Slice(IpOffset, IpHeaderLength));
        BinaryPrimitives.WriteUInt16BigEndian(_frame.Slice(IpOffset + 10, 2), checksum);
    }

    private void RecalculateTransportChecksum()
    {
        var checksumOffset = IsTcp ? TransportOffset + 16 : TransportOffset + 6;
        _frame[checksumOffset] = 0;
        _frame[checksumOffset + 1] = 0;

        uint sum = 0;
        if (AddressFamily == AddressFamily.InterNetwork)
        {
            sum = AddBytes(sum, _frame.Slice(_sourceAddressOffset, 4));
            sum = AddBytes(sum, _frame.Slice(_destinationAddressOffset, 4));
            sum += Protocol;
            sum += (uint)TransportLength;
        }
        else
        {
            sum = AddBytes(sum, _frame.Slice(_sourceAddressOffset, 16));
            sum = AddBytes(sum, _frame.Slice(_destinationAddressOffset, 16));
            sum += (uint)(TransportLength >> 16);
            sum += (uint)(TransportLength & 0xFFFF);
            sum += Protocol;
        }

        sum = AddBytes(sum, _frame.Slice(TransportOffset, TransportLength));
        var checksum = FoldChecksum(sum);
        if (IsUdp && checksum == 0)
        {
            checksum = 0xFFFF;
        }

        BinaryPrimitives.WriteUInt16BigEndian(_frame.Slice(checksumOffset, 2), checksum);
    }

    private static ushort ComputeOnesComplement(ReadOnlySpan<byte> data)
    {
        return FoldChecksum(AddBytes(0, data));
    }

    private static uint AddBytes(uint sum, ReadOnlySpan<byte> data)
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
}
