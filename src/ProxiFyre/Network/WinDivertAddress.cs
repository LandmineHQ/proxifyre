using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ProxiFyre;

internal enum WinDivertLayer
{
    Network = 0,
    Forward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4
}

internal enum WinDivertEvent
{
    NetworkPacket = 0,
    FlowEstablished = 1,
    FlowDeleted = 2,
    SocketBind = 3,
    SocketConnect = 4,
    SocketListen = 5,
    SocketAccept = 6,
    SocketClose = 7,
    ReflectOpen = 8,
    ReflectClose = 9
}

[StructLayout(LayoutKind.Explicit, Size = 80)]
internal struct WinDivertAddress
{
    private const uint LayerMask = 0x000000FF;
    private const int LayerShift = 0;
    private const uint EventMask = 0x0000FF00;
    private const int EventShift = 8;
    private const uint SniffedBit = 1u << 16;
    private const uint OutboundBit = 1u << 17;
    private const uint LoopbackBit = 1u << 18;
    private const uint ImpostorBit = 1u << 19;
    private const uint Ipv6Bit = 1u << 20;
    private const uint IpChecksumBit = 1u << 21;
    private const uint TcpChecksumBit = 1u << 22;
    private const uint UdpChecksumBit = 1u << 23;

    [FieldOffset(0)]
    private long _timestamp;

    [FieldOffset(8)]
    private uint _flags;

    [FieldOffset(12)]
    private uint _reserved2;

    [FieldOffset(16)]
    private uint _networkInterfaceIndex;

    [FieldOffset(20)]
    private uint _networkSubInterfaceIndex;

    [FieldOffset(16)]
    private ulong _endpointId;

    [FieldOffset(24)]
    private ulong _parentEndpointId;

    [FieldOffset(32)]
    private uint _processId;

    [FieldOffset(36)]
    private uint _localAddress0;

    [FieldOffset(40)]
    private uint _localAddress1;

    [FieldOffset(44)]
    private uint _localAddress2;

    [FieldOffset(48)]
    private uint _localAddress3;

    [FieldOffset(52)]
    private uint _remoteAddress0;

    [FieldOffset(56)]
    private uint _remoteAddress1;

    [FieldOffset(60)]
    private uint _remoteAddress2;

    [FieldOffset(64)]
    private uint _remoteAddress3;

    [FieldOffset(68)]
    private ushort _localPort;

    [FieldOffset(70)]
    private ushort _remotePort;

    [FieldOffset(72)]
    private byte _protocol;

    public WinDivertLayer Layer => (WinDivertLayer)(_flags & LayerMask);

    public WinDivertEvent Event => (WinDivertEvent)((_flags & EventMask) >> EventShift);

    public bool IsSniffed => (_flags & SniffedBit) != 0;

    public bool IsOutbound
    {
        get => (_flags & OutboundBit) != 0;
        set => _flags = value ? _flags | OutboundBit : _flags & ~OutboundBit;
    }

    public bool IsLoopback => (_flags & LoopbackBit) != 0;

    public bool IsImpostor
    {
        get => (_flags & ImpostorBit) != 0;
        set => _flags = value ? _flags | ImpostorBit : _flags & ~ImpostorBit;
    }

    public bool IsIpv6 => (_flags & Ipv6Bit) != 0;

    public long Timestamp => _timestamp;

    public uint NetworkInterfaceIndex
    {
        get => _networkInterfaceIndex;
        set => _networkInterfaceIndex = value;
    }

    public uint NetworkSubInterfaceIndex
    {
        get => _networkSubInterfaceIndex;
        set => _networkSubInterfaceIndex = value;
    }

    public ulong EndpointId => _endpointId;

    public ulong ParentEndpointId => _parentEndpointId;

    public uint ProcessId => _processId;

    public IPAddress LocalAddress => ReadAddress(
        _localAddress0,
        _localAddress1,
        _localAddress2,
        _localAddress3);

    public IPAddress RemoteAddress => ReadAddress(
        _remoteAddress0,
        _remoteAddress1,
        _remoteAddress2,
        _remoteAddress3);

    public ushort LocalPort => _localPort;

    public ushort RemotePort => _remotePort;

    public byte Protocol => _protocol;

    public static WinDivertAddress CreateInbound(
        uint interfaceIndex,
        uint subInterfaceIndex,
        bool ipv6)
    {
        var address = new WinDivertAddress
        {
            _flags = (uint)WinDivertLayer.Network
                | ((uint)WinDivertEvent.NetworkPacket << EventShift)
                | (ipv6 ? Ipv6Bit : 0),
            _networkInterfaceIndex = interfaceIndex,
            _networkSubInterfaceIndex = subInterfaceIndex
        };
        return address;
    }

    private static IPAddress ReadAddress(uint value0, uint value1, uint value2, uint value3)
    {
        Span<byte> bytes = stackalloc byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes[..4], value0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.Slice(4, 4), value1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.Slice(8, 4), value2);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.Slice(12, 4), value3);
        var address = new IPAddress(bytes);
        return NetworkAddress.Normalize(address);
    }
}
