using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal static class NetworkAddress
{
    public static IPAddress Normalize(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
        {
            return new IPAddress(address.GetAddressBytes());
        }

        return address;
    }
}

internal readonly record struct TcpSessionKey
{
    public TcpSessionKey(IPAddress localAddress, IPAddress remoteAddress, ushort localPort, ushort remotePort)
    {
        LocalAddress = NetworkAddress.Normalize(localAddress);
        RemoteAddress = NetworkAddress.Normalize(remoteAddress);
        LocalPort = localPort;
        RemotePort = remotePort;
    }

    public IPAddress LocalAddress { get; }

    public IPAddress RemoteAddress { get; }

    public ushort LocalPort { get; }

    public ushort RemotePort { get; }

    public override string ToString()
    {
        return $"{LocalAddress}:{LocalPort} -> {RemoteAddress}:{RemotePort}";
    }
}

internal readonly record struct UdpEndpointKey
{
    public UdpEndpointKey(IPAddress localAddress, ushort localPort)
    {
        LocalAddress = NetworkAddress.Normalize(localAddress);
        LocalPort = localPort;
    }

    public IPAddress LocalAddress { get; }

    public ushort LocalPort { get; }
}

internal readonly record struct UdpRelayKey
{
    public UdpRelayKey(
        IntPtr adapterHandle,
        uint dot1q,
        IPAddress clientAddress,
        ushort clientPort,
        IPAddress remoteAddress,
        ushort remotePort)
    {
        AdapterHandle = adapterHandle;
        Dot1q = dot1q;
        ClientAddress = NetworkAddress.Normalize(clientAddress);
        ClientPort = clientPort;
        RemoteAddress = NetworkAddress.Normalize(remoteAddress);
        RemotePort = remotePort;
    }

    public IntPtr AdapterHandle { get; }

    public uint Dot1q { get; }

    public IPAddress ClientAddress { get; }

    public ushort ClientPort { get; }

    public IPAddress RemoteAddress { get; }

    public ushort RemotePort { get; }
}

internal readonly record struct TcpClientKey
{
    public TcpClientKey(IPAddress clientAddress, ushort clientPort)
    {
        ClientAddress = NetworkAddress.Normalize(clientAddress);
        ClientPort = clientPort;
    }

    public IPAddress ClientAddress { get; }

    public ushort ClientPort { get; }
}

internal readonly record struct TcpRelayKey
{
    public TcpRelayKey(
        IntPtr adapterHandle,
        IPAddress clientAddress,
        IPAddress remoteAddress,
        ushort clientPort,
        ushort remotePort)
    {
        AdapterHandle = adapterHandle;
        ClientAddress = NetworkAddress.Normalize(clientAddress);
        RemoteAddress = NetworkAddress.Normalize(remoteAddress);
        ClientPort = clientPort;
        RemotePort = remotePort;
    }

    public IPAddress ClientAddress { get; }

    public IPAddress RemoteAddress { get; }

    public ushort ClientPort { get; }

    public ushort RemotePort { get; }

    public IntPtr AdapterHandle { get; }

    public override string ToString()
    {
        return $"{ClientAddress}:{ClientPort} -> {RemoteAddress}:{RemotePort}";
    }
}

internal readonly record struct RelayOutboundFlow
{
    public RelayOutboundFlow(IntPtr adapterHandle, byte protocol, IPAddress localAddress, IPAddress remoteAddress, ushort localPort, ushort remotePort)
    {
        AdapterHandle = adapterHandle;
        Protocol = protocol;
        LocalAddress = NetworkAddress.Normalize(localAddress);
        RemoteAddress = NetworkAddress.Normalize(remoteAddress);
        LocalPort = localPort;
        RemotePort = remotePort;
    }

    public IntPtr AdapterHandle { get; }

    public byte Protocol { get; }

    public IPAddress LocalAddress { get; }

    public IPAddress RemoteAddress { get; }

    public ushort LocalPort { get; }

    public ushort RemotePort { get; }

    public override string ToString()
    {
        var protocol = Protocol == PacketView.ProtocolTcp
            ? "TCP"
            : Protocol == PacketView.ProtocolUdp ? "UDP" : Protocol.ToString();
        return $"{protocol} local={LocalAddress}:{LocalPort} -> {RemoteAddress}:{RemotePort} adapter=0x{AdapterHandle.ToInt64():X}";
    }
}

internal sealed record DirectRelayTarget(
    IPAddress RemoteAddress,
    ushort RemotePort,
    DateTimeOffset CreatedAt,
    int ProcessId = 0,
    string ProcessName = "",
    string ProcessPath = "",
    string MatchedPattern = "",
    IPAddress? ClientAddress = null,
    ushort ClientPort = 0,
    IntPtr AdapterHandle = default,
    byte[]? LinkHeader = null,
    byte[]? InboundEthernetSource = null,
    byte[]? InboundEthernetDestination = null,
    int AdapterMtu = 1500,
    uint Dot1q = 0,
    int InterfaceIndex = 0)
{
    public string AppLabel => ProcessId > 0
        ? $"{ProcessName} pid={ProcessId} pattern={MatchedPattern}"
        : "unknown-app";

    public string RemoteEndpoint => $"{NetworkAddress.Normalize(RemoteAddress)}:{RemotePort}";

    public string ClientEndpoint => ClientAddress is null
        ? "unknown-client"
        : $"{NetworkAddress.Normalize(ClientAddress)}:{ClientPort}";

    public override string ToString() => $"{NetworkAddress.Normalize(RemoteAddress)}:{RemotePort}";
}
