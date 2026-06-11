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
    public UdpRelayKey(IPAddress clientAddress, ushort clientPort, IPAddress remoteAddress, ushort remotePort)
    {
        ClientAddress = NetworkAddress.Normalize(clientAddress);
        ClientPort = clientPort;
        RemoteAddress = NetworkAddress.Normalize(remoteAddress);
        RemotePort = remotePort;
    }

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
    public TcpRelayKey(IPAddress remoteAddress, ushort clientPort, ushort remotePort)
    {
        RemoteAddress = NetworkAddress.Normalize(remoteAddress);
        ClientPort = clientPort;
        RemotePort = remotePort;
    }

    public IPAddress RemoteAddress { get; }

    public ushort ClientPort { get; }

    public ushort RemotePort { get; }
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
    ushort ClientPort = 0)
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
