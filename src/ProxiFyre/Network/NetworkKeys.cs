using System.Net;

namespace ProxiFyre;

internal static class NetworkAddress
{
    public static IPAddress Normalize(IPAddress address)
    {
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
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

internal sealed record DirectRelayTarget(IPAddress RemoteAddress, ushort RemotePort, DateTimeOffset CreatedAt)
{
    public override string ToString() => $"{NetworkAddress.Normalize(RemoteAddress)}:{RemotePort}";
}
