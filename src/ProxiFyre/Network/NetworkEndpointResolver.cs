using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ProxiFyre;

internal static class NetworkEndpointResolver
{
    public static IPEndPoint? CreateBindEndPoint(DirectRelayTarget target)
    {
        if (target.ClientAddress is null)
        {
            return null;
        }

        var address = AddScopeIfNeeded(
            NetworkAddress.Normalize(target.ClientAddress),
            target.ClientAddress,
            target.InterfaceIndex);
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return null;
        }

        return new IPEndPoint(address, 0);
    }

    public static IPEndPoint CreateRemoteEndPoint(DirectRelayTarget target)
    {
        var remoteAddress = ResolveRemoteAddress(
            target.RemoteAddress,
            target.ClientAddress,
            target.InterfaceIndex);
        return new IPEndPoint(remoteAddress, target.RemotePort);
    }

    public static IPEndPoint CreateRemoteEndPoint(DirectRelayTarget target, IPAddress remoteAddress, ushort remotePort)
    {
        return new IPEndPoint(
            ResolveRemoteAddress(remoteAddress, target.ClientAddress, target.InterfaceIndex),
            remotePort);
    }

    public static IPEndPoint CreateAnyEndPoint(AddressFamily addressFamily)
    {
        return addressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(IPAddress.Any, 0)
            : new IPEndPoint(IPAddress.IPv6Any, 0);
    }

    private static IPAddress ResolveRemoteAddress(
        IPAddress remoteAddress,
        IPAddress? clientAddress,
        int interfaceIndex)
    {
        remoteAddress = NetworkAddress.Normalize(remoteAddress);
        if (remoteAddress.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return remoteAddress;
        }

        return AddScopeIfNeeded(remoteAddress, clientAddress, interfaceIndex);
    }

    private static IPAddress AddScopeIfNeeded(
        IPAddress address,
        IPAddress? scopeSource,
        int interfaceIndex)
    {
        if (address.AddressFamily != AddressFamily.InterNetworkV6 || address.ScopeId != 0 || !NeedsScopeId(address))
        {
            return address;
        }

        var scopeId = interfaceIndex > 0
            ? interfaceIndex
            : FindScopeId(scopeSource) ?? FindScopeId(address);
        return scopeId is > 0
            ? new IPAddress(address.GetAddressBytes(), scopeId.Value)
            : address;
    }

    private static bool NeedsScopeId(IPAddress address)
    {
        return address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal;
    }

    private static long? FindScopeId(IPAddress? address)
    {
        if (address is null || address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return null;
        }

        if (address.ScopeId != 0)
        {
            return address.ScopeId;
        }

        var addressBytes = address.GetAddressBytes();
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            var properties = networkInterface.GetIPProperties();
            foreach (var unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    continue;
                }

                if (!unicast.Address.GetAddressBytes().SequenceEqual(addressBytes))
                {
                    continue;
                }

                if (unicast.Address.ScopeId != 0)
                {
                    return unicast.Address.ScopeId;
                }

                if (NetworkInterfaceIndexResolver.TryGetIndex(networkInterface, out var index))
                {
                    return index;
                }
            }
        }

        return null;
    }
}
