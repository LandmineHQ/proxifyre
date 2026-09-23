using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ProxiFyre;

internal static class NetworkInterfaceIndexResolver
{
    private const int MaxCachedAddresses = 4096;
    private static readonly TimeSpan PositiveCacheTtl = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan NegativeCacheTtl = TimeSpan.FromSeconds(1);
    private static readonly ConcurrentDictionary<IPAddress, CachedInterfaceIndex> LocalAddressIndexCache = new();
    private static readonly ConcurrentDictionary<IPAddress, CachedInterfaceIndex> BestInterfaceIndexCache = new();
    private static readonly ConcurrentDictionary<MtuCacheKey, CachedMtu> MtuCache = new();

    public static int FindAdapterIndex(string adapterName, ReadOnlySpan<byte> macAddress)
    {
        if (string.IsNullOrWhiteSpace(adapterName))
        {
            return 0;
        }

        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!MatchesAdapter(networkInterface, adapterName, macAddress))
            {
                continue;
            }

            if (TryGetIndex(networkInterface, out var index))
            {
                return index;
            }
        }

        return 0;
    }

    public static bool TryGetIndex(NetworkInterface networkInterface, out int index)
    {
        try
        {
            var properties = networkInterface.GetIPProperties();
            if (TryReadIndex(() => properties.GetIPv4Properties().Index, out index))
            {
                return true;
            }

            return TryReadIndex(() => properties.GetIPv6Properties().Index, out index);
        }
        catch (NetworkInformationException)
        {
            index = 0;
            return false;
        }
    }

    public static bool TryGetMtu(int interfaceIndex, AddressFamily addressFamily, out int mtu)
    {
        mtu = 0;
        if (interfaceIndex <= 0)
        {
            return false;
        }

        var key = new MtuCacheKey(interfaceIndex, addressFamily);
        if (MtuCache.TryGetValue(key, out var cached)
            && Environment.TickCount64 < cached.ExpiresAt)
        {
            mtu = cached.Mtu;
            return mtu > 0;
        }

        MtuCache.TryRemove(key, out _);
        var resolvedMtu = TryGetMtuCore(interfaceIndex, addressFamily);
        var ttl = resolvedMtu > 0 ? PositiveCacheTtl : NegativeCacheTtl;
        MtuCache[key] = new CachedMtu(
            resolvedMtu,
            Environment.TickCount64 + (long)ttl.TotalMilliseconds);
        mtu = resolvedMtu;
        return mtu > 0;
    }

    public static void PrimeMtuCache()
    {
        try
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (TryGetIndex(networkInterface, out var interfaceIndex))
                {
                    _ = TryGetMtu(interfaceIndex, AddressFamily.InterNetwork, out _);
                    _ = TryGetMtu(interfaceIndex, AddressFamily.InterNetworkV6, out _);
                }
            }
        }
        catch (NetworkInformationException)
        {
        }
    }

    private static int TryGetMtuCore(int interfaceIndex, AddressFamily addressFamily)
    {
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!TryGetIndex(networkInterface, out var index) || index != interfaceIndex)
            {
                continue;
            }

            IPInterfaceProperties properties;
            try
            {
                properties = networkInterface.GetIPProperties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            if (addressFamily == AddressFamily.InterNetwork)
            {
                try
                {
                    var mtu = properties.GetIPv4Properties()?.Mtu ?? 0;
                    if (mtu > 0)
                    {
                        return mtu;
                    }
                }
                catch (NetworkInformationException)
                {
                }

                try
                {
                    return properties.GetIPv6Properties()?.Mtu ?? 0;
                }
                catch (NetworkInformationException)
                {
                    return 0;
                }
            }

            try
            {
                var mtu = properties.GetIPv6Properties()?.Mtu ?? 0;
                if (mtu > 0)
                {
                    return mtu;
                }
            }
            catch (NetworkInformationException)
            {
            }

            try
            {
                return properties.GetIPv4Properties()?.Mtu ?? 0;
            }
            catch (NetworkInformationException)
            {
                return 0;
            }
        }

        return 0;
    }

    public static int FindBestInterfaceIndex(IPAddress remoteAddress)
    {
        remoteAddress = NetworkAddress.Normalize(remoteAddress);
        if (TryGetCachedIndex(BestInterfaceIndexCache, remoteAddress, out var cached))
        {
            return cached;
        }

        var socketAddress = CreateSocketAddress(remoteAddress);
        var resolved = GetBestInterfaceEx(socketAddress, out var interfaceIndex) == 0
            ? checked((int)interfaceIndex)
            : 0;
        StoreCachedIndex(BestInterfaceIndexCache, remoteAddress, resolved);
        return resolved;
    }

    public static int FindInterfaceIndexForLocalAddress(IPAddress localAddress)
    {
        localAddress = NetworkAddress.Normalize(localAddress);
        if (TryGetCachedIndex(LocalAddressIndexCache, localAddress, out var cached))
        {
            return cached;
        }

        var resolved = FindInterfaceIndexForLocalAddressCore(localAddress);
        StoreCachedIndex(LocalAddressIndexCache, localAddress, resolved);
        return resolved;
    }

    private static int FindInterfaceIndexForLocalAddressCore(IPAddress localAddress)
    {
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            IPInterfaceProperties properties;
            try
            {
                properties = networkInterface.GetIPProperties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            foreach (var unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != localAddress.AddressFamily
                    || !unicast.Address.GetAddressBytes().AsSpan()
                        .SequenceEqual(localAddress.GetAddressBytes()))
                {
                    continue;
                }

                if (TryGetIndex(networkInterface, out var index))
                {
                    return index;
                }
            }
        }

        return 0;
    }

    private static bool TryGetCachedIndex(
        ConcurrentDictionary<IPAddress, CachedInterfaceIndex> cache,
        IPAddress address,
        out int index)
    {
        if (cache.TryGetValue(address, out var cached)
            && Environment.TickCount64 < cached.ExpiresAt)
        {
            index = cached.Index;
            return true;
        }

        cache.TryRemove(address, out _);
        index = 0;
        return false;
    }

    private static void StoreCachedIndex(
        ConcurrentDictionary<IPAddress, CachedInterfaceIndex> cache,
        IPAddress address,
        int index)
    {
        if (cache.Count >= MaxCachedAddresses)
        {
            cache.Clear();
        }

        var ttl = index > 0 ? PositiveCacheTtl : NegativeCacheTtl;
        cache[address] = new CachedInterfaceIndex(
            index,
            Environment.TickCount64 + (long)ttl.TotalMilliseconds);
    }

    private static bool MatchesAdapter(
        NetworkInterface networkInterface,
        string adapterName,
        ReadOnlySpan<byte> macAddress)
    {
        if (networkInterface.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase)
            || networkInterface.Description.Equals(adapterName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(networkInterface.Id)
            && adapterName.Contains(networkInterface.Id, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (macAddress.Length == 0)
        {
            return false;
        }

        try
        {
            var interfaceAddress = networkInterface.GetPhysicalAddress().GetAddressBytes();
            return interfaceAddress.Length == macAddress.Length
                && interfaceAddress.AsSpan().SequenceEqual(macAddress);
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }

    private static bool TryReadIndex(Func<int> readIndex, out int index)
    {
        try
        {
            index = readIndex();
            return index > 0;
        }
        catch (NetworkInformationException)
        {
            index = 0;
            return false;
        }
    }

    private static byte[] CreateSocketAddress(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var socketAddress = new byte[16];
            BinaryPrimitives.WriteUInt16LittleEndian(
                socketAddress.AsSpan(0, 2),
                (ushort)AddressFamily.InterNetwork);
            address.GetAddressBytes().CopyTo(socketAddress, 4);
            return socketAddress;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var socketAddress = new byte[28];
            BinaryPrimitives.WriteUInt16LittleEndian(
                socketAddress.AsSpan(0, 2),
                (ushort)AddressFamily.InterNetworkV6);
            address.GetAddressBytes().CopyTo(socketAddress, 8);
            BinaryPrimitives.WriteUInt32LittleEndian(
                socketAddress.AsSpan(24, 4),
                unchecked((uint)address.ScopeId));
            return socketAddress;
        }

        throw new ArgumentException("The address family is not supported.", nameof(address));
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int GetBestInterfaceEx(
        [In] byte[] destinationAddress,
        out uint bestInterfaceIndex);

    private readonly record struct CachedInterfaceIndex(int Index, long ExpiresAt);

    private readonly record struct MtuCacheKey(int InterfaceIndex, AddressFamily AddressFamily);

    private readonly record struct CachedMtu(int Mtu, long ExpiresAt);
}
