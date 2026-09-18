using System.Net.NetworkInformation;

namespace ProxiFyre;

internal static class NetworkInterfaceIndexResolver
{
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
}
