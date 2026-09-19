using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class DnsSpoofHandler
{
    private readonly DynamicAppConfiguration _configuration;
    private readonly ProcessLookup _processLookup;
    private readonly PacketInjector _injector;
    private readonly Func<AdapterPipelineSet?> _getAdapters;
    private readonly Action<string> _log;
    private readonly TimeProvider _timeProvider;

    public DnsSpoofHandler(
        DynamicAppConfiguration configuration,
        ProcessLookup processLookup,
        PacketInjector injector,
        Func<AdapterPipelineSet?> getAdapters,
        Action<string> log,
        TimeProvider timeProvider)
    {
        _configuration = configuration;
        _processLookup = processLookup;
        _injector = injector;
        _getAdapters = getAdapters;
        _log = log;
        _timeProvider = timeProvider;
    }

    public bool TryHandle(IntPtr adapterHandle, uint dot1q, PacketView packet)
    {
        if (!_configuration.Current.EnableFakeIpWhitelist)
        {
            return false;
        }

        var isDnsPort = packet.DestinationPort == 53 || packet.DestinationPort == 5353;
        if (!isDnsPort || !packet.IsUdp)
        {
            return false;
        }

        var process = _processLookup.LookupUdpOwner(
            CreateEndpointKey(packet.SourceAddress, packet.SourcePort, adapterHandle));
        var payload = packet.UdpPayload;
        if (payload.Length < 12)
        {
            return false;
        }

        var transactionId = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
        if (questionCount == 0 || (flags & 0x8000) != 0)
        {
            return false;
        }

        var offset = 12;
        var domain = new System.Text.StringBuilder();
        while (offset < payload.Length)
        {
            var length = payload[offset];
            if (length == 0)
            {
                offset++;
                break;
            }

            if (offset + 1 + length > payload.Length)
            {
                return false;
            }

            if (domain.Length > 0)
            {
                domain.Append('.');
            }

            domain.Append(System.Text.Encoding.ASCII.GetString(payload.Slice(offset + 1, length)));
            offset += 1 + length;
        }

        if (offset + 4 > payload.Length)
        {
            return false;
        }

        var queryType = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
        offset += 4;
        var queryDomain = domain.ToString();
        if ((queryType != 1 && queryType != 28)
            || !queryDomain.StartsWith("fakeip-", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var firstDot = queryDomain.IndexOf('.');
        if (firstDot == -1)
        {
            return false;
        }

        var parts = queryDomain[..firstDot].Split('-');
        if (parts.Length != 5
            || !IPAddress.TryParse($"{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}", out var fakeIp))
        {
            return false;
        }

        var questionLength = offset - 12;
        var ipLength = queryType == 1 ? 4 : 16;
        var response = new byte[12 + questionLength + 12 + ipLength];
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(0, 2), transactionId);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), 0);
        payload.Slice(12, questionLength).CopyTo(response.AsSpan(12));

        var answerOffset = 12 + questionLength;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(answerOffset, 2), 0xC00C);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(answerOffset + 2, 2), queryType);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(answerOffset + 4, 2), 1);
        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(answerOffset + 6, 4), 60);
        BinaryPrimitives.WriteUInt16BigEndian(
            response.AsSpan(answerOffset + 10, 2),
            (ushort)ipLength);

        if (queryType == 1)
        {
            fakeIp.GetAddressBytes().CopyTo(response.AsSpan(answerOffset + 12, 4));
        }
        else
        {
            var ipv6Bytes = new byte[16];
            ipv6Bytes[10] = 0xFF;
            ipv6Bytes[11] = 0xFF;
            fakeIp.GetAddressBytes().CopyTo(ipv6Bytes.AsSpan(12, 4));
            ipv6Bytes.CopyTo(response.AsSpan(answerOffset + 12, 16));
        }

        InjectResponse(adapterHandle, dot1q, packet, packet.DestinationPort, response);
        if (packet.DestinationPort != 53)
        {
            InjectResponse(adapterHandle, dot1q, packet, 53, response);
        }

        var processInfo = process is null
            ? "process=unknown"
            : $"process={process.Name} pid={process.ProcessId}";
        _log(
            $"[DNS SPOOF] Spoofed {queryDomain} (Type={queryType}) -> {fakeIp} ({processInfo}) (TargetPort={packet.DestinationPort})");
        return true;
    }

    private void InjectResponse(
        IntPtr adapterHandle,
        uint dot1q,
        PacketView originalQuery,
        ushort sourcePort,
        ReadOnlySpan<byte> dnsPayload)
    {
        var target = new DirectRelayTarget(
            originalQuery.DestinationAddress,
            sourcePort,
            _timeProvider.GetUtcNow(),
            AdapterHandle: adapterHandle,
            ClientAddress: originalQuery.SourceAddress,
            ClientPort: originalQuery.SourcePort,
            LinkHeader: originalQuery.GetLinkHeader(),
            InboundEthernetSource: originalQuery.GetEthernetDestination(),
            InboundEthernetDestination: originalQuery.GetEthernetSource(),
            Dot1q: dot1q);
        _injector.InjectUdpResponseToClient(
            target,
            new IPEndPoint(originalQuery.DestinationAddress, sourcePort),
            dnsPayload.ToArray());
    }

    private UdpEndpointKey CreateEndpointKey(
        IPAddress address,
        ushort port,
        IntPtr adapterHandle)
    {
        _ = _getAdapters()!.TryGetInterfaceIndex(adapterHandle, out var interfaceIndex);
        if (address.AddressFamily == AddressFamily.InterNetworkV6
            && address.ScopeId == 0
            && interfaceIndex > 0
            && (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal))
        {
            address = new IPAddress(address.GetAddressBytes(), interfaceIndex);
        }

        return new UdpEndpointKey(address, port);
    }

    internal static bool TryGetQueryDomain(ReadOnlySpan<byte> payload, out string domain)
    {
        domain = string.Empty;
        if (payload.Length < 12)
        {
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(6, 2));
        var authorityCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(8, 2));
        var additionalCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(10, 2));
        if (questionCount == 0
            || (flags & 0x8000) != 0
            || answerCount != 0
            || authorityCount != 0
            || additionalCount > 1)
        {
            return false;
        }

        try
        {
            var offset = 12;
            var builder = new System.Text.StringBuilder();
            while (offset < payload.Length)
            {
                var length = payload[offset];
                if (length == 0)
                {
                    offset++;
                    break;
                }

                if ((length & 0xC0) != 0 || length > 63 || offset + 1 + length > payload.Length)
                {
                    return false;
                }

                for (var i = 0; i < length; i++)
                {
                    var character = (char)payload[offset + 1 + i];
                    if (!char.IsLetterOrDigit(character)
                        && character != '-'
                        && character != '_'
                        && character != '.')
                    {
                        return false;
                    }
                }

                if (builder.Length > 0)
                {
                    builder.Append('.');
                }

                builder.Append(
                    System.Text.Encoding.ASCII.GetString(
                        payload.Slice(offset + 1, length)));
                offset += 1 + length;
            }

            if (builder.Length == 0)
            {
                return false;
            }

            domain = builder.ToString();
            return true;
        }
        catch
        {
            return false;
        }
    }
}
