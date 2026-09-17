using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal enum FragmentAddStatus
{
    NotFragment,
    Incomplete,
    Complete,
    Invalid
}

internal sealed class CapturedPacketFragment(
    byte[] frame,
    int length,
    IntPtr adapterHandle,
    uint deviceFlags,
    uint dot1q)
{
    public byte[] Frame { get; } = frame;
    public int Length { get; } = length;
    public IntPtr AdapterHandle { get; } = adapterHandle;
    public uint DeviceFlags { get; } = deviceFlags;
    public uint Dot1q { get; } = dot1q;
}

internal sealed class ReassembledIpPacket(
    byte[] frame,
    int length,
    IntPtr adapterHandle,
    uint deviceFlags,
    uint dot1q,
    IReadOnlyList<CapturedPacketFragment> fragments)
{
    public byte[] Frame { get; } = frame;
    public int Length { get; } = length;
    public IntPtr AdapterHandle { get; } = adapterHandle;
    public uint DeviceFlags { get; } = deviceFlags;
    public uint Dot1q { get; } = dot1q;
    public IReadOnlyList<CapturedPacketFragment> Fragments { get; } = fragments;
}

internal sealed class IpFragmentReassembler
{
    private static readonly TimeSpan AssemblyTtl = TimeSpan.FromSeconds(30);
    private const int MaxAssemblies = 256;
    private readonly Dictionary<FragmentKey, FragmentAssembly> _assemblies = [];
    private readonly TimeProvider _timeProvider;

    public IpFragmentReassembler(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public FragmentAddStatus Add(
        ReadOnlySpan<byte> frame,
        int packetLength,
        IntPtr adapterHandle,
        uint deviceFlags,
        uint dot1q,
        out ReassembledIpPacket? packet)
    {
        packet = null;
        CleanupExpired();

        if (!TryParseFragment(frame, packetLength, out var fragment))
        {
            return FragmentAddStatus.NotFragment;
        }

        if (fragment.PayloadLength <= 0
            || (fragment.MoreFragments && (fragment.PayloadLength & 7) != 0)
            || fragment.Offset > ushort.MaxValue
            || fragment.Offset + fragment.PayloadLength > ushort.MaxValue)
        {
            return FragmentAddStatus.Invalid;
        }

        var key = new FragmentKey(
            adapterHandle,
            fragment.AddressFamily,
            fragment.SourceAddress,
            fragment.DestinationAddress,
            fragment.Identification,
            fragment.Protocol);

        if (!_assemblies.TryGetValue(key, out var assembly))
        {
            if (_assemblies.Count >= MaxAssemblies)
            {
                return FragmentAddStatus.Invalid;
            }

            assembly = new FragmentAssembly(_timeProvider.GetUtcNow());
            _assemblies[key] = assembly;
        }

        assembly.LastActivity = _timeProvider.GetUtcNow();
        if (!assembly.TryAdd(fragment, frame, packetLength, adapterHandle, deviceFlags, dot1q))
        {
            _assemblies.Remove(key);
            return FragmentAddStatus.Invalid;
        }

        if (!assembly.IsComplete)
        {
            return FragmentAddStatus.Incomplete;
        }

        _assemblies.Remove(key);
        packet = assembly.Build();
        return packet is null ? FragmentAddStatus.Invalid : FragmentAddStatus.Complete;
    }

    public void CleanupExpired()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var pair in _assemblies.ToArray())
        {
            if (now - pair.Value.LastActivity > AssemblyTtl)
            {
                _assemblies.Remove(pair.Key);
            }
        }
    }

    private static bool TryParseFragment(
        ReadOnlySpan<byte> frame,
        int packetLength,
        out IpFragment fragment)
    {
        fragment = default;
        var linkHeaderLength = GetLinkHeaderLength(frame, packetLength);
        if (linkHeaderLength < PacketView.EthernetHeaderLength)
        {
            return false;
        }

        var etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(linkHeaderLength - 2, 2));
        return etherType switch
        {
            PacketView.EtherTypeIpv4 => TryParseIpv4Fragment(frame, packetLength, linkHeaderLength, out fragment),
            PacketView.EtherTypeIpv6 => TryParseIpv6Fragment(frame, packetLength, linkHeaderLength, out fragment),
            _ => false
        };
    }

    private static int GetLinkHeaderLength(ReadOnlySpan<byte> frame, int packetLength)
    {
        if (packetLength < PacketView.EthernetHeaderLength || frame.Length < packetLength)
        {
            return 0;
        }

        var offset = PacketView.EthernetHeaderLength;
        var etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(12, 2));
        while (etherType is PacketView.EtherTypeVlan or PacketView.EtherTypeProviderVlan)
        {
            if (packetLength < offset + 4)
            {
                return 0;
            }

            etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(offset + 2, 2));
            offset += 4;
        }

        return offset;
    }

    private static bool TryParseIpv4Fragment(
        ReadOnlySpan<byte> frame,
        int packetLength,
        int ipOffset,
        out IpFragment fragment)
    {
        fragment = default;
        if (packetLength < ipOffset + 20 || frame[ipOffset] >> 4 != 4)
        {
            return false;
        }

        var headerLength = (frame[ipOffset] & 0x0F) * 4;
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ipOffset + 2, 2));
        var fragmentField = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ipOffset + 6, 2));
        if (headerLength < 20
            || totalLength < headerLength
            || packetLength < ipOffset + totalLength
            || (fragmentField & 0x3FFF) == 0)
        {
            return false;
        }

        var payloadOffset = ipOffset + headerLength;
        var payloadLength = totalLength - headerLength;
        fragment = new IpFragment(
            AddressFamily.InterNetwork,
            new IPAddress(frame.Slice(ipOffset + 12, 4)),
            new IPAddress(frame.Slice(ipOffset + 16, 4)),
            BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ipOffset + 4, 2)),
            frame[ipOffset + 9],
            (fragmentField & 0x1FFF) * 8,
            (fragmentField & 0x2000) != 0,
            frame.Slice(0, ipOffset).ToArray(),
            frame.Slice(ipOffset, headerLength).ToArray(),
            ipOffset + 6,
            frame.Slice(payloadOffset, payloadLength).ToArray());
        return true;
    }

    private static bool TryParseIpv6Fragment(
        ReadOnlySpan<byte> frame,
        int packetLength,
        int ipOffset,
        out IpFragment fragment)
    {
        fragment = default;
        if (packetLength < ipOffset + 40 || frame[ipOffset] >> 4 != 6)
        {
            return false;
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ipOffset + 4, 2));
        if (packetLength < ipOffset + 40 + payloadLength)
        {
            return false;
        }

        var nextHeader = frame[ipOffset + 6];
        var currentOffset = ipOffset + 40;
        var bytesRemaining = (int)payloadLength;
        while (true)
        {
            if (nextHeader == 44)
            {
                if (bytesRemaining < 8 || currentOffset + 8 > packetLength)
                {
                    return false;
                }

                var fragmentHeader = frame.Slice(currentOffset, 8);
                var fragmentField = BinaryPrimitives.ReadUInt16BigEndian(fragmentHeader.Slice(2, 2));
                var fragmentPayloadOffset = currentOffset + 8;
                var fragmentPayloadLength = bytesRemaining - 8;
                fragment = new IpFragment(
                    AddressFamily.InterNetworkV6,
                    new IPAddress(frame.Slice(ipOffset + 8, 16)),
                    new IPAddress(frame.Slice(ipOffset + 24, 16)),
                    BinaryPrimitives.ReadUInt32BigEndian(fragmentHeader.Slice(4, 4)),
                    fragmentHeader[0],
                    (fragmentField >> 3) * 8,
                    (fragmentField & 0x1) != 0,
                    frame.Slice(0, ipOffset).ToArray(),
                    frame.Slice(ipOffset, currentOffset - ipOffset).ToArray(),
                    GetPreviousNextHeaderOffset(frame, ipOffset, currentOffset),
                    frame.Slice(fragmentPayloadOffset, fragmentPayloadLength).ToArray());
                return true;
            }

            if (nextHeader is not (0 or 43 or 60) || bytesRemaining < 8)
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
            bytesRemaining -= extensionLength;
        }
    }

    private static int GetPreviousNextHeaderOffset(
        ReadOnlySpan<byte> frame,
        int ipOffset,
        int fragmentHeaderOffset)
    {
        var previous = ipOffset + 6;
        var nextHeader = frame[ipOffset + 6];
        var currentOffset = ipOffset + 40;
        while (currentOffset < fragmentHeaderOffset && nextHeader is 0 or 43 or 60)
        {
            previous = currentOffset;
            nextHeader = frame[currentOffset];
            currentOffset += (frame[currentOffset + 1] + 1) * 8;
        }

        return previous - ipOffset;
    }

    private sealed class FragmentAssembly(DateTimeOffset now)
    {
        private readonly List<StoredFragment> _fragments = [];
        private int _totalLength = -1;
        private IpFragment? _headerFragment;

        public DateTimeOffset LastActivity { get; set; } = now;

        public bool IsComplete => _totalLength >= 0 && IsContiguous();

        public bool TryAdd(
            IpFragment fragment,
            ReadOnlySpan<byte> frame,
            int packetLength,
            IntPtr adapterHandle,
            uint deviceFlags,
            uint dot1q)
        {
            var end = fragment.Offset + fragment.PayloadLength;
            foreach (var stored in _fragments)
            {
                if (fragment.Offset < stored.Fragment.Offset + stored.Fragment.PayloadLength
                    && stored.Fragment.Offset < end)
                {
                    return false;
                }
            }

            var original = new CapturedPacketFragment(
                frame[..packetLength].ToArray(),
                packetLength,
                adapterHandle,
                deviceFlags,
                dot1q);
            _fragments.Add(new StoredFragment(fragment, original));
            _fragments.Sort(static (left, right) => left.Fragment.Offset.CompareTo(right.Fragment.Offset));

            if (fragment.Offset == 0)
            {
                _headerFragment = fragment;
            }

            if (!fragment.MoreFragments)
            {
                _totalLength = end;
            }

            return true;
        }

        public ReassembledIpPacket? Build()
        {
            if (_headerFragment is not { } header || _totalLength < 0)
            {
                return null;
            }

            var payload = new byte[_totalLength];
            foreach (var stored in _fragments)
            {
                stored.Fragment.Payload.CopyTo(payload.AsSpan(stored.Fragment.Offset));
            }

            if (header.AddressFamily == AddressFamily.InterNetwork)
            {
                var ipHeader = header.HeaderPrefix;
                var frame = new byte[header.LinkHeader.Length + ipHeader.Length + payload.Length];
                header.LinkHeader.CopyTo(frame, 0);
                ipHeader.CopyTo(frame, header.LinkHeader.Length);
                var ip = frame.AsSpan(header.LinkHeader.Length, ipHeader.Length);
                var totalLength = ip.Length + payload.Length;
                if (totalLength > ushort.MaxValue)
                {
                    return null;
                }

                BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)totalLength);
                BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(6, 2), 0);
                BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), 0);
                BinaryPrimitives.WriteUInt16BigEndian(
                    ip.Slice(10, 2),
                    ComputeOnesComplement(ip));
                payload.CopyTo(frame.AsSpan(header.LinkHeader.Length + ipHeader.Length));
                return new ReassembledIpPacket(
                    frame,
                    frame.Length,
                    _fragments[0].Original.AdapterHandle,
                    _fragments[0].Original.DeviceFlags,
                    _fragments[0].Original.Dot1q,
                    _fragments.Select(static item => item.Original).ToArray());
            }

            var baseHeader = header.HeaderPrefix;
            var ipv6Frame = new byte[header.LinkHeader.Length + baseHeader.Length + payload.Length];
            header.LinkHeader.CopyTo(ipv6Frame, 0);
            baseHeader.CopyTo(ipv6Frame, header.LinkHeader.Length);
            var ipv6 = ipv6Frame.AsSpan(header.LinkHeader.Length, baseHeader.Length);
            var ipv6PayloadLength = ipv6.Length - 40 + payload.Length;
            if (ipv6PayloadLength > ushort.MaxValue)
            {
                return null;
            }

            ipv6[header.PreviousNextHeaderOffset] = header.Protocol;
            BinaryPrimitives.WriteUInt16BigEndian(
                ipv6.Slice(4, 2),
                (ushort)ipv6PayloadLength);
            payload.CopyTo(ipv6Frame.AsSpan(header.LinkHeader.Length + baseHeader.Length));
            return new ReassembledIpPacket(
                ipv6Frame,
                ipv6Frame.Length,
                _fragments[0].Original.AdapterHandle,
                _fragments[0].Original.DeviceFlags,
                _fragments[0].Original.Dot1q,
                _fragments.Select(static item => item.Original).ToArray());
        }

        private bool IsContiguous()
        {
            var expected = 0;
            foreach (var stored in _fragments)
            {
                if (stored.Fragment.Offset != expected)
                {
                    return false;
                }

                expected += stored.Fragment.PayloadLength;
            }

            return expected == _totalLength;
        }

        private static ushort ComputeOnesComplement(ReadOnlySpan<byte> data)
        {
            uint sum = 0;
            for (var i = 0; i + 1 < data.Length; i += 2)
            {
                sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
            }

            if ((data.Length & 1) != 0)
            {
                sum += (uint)(data[^1] << 8);
            }

            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            return (ushort)~sum;
        }
    }

    private sealed record StoredFragment(IpFragment Fragment, CapturedPacketFragment Original);

    private readonly record struct FragmentKey(
        IntPtr AdapterHandle,
        AddressFamily AddressFamily,
        IPAddress SourceAddress,
        IPAddress DestinationAddress,
        uint Identification,
        byte Protocol);

    private readonly record struct IpFragment(
        AddressFamily AddressFamily,
        IPAddress SourceAddress,
        IPAddress DestinationAddress,
        uint Identification,
        byte Protocol,
        int Offset,
        bool MoreFragments,
        byte[] LinkHeader,
        byte[] HeaderPrefix,
        int PreviousNextHeaderOffset,
        byte[] Payload)
    {
        public int PayloadLength => Payload.Length;
    }
}
