using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;

namespace ProxiFyre;

internal sealed unsafe class PacketFilterLoop : IDisposable
{
    private const int UdpHeaderIpv4Size = 10;
    private const int UdpHeaderIpv6Size = 22;

    private readonly AppConfiguration _configuration;
    private readonly TcpDirectRelay _tcpRelay;
    private readonly UdpDirectRelay _udpRelay;
    private readonly ProcessLookup _processLookup;
    private readonly HashSet<IntPtr> _adapters = [];
    private readonly Action<string> _log;
    private readonly TimeProvider _timeProvider;
    private readonly Dictionary<string, DateTimeOffset> _detailLogTimes = [];
    private IntPtr _driverHandle;
    private bool _disposed;

    public PacketFilterLoop(AppConfiguration configuration, TcpDirectRelay tcpRelay, UdpDirectRelay udpRelay, Action<string>? log = null, TimeProvider? timeProvider = null)
    {
        _configuration = configuration;
        _tcpRelay = tcpRelay;
        _udpRelay = udpRelay;
        _log = log ?? Console.WriteLine;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _processLookup = new ProcessLookup(
            message => LogDetail(message, message, TimeSpan.FromSeconds(10)),
            _timeProvider);
    }

    public Task RunAsync(CancellationToken cancellationToken)
    {
        return Task.Run(() => Run(cancellationToken), cancellationToken);
    }

    private void Run(CancellationToken cancellationToken)
    {
        OpenDriver();
        ConfigureAdapters();

        using var packetEvent = new ManualResetEvent(false);
        try
        {
            foreach (var adapter in _adapters)
            {
                NdisApi.SetPacketEvent(_driverHandle, adapter, packetEvent.SafeWaitHandle);
            }

            _log("Packet filter started.");

            while (!cancellationToken.IsCancellationRequested)
            {
                packetEvent.WaitOne(TimeSpan.FromMilliseconds(250));
                packetEvent.Reset();

                bool drainedAny;
                do
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    drainedAny = TryReadAndProcessPacket();
                }
                while (drainedAny);
            }
        }
        finally
        {
            foreach (var adapter in _adapters)
            {
                NdisApi.SetPacketEvent(_driverHandle, adapter, IntPtr.Zero);
            }
        }
    }

    private void OpenDriver()
    {
        _driverHandle = NdisApi.OpenFilterDriver("NDISRD");
        if (_driverHandle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to open WinpkFilter driver.");
        }

        if (!NdisApi.IsDriverLoaded(_driverHandle))
        {
            throw new InvalidOperationException("Windows Packet Filter driver is not loaded.");
        }

        _log($"WinpkFilter driver version: 0x{NdisApi.GetDriverVersion(_driverHandle):X8}");
    }

    private void ConfigureAdapters()
    {
        var adapterList = new NdisApi.TcpAdapterList();
        if (!NdisApi.GetTcpipBoundAdaptersInfo(_driverHandle, ref adapterList))
        {
            throw new InvalidOperationException("Failed to enumerate TCP/IP bound adapters.");
        }

        for (var i = 0; i < adapterList.Count; i++)
        {
            var adapter = adapterList.GetHandle(i);
            if (adapter == IntPtr.Zero)
            {
                continue;
            }

            _adapters.Add(adapter);
            var mode = new NdisApi.AdapterMode
            {
                AdapterHandle = adapter,
                Flags = NdisApi.MstcpFlagSentTunnel | NdisApi.MstcpFlagRecvTunnel
            };

            if (!NdisApi.SetAdapterMode(_driverHandle, ref mode))
            {
                _log($"Failed to set tunnel mode for adapter handle 0x{adapter.ToInt64():X}.");
            }
        }

        if (_adapters.Count == 0)
        {
            throw new InvalidOperationException("No TCP/IP adapters were returned by WinpkFilter.");
        }

        _log($"Filtering {_adapters.Count} adapter(s).");
    }

    private bool TryReadAndProcessPacket()
    {
        var buffer = default(NdisApi.IntermediateBuffer);
        var packets = stackalloc IntPtr[1];
        packets[0] = (IntPtr)(&buffer);

        if (!NdisApi.ReadPacketsUnsorted(_driverHandle, packets, 1, out var packetsRead) || packetsRead == 0)
        {
            return false;
        }

        ProcessPacket(&buffer);
        return true;
    }

    private void ProcessPacket(NdisApi.IntermediateBuffer* buffer)
    {
        var length = checked((int)Math.Min(buffer->Length, NdisApi.MaxEtherFrame));
        var frame = new Span<byte>(buffer->Data, length);

        if (!PacketView.TryParse(frame, length, out var packet))
        {
            Pass(buffer);
            return;
        }

        if (buffer->DeviceFlags == NdisApi.PacketFlagOnSend)
        {
            ProcessOutgoing(buffer, packet);
            return;
        }

        if (buffer->DeviceFlags == NdisApi.PacketFlagOnReceive)
        {
            ProcessIncoming(buffer, packet);
            return;
        }

        Pass(buffer);
    }

    private void ProcessOutgoing(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (packet.IsTcp)
        {
            ProcessOutgoingTcp(buffer, packet);
        }
        else if (packet.IsUdp)
        {
            ProcessOutgoingUdp(buffer, packet);
        }
        else
        {
            Pass(buffer);
        }
    }

    private void ProcessIncoming(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (packet.IsTcp)
        {
            ProcessIncomingTcp(buffer, packet);
        }
        else if (packet.IsUdp)
        {
            ProcessIncomingUdp(buffer, packet);
        }
        else
        {
            Pass(buffer);
        }
    }

    private void ProcessOutgoingTcp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (packet.SourcePort == _tcpRelay.Port && TryRestoreTcpServerToClient(buffer, packet))
        {
            Revert(buffer);
            return;
        }

        var relayKey = new TcpClientKey(packet.DestinationAddress, packet.SourcePort);
            if (_tcpRelay.HasTarget(relayKey))
            {
                _tcpRelay.Refresh(relayKey);
                LogDetail($"TCP EXISTING TARGET {packet.Session} relayPort={_tcpRelay.Port}", $"tcp-existing:{relayKey.ClientAddress}:{relayKey.ClientPort}", TimeSpan.FromSeconds(10));
                RedirectTcpClientToRelay(buffer, packet);
                Revert(buffer);
                return;
            }

        var process = _processLookup.LookupTcpOwner(packet.Session);
        if (process is null)
        {
            if (packet.IsSynOnly)
            {
                LogDetail($"TCP OWNER MISS {packet.Session}", $"tcp-owner-miss:{packet.Session}", TimeSpan.FromSeconds(2));
            }

            Pass(buffer);
            return;
        }

        if (!_configuration.TryGetMatchingPattern(process, out var matchedPattern, out var matchMissReason))
        {
            if (packet.IsSynOnly)
            {
                LogDetail(
                    $"TCP APP MISS {packet.Session} pid={process.ProcessId} name={process.Name} path={process.Path} reason={matchMissReason}",
                    $"tcp-app-miss:{process.ProcessId}:{packet.DestinationAddress}:{packet.DestinationPort}",
                    TimeSpan.FromSeconds(10));
            }

            Pass(buffer);
            return;
        }

        if (packet.IsSynOnly)
        {
            LogDetail(
                $"TCP APP MATCH {packet.Session} pid={process.ProcessId} name={process.Name} path={process.Path} pattern={matchedPattern}",
                $"tcp-app-match:{process.ProcessId}:{packet.DestinationAddress}:{packet.DestinationPort}",
                TimeSpan.FromSeconds(2));
            _tcpRelay.Register(relayKey, packet.DestinationAddress, packet.DestinationPort);
            RedirectTcpClientToRelay(buffer, packet);
            Revert(buffer);
            return;
        }

        Pass(buffer);
    }

    private void ProcessIncomingTcp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (packet.SourcePort == _tcpRelay.Port && TryRestoreTcpServerToClient(buffer, packet))
        {
            Revert(buffer);
            return;
        }

        Pass(buffer);
    }

    private void RedirectTcpClientToRelay(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        var originalRemote = new DirectRelayTarget(packet.DestinationAddress, packet.DestinationPort, _timeProvider.GetUtcNow());
        packet.SwapEthernetAddresses();
        packet.SwapIpAddresses();
        packet.DestinationPort = _tcpRelay.Port;
        packet.RecalculateChecksums();
        buffer->Length = (uint)packet.PacketLength;

        if (packet.IsSynOnly)
        {
            _log($"REDIRECT TCP {packet.DestinationAddress}:{packet.SourcePort} -> {originalRemote}");
        }
    }

    private bool TryRestoreTcpServerToClient(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        var key = packet.DestinationClientKey;
        if (!_tcpRelay.TryGetTarget(key, out var target))
        {
            LogDetail($"TCP RESTORE MISS key={key.ClientAddress}:{key.ClientPort} packet={packet.Session}", $"tcp-restore-miss:{key.ClientAddress}:{key.ClientPort}", TimeSpan.FromSeconds(5));
            return false;
        }

        packet.SourcePort = target.RemotePort;
        packet.SwapEthernetAddresses();
        packet.SwapIpAddresses();
        packet.RecalculateChecksums();
        buffer->Length = (uint)packet.PacketLength;

        if (packet.IsClosing)
        {
            _tcpRelay.Remove(key);
        }
        else
        {
            _tcpRelay.Refresh(key);
        }

        return true;
    }

    private void ProcessOutgoingUdp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (packet.SourcePort == _udpRelay.Port && TryRestoreUdpServerToClient(buffer, packet))
        {
            Revert(buffer);
            return;
        }

        var relayKey = new UdpRelayKey(packet.DestinationAddress, packet.SourcePort, packet.DestinationAddress, packet.DestinationPort);
        if (_udpRelay.HasTarget(relayKey))
        {
            _udpRelay.Refresh(relayKey);
            LogDetail($"UDP EXISTING TARGET {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}", $"udp-existing:{relayKey.ClientAddress}:{relayKey.ClientPort}:{relayKey.RemoteAddress}:{relayKey.RemotePort}", TimeSpan.FromSeconds(10));
            if (RedirectUdpClientToRelay(buffer, packet))
            {
                Revert(buffer);
            }
            else
            {
                Pass(buffer);
            }

            return;
        }

        var process = _processLookup.LookupUdpOwner(packet.UdpEndpoint);
        if (process is null)
        {
            LogDetail(
                $"UDP OWNER MISS {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}",
                $"udp-owner-miss:{packet.SourceAddress}:{packet.SourcePort}:{packet.DestinationAddress}:{packet.DestinationPort}",
                TimeSpan.FromSeconds(2));
            Pass(buffer);
            return;
        }

        if (!_configuration.TryGetMatchingPattern(process, out var matchedPattern, out var matchMissReason))
        {
            LogDetail(
                $"UDP APP MISS {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} pid={process.ProcessId} name={process.Name} path={process.Path} reason={matchMissReason}",
                $"udp-app-miss:{process.ProcessId}:{packet.DestinationAddress}:{packet.DestinationPort}",
                TimeSpan.FromSeconds(10));
            Pass(buffer);
            return;
        }

        LogDetail(
            $"UDP APP MATCH {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} pid={process.ProcessId} name={process.Name} path={process.Path} pattern={matchedPattern}",
            $"udp-app-match:{process.ProcessId}:{packet.DestinationAddress}:{packet.DestinationPort}",
            TimeSpan.FromSeconds(2));
        _udpRelay.Register(relayKey, packet.DestinationAddress, packet.DestinationPort);
        if (RedirectUdpClientToRelay(buffer, packet))
        {
            Revert(buffer);
        }
        else
        {
            _udpRelay.Remove(relayKey);
            Pass(buffer);
        }
    }

    private void ProcessIncomingUdp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (packet.SourcePort == _udpRelay.Port && TryRestoreUdpServerToClient(buffer, packet))
        {
            Revert(buffer);
            return;
        }

        Pass(buffer);
    }

    private bool RedirectUdpClientToRelay(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        var originalRemote = new DirectRelayTarget(packet.DestinationAddress, packet.DestinationPort, _timeProvider.GetUtcNow());
        var header = BuildUdpRelayHeader(packet.DestinationAddress, packet.DestinationPort);
        if (!packet.TryPrependUdpPayload(header))
        {
            return false;
        }

        packet.SwapEthernetAddresses();
        packet.SwapIpAddresses();
        packet.DestinationPort = _udpRelay.Port;
        packet.RecalculateChecksums();
        buffer->Length = (uint)packet.PacketLength;
        _log($"REDIRECT UDP {packet.DestinationAddress}:{packet.SourcePort} -> {originalRemote}");
        return true;
    }

    private bool TryRestoreUdpServerToClient(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (!TryReadUdpRelayHeader(packet.UdpPayload, packet.AddressFamily, out var remoteAddress, out var remotePort, out var headerSize))
        {
            LogDetail($"UDP RESTORE HEADER MISS {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}", $"udp-restore-header:{packet.SourceAddress}:{packet.SourcePort}:{packet.DestinationAddress}:{packet.DestinationPort}", TimeSpan.FromSeconds(5));
            return false;
        }

        var key = new UdpRelayKey(packet.DestinationAddress, packet.DestinationPort, remoteAddress, remotePort);
        if (!_udpRelay.TryGetTarget(key, out var target))
        {
            target = new DirectRelayTarget(remoteAddress, remotePort, _timeProvider.GetUtcNow());
        }

        if (!packet.TryRemoveUdpPayloadPrefix(headerSize))
        {
            LogDetail($"UDP RESTORE REMOVE PREFIX FAILED headerSize={headerSize} {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}", $"udp-restore-remove:{packet.SourceAddress}:{packet.SourcePort}:{packet.DestinationAddress}:{packet.DestinationPort}", TimeSpan.FromSeconds(5));
            return false;
        }

        packet.SourcePort = target.RemotePort;
        packet.SwapEthernetAddresses();
        packet.SwapIpAddresses();
        packet.SourceAddress = target.RemoteAddress;
        packet.RecalculateChecksums();
        buffer->Length = (uint)packet.PacketLength;
        _udpRelay.Refresh(key);
        return true;
    }

    private static byte[] BuildUdpRelayHeader(IPAddress remoteAddress, ushort remotePort)
    {
        remoteAddress = NetworkAddress.Normalize(remoteAddress);
        if (remoteAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            var header = new byte[UdpHeaderIpv4Size];
            header[3] = 1;
            remoteAddress.GetAddressBytes().CopyTo(header.AsSpan(4, 4));
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(8, 2), remotePort);
            return header;
        }

        var header6 = new byte[UdpHeaderIpv6Size];
        header6[3] = 4;
        remoteAddress.GetAddressBytes().CopyTo(header6.AsSpan(4, 16));
        BinaryPrimitives.WriteUInt16BigEndian(header6.AsSpan(20, 2), remotePort);
        return header6;
    }

    private static bool TryReadUdpRelayHeader(ReadOnlySpan<byte> payload, AddressFamily family, out IPAddress remoteAddress, out ushort remotePort, out int headerSize)
    {
        remoteAddress = IPAddress.None;
        remotePort = 0;
        headerSize = 0;

        if (payload.Length < 4 || payload[0] != 0 || payload[1] != 0 || payload[2] != 0)
        {
            return false;
        }

        if (payload[3] == 1 && payload.Length >= UdpHeaderIpv4Size)
        {
            remoteAddress = new IPAddress(payload.Slice(4, 4));
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(8, 2));
            headerSize = UdpHeaderIpv4Size;
            return true;
        }

        if (payload[3] == 4 && payload.Length >= UdpHeaderIpv6Size)
        {
            remoteAddress = new IPAddress(payload.Slice(4, 16));
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(20, 2));
            headerSize = UdpHeaderIpv6Size;
            return true;
        }

        return false;
    }

    private void Pass(NdisApi.IntermediateBuffer* buffer)
    {
        if (buffer->DeviceFlags == NdisApi.PacketFlagOnSend)
        {
            SendToAdapter(buffer);
        }
        else
        {
            SendToMstcp(buffer);
        }
    }

    private void LogDetail(string message, string key, TimeSpan interval)
    {
        var now = _timeProvider.GetUtcNow();
        if (_detailLogTimes.TryGetValue(key, out var lastLogged) && now - lastLogged < interval)
        {
            return;
        }

        _detailLogTimes[key] = now;
        _log(message);
    }

    private void Revert(NdisApi.IntermediateBuffer* buffer)
    {
        if (buffer->DeviceFlags == NdisApi.PacketFlagOnReceive)
        {
            SendToAdapter(buffer);
        }
        else
        {
            SendToMstcp(buffer);
        }
    }

    private void SendToMstcp(NdisApi.IntermediateBuffer* buffer)
    {
        var request = CreateRequest(buffer);
        NdisApi.SendPacketToMstcp(_driverHandle, ref request);
    }

    private void SendToAdapter(NdisApi.IntermediateBuffer* buffer)
    {
        var request = CreateRequest(buffer);
        NdisApi.SendPacketToAdapter(_driverHandle, ref request);
    }

    private static NdisApi.EthRequest CreateRequest(NdisApi.IntermediateBuffer* buffer)
    {
        return new NdisApi.EthRequest
        {
            AdapterHandle = buffer->AdapterOrListFlink,
            Buffer = (IntPtr)buffer
        };
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        foreach (var adapter in _adapters)
        {
            NdisApi.SetPacketEvent(_driverHandle, adapter, IntPtr.Zero);
            var mode = new NdisApi.AdapterMode { AdapterHandle = adapter, Flags = 0 };
            NdisApi.SetAdapterMode(_driverHandle, ref mode);
            NdisApi.FlushAdapterPacketQueue(_driverHandle, adapter);
        }

        if (_driverHandle != IntPtr.Zero)
        {
            NdisApi.CloseFilterDriver(_driverHandle);
            _driverHandle = IntPtr.Zero;
        }

        GC.SuppressFinalize(this);
    }
}
