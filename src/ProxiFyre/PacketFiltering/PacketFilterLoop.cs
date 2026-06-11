using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;

namespace ProxiFyre;

internal sealed unsafe class PacketFilterLoop : IDisposable
{
    private const int UdpHeaderIpv4Size = 10;
    private const int UdpHeaderIpv6Size = 22;

    private readonly DynamicAppConfiguration _configuration;
    private readonly TcpDirectRelay _tcpRelay;
    private readonly UdpDirectRelay _udpRelay;
    private readonly PacketWakeSignal _wakeSignal;
    private readonly ProcessLookup _processLookup;
    private readonly HashSet<IntPtr> _adapters = [];
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TimeProvider _timeProvider;
    private readonly Dictionary<string, DateTimeOffset> _detailLogTimes = [];
    private DateTimeOffset _lastPacketStatsLog;
    private long _packetsRead;
    private long _packetsPassed;
    private long _packetsRedirected;
    private IntPtr _driverHandle;
    private bool _disposed;

    public PacketFilterLoop(DynamicAppConfiguration configuration, TcpDirectRelay tcpRelay, UdpDirectRelay udpRelay, PacketWakeSignal wakeSignal, Action<string>? log = null, bool detailedLogging = false, TimeProvider? timeProvider = null)
    {
        _configuration = configuration;
        _tcpRelay = tcpRelay;
        _udpRelay = udpRelay;
        _wakeSignal = wakeSignal;
        _log = log ?? Console.WriteLine;
        _detailedLogging = detailedLogging;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _processLookup = new ProcessLookup(timeProvider: _timeProvider);
        _udpRelay.SetResponseInjector(InjectUdpResponseToClient);
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
        WaitHandle[] waitHandles = [packetEvent, _wakeSignal.WaitHandle, cancellationToken.WaitHandle];
        try
        {
            foreach (var adapter in _adapters)
            {
                NdisApi.SetPacketEvent(_driverHandle, adapter, packetEvent.SafeWaitHandle);
            }

            _log("Packet filter started.");

            while (!cancellationToken.IsCancellationRequested)
            {
                var signaledIndex = WaitHandle.WaitAny(waitHandles);
                if (signaledIndex == 2)
                {
                    break;
                }

                var driverSignaled = signaledIndex == 0;
                if (driverSignaled)
                {
                    packetEvent.Reset();
                }

                bool drainedAny;
                var drainedCount = 0;
                do
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    drainedAny = TryReadAndProcessPacket();
                    if (drainedAny)
                    {
                        drainedCount++;
                    }
                }
                while (drainedAny);

                if (driverSignaled && drainedCount == 0)
                {
                    LogDetail(
                        $"Packet event was signaled, but no packets were read. Last Win32 error: {NdisApi.LastWin32Error}",
                        "packet-event-empty",
                        TimeSpan.FromSeconds(5));
                }
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
            var error = NdisApi.LastWin32Error;
            throw new InvalidOperationException($"Failed to open WinpkFilter driver NDISRD. Win32 error {error}: {new System.ComponentModel.Win32Exception(error).Message}");
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
        foreach (var adapter in _adapters)
        {
            var buffer = default(NdisApi.IntermediateBuffer);
            var request = new NdisApi.EthRequest
            {
                AdapterHandle = adapter,
                Buffer = (IntPtr)(&buffer)
            };

            if (!NdisApi.ReadPacket(_driverHandle, ref request))
            {
                continue;
            }

            buffer.AdapterOrListFlink = adapter;
            ProcessPacket(&buffer);
            return true;
        }

        return false;
    }

    private void ProcessPacket(NdisApi.IntermediateBuffer* buffer)
    {
        _packetsRead++;

        var length = checked((int)Math.Min(buffer->Length, NdisApi.MaxEtherFrame));
        var frame = new Span<byte>(buffer->Data, NdisApi.MaxEtherFrame);

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

        var relayKey = new TcpRelayKey(packet.DestinationAddress, packet.SourcePort, packet.DestinationPort);
        if (_tcpRelay.IsRelayOutboundFlow(relayKey))
        {
            LogDetail(
                $"PASS RELAY TCP OUT flags={FormatTcpFlags(packet.TcpFlags)} payload={packet.TcpPayloadLength} flow={packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}",
                $"tcp-relay-out:{packet.SourceAddress}:{packet.SourcePort}:{packet.DestinationAddress}:{packet.DestinationPort}:{packet.TcpFlags}:{packet.TcpPayloadLength > 0}",
                packet.TcpPayloadLength > 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(2));
            Pass(buffer);
            return;
        }

        if (_tcpRelay.TryGetTarget(relayKey, out var existingTarget))
        {
            _tcpRelay.Refresh(relayKey);
            RedirectTcpClientToRelay(buffer, packet, existingTarget);
            Revert(buffer);
            return;
        }

        if (!packet.IsSynOnly)
        {
            Pass(buffer);
            return;
        }

        var process = LookupTcpOwner(packet);
        if (process is null)
        {
            Pass(buffer);
            return;
        }

        if (!_configuration.Current.TryGetMatchingPattern(process, out var matchedPattern, out _))
        {
            Pass(buffer);
            return;
        }

        LogAppConnection("TCP", packet, process, matchedPattern);
        LogDetail(
            $"TCP APP MATCH {packet.Session} pid={process.ProcessId} name={process.Name} path={process.Path} pattern={matchedPattern}",
            $"tcp-app-match:{process.ProcessId}:{packet.DestinationAddress}:{packet.DestinationPort}",
            TimeSpan.FromSeconds(2));
        var target = CreateTarget(buffer, packet, process, matchedPattern);
        var clientKey = new TcpClientKey(packet.DestinationAddress, packet.SourcePort);
        _tcpRelay.Register(relayKey, clientKey, target);
        RedirectTcpClientToRelay(buffer, packet, target);
        Revert(buffer);
    }

    private void ProcessIncomingTcp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (packet.SourcePort == _tcpRelay.Port && TryRestoreTcpServerToClient(buffer, packet))
        {
            Revert(buffer);
            return;
        }

        var relayKey = new TcpRelayKey(packet.SourceAddress, packet.DestinationPort, packet.SourcePort);
        if (_tcpRelay.IsRelayOutboundFlow(relayKey))
        {
            LogDetail(
                $"PASS RELAY TCP IN flags={FormatTcpFlags(packet.TcpFlags)} payload={packet.TcpPayloadLength} flow={packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}",
                $"tcp-relay-in:{packet.SourceAddress}:{packet.SourcePort}:{packet.DestinationAddress}:{packet.DestinationPort}:{packet.TcpFlags}:{packet.TcpPayloadLength > 0}",
                packet.TcpPayloadLength > 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(2));
        }

        Pass(buffer);
    }

    private void RedirectTcpClientToRelay(NdisApi.IntermediateBuffer* buffer, PacketView packet, DirectRelayTarget target)
    {
        packet.SwapEthernetAddresses();
        packet.SwapIpAddresses();
        packet.DestinationPort = _tcpRelay.Port;
        packet.RecalculateChecksums();
        buffer->Length = (uint)packet.PacketLength;

        if (packet.IsSynOnly || packet.TcpPayloadLength > 0 || packet.IsClosing)
        {
            LogDetail(
                $"REDIRECT TCP flags={FormatTcpFlags(packet.TcpFlags)} payload={packet.TcpPayloadLength} app={target.AppLabel} appLocal={target.ClientEndpoint} client={packet.DestinationAddress}:{packet.SourcePort} target={target.RemoteEndpoint}",
                $"tcp-redirect:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}:{packet.TcpFlags}:{packet.TcpPayloadLength > 0}",
                packet.TcpPayloadLength > 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(2));
        }

        _packetsRedirected++;
        LogPacketStats();
    }

    private bool TryRestoreTcpServerToClient(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        var key = packet.DestinationClientKey;
        if (!_tcpRelay.TryGetTarget(key, out var target))
        {
            return false;
        }

        LogDetail(
            $"RESTORE TCP RECV flags={FormatTcpFlags(packet.TcpFlags)} payload={packet.TcpPayloadLength} app={target.AppLabel} appLocal={target.ClientEndpoint} from={target.RemoteEndpoint} relayLocalPort={_tcpRelay.Port} packetLen={packet.PacketLength}",
            $"tcp-restore:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}:{packet.TcpFlags}:{packet.TcpPayloadLength > 0}",
            packet.TcpPayloadLength > 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(2));
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
        if (packet.SourcePort == _udpRelay.Port)
        {
            if (TryRestoreUdpServerToClient(buffer, packet))
            {
                Revert(buffer);
            }
            else
            {
                LogDetail(
                    $"UDP relay source packet was not restored {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} payloadBytes={packet.UdpPayload.Length} prefix={FormatBytes(packet.UdpPayload, 8)}",
                    $"udp-relay-source-not-restored:{packet.SourceAddress}:{packet.SourcePort}:{packet.DestinationAddress}:{packet.DestinationPort}",
                    TimeSpan.FromSeconds(1));
                Pass(buffer);
            }

            return;
        }

        if (_udpRelay.IsRelayOutboundEndpoint(packet.UdpEndpoint))
        {
            Pass(buffer);
            return;
        }

        var relayKey = new UdpRelayKey(packet.SourceAddress, packet.SourcePort, packet.DestinationAddress, packet.DestinationPort);
        if (_udpRelay.TryGetTarget(relayKey, out var existingTarget))
        {
            _udpRelay.Refresh(relayKey);
            if (RedirectUdpClientToRelay(buffer, packet, existingTarget))
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
            if (packet.SourcePort == 53 || packet.DestinationPort == 53)
            {
                LogDetail(
                    $"UDP DNS owner miss {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}; packet will pass without relay.",
                    "udp-dns-owner-miss",
                    TimeSpan.FromSeconds(5));
            }

            Pass(buffer);
            return;
        }

        if (!_configuration.Current.TryGetMatchingPattern(process, out var matchedPattern, out _))
        {
            if (packet.SourcePort == 53 || packet.DestinationPort == 53)
            {
                LogDetail(
                    $"UDP DNS non-target {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} pid={process.ProcessId} name={process.Name}",
                    "udp-dns-non-target",
                    TimeSpan.FromSeconds(5));
            }

            Pass(buffer);
            return;
        }

        LogAppConnection("UDP", packet, process, matchedPattern);
        LogDetail(
            $"UDP APP MATCH {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} pid={process.ProcessId} name={process.Name} path={process.Path} pattern={matchedPattern}",
            $"udp-app-match:{process.ProcessId}:{packet.DestinationAddress}:{packet.DestinationPort}",
            TimeSpan.FromSeconds(2));
        var target = CreateTarget(buffer, packet, process, matchedPattern);
        _udpRelay.Register(relayKey, target);
        if (RedirectUdpClientToRelay(buffer, packet, target))
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

    private bool RedirectUdpClientToRelay(NdisApi.IntermediateBuffer* buffer, PacketView packet, DirectRelayTarget target)
    {
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
        LogDetail(
            $"REDIRECT UDP app={target.AppLabel} appLocal={target.ClientEndpoint} client={packet.DestinationAddress}:{packet.SourcePort} target={target.RemoteEndpoint}",
            $"udp-redirect:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
            TimeSpan.FromSeconds(2));
        _packetsRedirected++;
        LogPacketStats();
        return true;
    }

    private bool TryRestoreUdpServerToClient(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (!TryReadUdpRelayHeader(packet.UdpPayload, packet.AddressFamily, out var remoteAddress, out var remotePort, out var headerSize))
        {
            return false;
        }

        var key = new UdpRelayKey(packet.DestinationAddress, packet.DestinationPort, remoteAddress, remotePort);
        if (!_udpRelay.TryGetTarget(key, out var target))
        {
            target = new DirectRelayTarget(remoteAddress, remotePort, _timeProvider.GetUtcNow());
        }

        LogDetail(
            $"RESTORE UDP RECV app={target.AppLabel} appLocal={target.ClientEndpoint} from={target.RemoteEndpoint} relayLocalPort={_udpRelay.Port} payloadBytes={Math.Max(0, packet.UdpPayload.Length - headerSize)}",
            $"udp-restore:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
            TimeSpan.FromSeconds(2));

        if (!packet.TryRemoveUdpPayloadPrefix(headerSize))
        {
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

    private void InjectUdpResponseToClient(DirectRelayTarget target, IPEndPoint remoteEndPoint, ReadOnlyMemory<byte> payload)
    {
        if (target.ClientAddress is null || target.ClientPort == 0)
        {
            LogDetail(
                $"UDP inject skipped because client endpoint is unknown app={target.AppLabel} from={remoteEndPoint}",
                $"udp-inject-no-client:{target.ProcessId}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        if (target.AdapterHandle == IntPtr.Zero)
        {
            LogDetail(
                $"UDP inject skipped because adapter is unknown app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint}",
                $"udp-inject-no-adapter:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        var clientAddress = NetworkAddress.Normalize(target.ClientAddress);
        var remoteAddress = NetworkAddress.Normalize(remoteEndPoint.Address);
        if (clientAddress.AddressFamily != remoteAddress.AddressFamily)
        {
            LogDetail(
                $"UDP inject skipped because address families differ app={target.AppLabel} client={clientAddress} remote={remoteAddress}",
                $"udp-inject-family-mismatch:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        if (target.InboundEthernetSource is not { Length: 6 } ethernetSource
            || target.InboundEthernetDestination is not { Length: 6 } ethernetDestination)
        {
            LogDetail(
                $"UDP inject skipped because ethernet addresses are unknown app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint}",
                $"udp-inject-no-ethernet:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        var payloadSpan = payload.Span;
        var ipHeaderLength = clientAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        var packetLength = PacketView.EthernetHeaderLength + ipHeaderLength + 8 + payloadSpan.Length;
        if (packetLength > NdisApi.MaxEtherFrame)
        {
            LogDetail(
                $"UDP inject skipped because packet is too large length={packetLength} app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint}",
                $"udp-inject-too-large:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        var buffer = default(NdisApi.IntermediateBuffer);
        buffer.AdapterOrListFlink = target.AdapterHandle;
        buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
        buffer.Length = (uint)packetLength;
        var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
        frame[..packetLength].Clear();
        ethernetDestination.CopyTo(frame[..6]);
        ethernetSource.CopyTo(frame.Slice(6, 6));

        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            BinaryPrimitives.WriteUInt16BigEndian(frame.Slice(12, 2), PacketView.EtherTypeIpv4);
            BuildIpv4UdpPacket(frame.Slice(PacketView.EthernetHeaderLength), remoteAddress, clientAddress, (ushort)remoteEndPoint.Port, target.ClientPort, payloadSpan);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(frame.Slice(12, 2), PacketView.EtherTypeIpv6);
            BuildIpv6UdpPacket(frame.Slice(PacketView.EthernetHeaderLength), remoteAddress, clientAddress, (ushort)remoteEndPoint.Port, target.ClientPort, payloadSpan);
        }

        var request = CreateRequest(&buffer);
        if (!NdisApi.SendPacketToMstcp(_driverHandle, ref request))
        {
            LogDetail(
                $"UDP inject SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint} length={packetLength} win32={NdisApi.LastWin32Error}",
                $"udp-inject-send-failed:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        LogDetail(
            $"RESTORE UDP RECV app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint} injectedBytes={payloadSpan.Length}",
            $"udp-inject:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
            TimeSpan.FromSeconds(2));
    }

    private static void BuildIpv4UdpPacket(Span<byte> packet, IPAddress sourceAddress, IPAddress destinationAddress, ushort sourcePort, ushort destinationPort, ReadOnlySpan<byte> payload)
    {
        var totalLength = 20 + 8 + payload.Length;
        packet[0] = 0x45;
        packet[1] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(2, 2), (ushort)totalLength);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(4, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(6, 2), 0);
        packet[8] = 64;
        packet[9] = PacketView.ProtocolUdp;
        sourceAddress.GetAddressBytes().CopyTo(packet.Slice(12, 4));
        destinationAddress.GetAddressBytes().CopyTo(packet.Slice(16, 4));
        var ipChecksum = ComputeOnesComplement(packet[..20]);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(10, 2), ipChecksum);

        var udp = packet.Slice(20, 8 + payload.Length);
        BinaryPrimitives.WriteUInt16BigEndian(udp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(4, 2), (ushort)(8 + payload.Length));
        payload.CopyTo(udp[8..]);
        var checksum = ComputeUdpChecksum(sourceAddress, destinationAddress, PacketView.ProtocolUdp, udp);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(6, 2), checksum == 0 ? (ushort)0xFFFF : checksum);
    }

    private static void BuildIpv6UdpPacket(Span<byte> packet, IPAddress sourceAddress, IPAddress destinationAddress, ushort sourcePort, ushort destinationPort, ReadOnlySpan<byte> payload)
    {
        var payloadLength = 8 + payload.Length;
        packet[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(4, 2), (ushort)payloadLength);
        packet[6] = PacketView.ProtocolUdp;
        packet[7] = 64;
        sourceAddress.GetAddressBytes().CopyTo(packet.Slice(8, 16));
        destinationAddress.GetAddressBytes().CopyTo(packet.Slice(24, 16));

        var udp = packet.Slice(40, payloadLength);
        BinaryPrimitives.WriteUInt16BigEndian(udp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(4, 2), (ushort)payloadLength);
        payload.CopyTo(udp[8..]);
        var checksum = ComputeUdpChecksum(sourceAddress, destinationAddress, PacketView.ProtocolUdp, udp);
        BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(6, 2), checksum == 0 ? (ushort)0xFFFF : checksum);
    }

    private static ushort ComputeUdpChecksum(IPAddress sourceAddress, IPAddress destinationAddress, byte protocol, ReadOnlySpan<byte> udpDatagram)
    {
        uint sum = 0;
        var sourceBytes = sourceAddress.GetAddressBytes();
        var destinationBytes = destinationAddress.GetAddressBytes();
        sum = AddChecksumBytes(sum, sourceBytes);
        sum = AddChecksumBytes(sum, destinationBytes);
        if (sourceAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            sum += protocol;
            sum += (uint)udpDatagram.Length;
        }
        else
        {
            sum += (uint)(udpDatagram.Length >> 16);
            sum += (uint)(udpDatagram.Length & 0xFFFF);
            sum += protocol;
        }

        sum = AddChecksumBytes(sum, udpDatagram);
        return FoldChecksum(sum);
    }

    private static ushort ComputeOnesComplement(ReadOnlySpan<byte> data)
    {
        return FoldChecksum(AddChecksumBytes(0, data));
    }

    private static uint AddChecksumBytes(uint sum, ReadOnlySpan<byte> data)
    {
        var i = 0;
        for (; i + 1 < data.Length; i += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
        }

        if (i < data.Length)
        {
            sum += (uint)(data[i] << 8);
        }

        return sum;
    }

    private static ushort FoldChecksum(uint sum)
    {
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    private DirectRelayTarget CreateTarget(NdisApi.IntermediateBuffer* buffer, PacketView packet, ProcessInfo process, string? matchedPattern)
    {
        return new DirectRelayTarget(
            packet.DestinationAddress,
            packet.DestinationPort,
            _timeProvider.GetUtcNow(),
            process.ProcessId,
            process.Name,
            process.Path,
            matchedPattern ?? string.Empty,
            packet.SourceAddress,
            packet.SourcePort,
            buffer->AdapterOrListFlink,
            packet.GetEthernetDestination(),
            packet.GetEthernetSource());
    }

    private void LogAppConnection(string protocol, PacketView packet, ProcessInfo process, string? matchedPattern)
    {
        _log(
            $"APP {protocol} CONNECT app={process.Name} pid={process.ProcessId} local={packet.SourceAddress}:{packet.SourcePort} target={packet.DestinationAddress}:{packet.DestinationPort} pattern={matchedPattern}");
    }

    private ProcessInfo? LookupTcpOwner(PacketView packet)
    {
        var process = _processLookup.LookupTcpOwner(packet.Session, forceRefresh: packet.IsSynOnly);
        if (process is not null || !packet.IsSynOnly)
        {
            return process;
        }

        for (var attempt = 0; attempt < 6; attempt++)
        {
            Thread.Sleep(30);
            process = _processLookup.LookupTcpOwner(packet.Session, forceRefresh: true);
            if (process is not null)
            {
                return process;
            }
        }

        LogDetail(
            $"TCP SYN owner miss session={packet.Session}; packet will pass without relay because no owning process was found yet.",
            "tcp-syn-owner-miss",
            TimeSpan.FromSeconds(5));
        return null;
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
        _packetsPassed++;
        LogPacketStats();
        if (buffer->DeviceFlags == NdisApi.PacketFlagOnSend)
        {
            SendToAdapter(buffer);
        }
        else
        {
            SendToMstcp(buffer);
        }
    }

    private void LogPacketStats()
    {
        if (!_detailedLogging)
        {
            return;
        }

        var now = _timeProvider.GetUtcNow();
        if (_lastPacketStatsLog != default && now - _lastPacketStatsLog < TimeSpan.FromSeconds(5))
        {
            return;
        }

        _lastPacketStatsLog = now;
        _log($"Packet stats: read={_packetsRead}, passed={_packetsPassed}, redirected={_packetsRedirected}");
    }

    private void LogDetail(string message, string key, TimeSpan interval)
    {
        if (!_detailedLogging)
        {
            return;
        }

        var now = _timeProvider.GetUtcNow();
        if (_detailLogTimes.TryGetValue(key, out var lastLogged) && now - lastLogged < interval)
        {
            return;
        }

        _detailLogTimes[key] = now;
        _log(message);
    }

    private static string FormatTcpFlags(byte flags)
    {
        Span<char> chars = stackalloc char[8];
        var index = 0;
        if ((flags & 0x01) != 0) chars[index++] = 'F';
        if ((flags & 0x02) != 0) chars[index++] = 'S';
        if ((flags & 0x04) != 0) chars[index++] = 'R';
        if ((flags & 0x08) != 0) chars[index++] = 'P';
        if ((flags & 0x10) != 0) chars[index++] = 'A';
        if ((flags & 0x20) != 0) chars[index++] = 'U';
        if ((flags & 0x40) != 0) chars[index++] = 'E';
        if ((flags & 0x80) != 0) chars[index++] = 'C';
        return index == 0 ? "none" : new string(chars[..index]);
    }

    private static string FormatBytes(ReadOnlySpan<byte> bytes, int maxLength)
    {
        if (bytes.IsEmpty || maxLength <= 0)
        {
            return string.Empty;
        }

        var length = Math.Min(bytes.Length, maxLength);
        Span<char> chars = stackalloc char[length * 2];
        for (var i = 0; i < length; i++)
        {
            var value = bytes[i];
            chars[i * 2] = GetHexChar(value >> 4);
            chars[(i * 2) + 1] = GetHexChar(value & 0x0F);
        }

        return new string(chars);
    }

    private static char GetHexChar(int value)
    {
        return (char)(value < 10 ? '0' + value : 'A' + value - 10);
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
        if (!NdisApi.SendPacketToMstcp(_driverHandle, ref request))
        {
            LogDetail(
                $"SendPacketToMstcp failed. adapter=0x{request.AdapterHandle.ToInt64():X} length={buffer->Length} flags={buffer->DeviceFlags} win32={NdisApi.LastWin32Error}",
                "send-mstcp-failed",
                TimeSpan.FromSeconds(2));
        }
    }

    private void SendToAdapter(NdisApi.IntermediateBuffer* buffer)
    {
        var request = CreateRequest(buffer);
        if (!NdisApi.SendPacketToAdapter(_driverHandle, ref request))
        {
            LogDetail(
                $"SendPacketToAdapter failed. adapter=0x{request.AdapterHandle.ToInt64():X} length={buffer->Length} flags={buffer->DeviceFlags} win32={NdisApi.LastWin32Error}",
                "send-adapter-failed",
                TimeSpan.FromSeconds(2));
        }
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
