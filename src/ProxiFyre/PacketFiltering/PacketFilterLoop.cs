using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;

namespace ProxiFyre;

internal sealed unsafe class PacketFilterLoop : IDisposable
{
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
    private readonly object _outboundBypassSync = new();
    private readonly Dictionary<RelayOutboundFlow, int> _outboundBypassFlows = [];
    private DateTimeOffset _lastPacketStatsLog;
    private long _packetsRead;
    private long _packetsPassed;
    private long _packetsRedirected;
    private IntPtr _driverHandle;
    private CancellationToken _cancellationToken;
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
        _tcpRelay.SetPacketInjector(InjectTcpSegmentToClient);
        _udpRelay.SetResponseInjector(InjectUdpResponseToClient);
        _tcpRelay.SetOutboundBypass(RegisterOutboundBypass, UnregisterOutboundBypass);
        _udpRelay.SetOutboundBypass(RegisterOutboundBypass, UnregisterOutboundBypass);
    }

    public Task RunAsync(CancellationToken cancellationToken)
    {
        return Task.Run(() => Run(cancellationToken), cancellationToken);
    }

    private void Run(CancellationToken cancellationToken)
    {
        _cancellationToken = cancellationToken;
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
                // Direct relay only needs to inspect app-originated packets. Keeping
                // receive traffic on the normal stack preserves Windows traffic attribution.
                Flags = NdisApi.MstcpFlagSentTunnel
            };

            if (!NdisApi.SetAdapterMode(_driverHandle, ref mode))
            {
                _log($"Failed to set send tunnel mode for adapter handle 0x{adapter.ToInt64():X}.");
            }
        }

        if (_adapters.Count == 0)
        {
            throw new InvalidOperationException("No TCP/IP adapters were returned by WinpkFilter.");
        }

        _log($"Filtering {_adapters.Count} adapter(s) on send path.");
    }

    private void RegisterOutboundBypass(RelayOutboundFlow flow)
    {
        lock (_outboundBypassSync)
        {
            _outboundBypassFlows.TryGetValue(flow, out var count);
            _outboundBypassFlows[flow] = count + 1;
            ApplyOutboundBypassFilters();
        }

        LogDetail($"Registered relay outbound kernel pass flow: {flow}", $"relay-pass-register:{flow}", TimeSpan.FromSeconds(2));
    }

    private void UnregisterOutboundBypass(RelayOutboundFlow flow)
    {
        lock (_outboundBypassSync)
        {
            if (!_outboundBypassFlows.TryGetValue(flow, out var count))
            {
                return;
            }

            if (count <= 1)
            {
                _outboundBypassFlows.Remove(flow);
            }
            else
            {
                _outboundBypassFlows[flow] = count - 1;
            }

            ApplyOutboundBypassFilters();
        }

        LogDetail($"Unregistered relay outbound kernel pass flow: {flow}", $"relay-pass-unregister:{flow}", TimeSpan.FromSeconds(2));
    }

    private void ApplyOutboundBypassFilters()
    {
        if (_driverHandle == IntPtr.Zero)
        {
            return;
        }

        var filters = new List<NdisApi.StaticFilter>(_outboundBypassFlows.Count * Math.Max(_adapters.Count, 1));
        foreach (var flow in _outboundBypassFlows.Keys)
        {
            foreach (var adapter in _adapters)
            {
                filters.Add(NdisApi.CreateOutboundPassFilter(
                    adapter,
                    flow.Protocol,
                    flow.RemoteAddress,
                    flow.LocalPort,
                    flow.RemotePort));
            }
        }

        if (!NdisApi.SetPacketFilterTable(_driverHandle, filters))
        {
            LogThrottled(
                $"SetPacketFilterTable failed for relay outbound pass flows count={filters.Count} win32={NdisApi.LastWin32Error}",
                "set-static-filter-failed",
                TimeSpan.FromSeconds(2));
        }
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

        if (_tcpRelay.TryGetConnection(relayKey, out var existingConnection))
        {
            var payload = packet.TcpPayload.ToArray();
            _ = existingConnection.SendClientPayloadAsync(
                packet.TcpSequenceNumber,
                packet.TcpAcknowledgmentNumber,
                packet.TcpWindow,
                payload,
                (packet.TcpFlags & PacketView.TcpFlagFin) != 0,
                (packet.TcpFlags & PacketView.TcpFlagRst) != 0,
                _cancellationToken);
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
        var clientKey = new TcpClientKey(packet.SourceAddress, packet.SourcePort);
        _tcpRelay.RegisterSyn(relayKey, clientKey, target, packet.TcpSequenceNumber, packet.TcpWindow, _cancellationToken);
        _packetsRedirected++;
        LogPacketStats();
    }

    private void ProcessIncomingTcp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
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

    private void ProcessOutgoingUdp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (_udpRelay.IsRelayOutboundEndpoint(packet.UdpEndpoint))
        {
            Pass(buffer);
            return;
        }

        var relayKey = new UdpRelayKey(packet.SourceAddress, packet.SourcePort, packet.DestinationAddress, packet.DestinationPort);
        if (_udpRelay.TryGetTarget(relayKey, out var existingTarget))
        {
            _udpRelay.Refresh(relayKey);
            SendUdpClientToRemote(packet, relayKey, existingTarget);
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
        SendUdpClientToRemote(packet, relayKey, target);
    }

    private void ProcessIncomingUdp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        Pass(buffer);
    }

    private void SendUdpClientToRemote(PacketView packet, UdpRelayKey relayKey, DirectRelayTarget target)
    {
        var remoteAddress = packet.DestinationAddress;
        var remotePort = packet.DestinationPort;
        var payload = packet.UdpPayload.ToArray();
        LogDetail(
            $"DIRECT UDP CAPTURE app={target.AppLabel} appLocal={target.ClientEndpoint} client={packet.SourceAddress}:{packet.SourcePort} target={target.RemoteEndpoint} payloadBytes={payload.Length}",
            $"udp-redirect:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
            TimeSpan.FromSeconds(2));
        _packetsRedirected++;
        LogPacketStats();
        _udpRelay.SendToRemoteAsync(relayKey, target, payload, remoteAddress, remotePort)
            .ContinueWith(
                task =>
                {
                    var ex = task.Exception?.GetBaseException();
                    if (ex is null or OperationCanceledException)
                    {
                        return;
                    }

                    _log($"DIRECT UDP send failed app={target.AppLabel} appLocal={target.ClientEndpoint} client={relayKey.ClientAddress}:{relayKey.ClientPort} target={target.RemoteEndpoint}: {ex.Message}");
                    _udpRelay.Remove(relayKey);
                },
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted,
                TaskScheduler.Default);
    }

    private void InjectTcpSegmentToClient(DirectRelayTarget target, uint sequenceNumber, uint acknowledgmentNumber, byte flags, ushort window, ReadOnlyMemory<byte> payload)
    {
        if (target.ClientAddress is null || target.ClientPort == 0)
        {
            LogDetail(
                $"TCP inject skipped because client endpoint is unknown app={target.AppLabel}",
                $"tcp-inject-no-client:{target.ProcessId}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        if (target.AdapterHandle == IntPtr.Zero)
        {
            LogDetail(
                $"TCP inject skipped because adapter is unknown app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"tcp-inject-no-adapter:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        var clientAddress = NetworkAddress.Normalize(target.ClientAddress);
        var remoteAddress = NetworkAddress.Normalize(target.RemoteAddress);
        if (clientAddress.AddressFamily != remoteAddress.AddressFamily)
        {
            LogDetail(
                $"TCP inject skipped because address families differ app={target.AppLabel} client={clientAddress} remote={remoteAddress}",
                $"tcp-inject-family-mismatch:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        if (target.InboundEthernetSource is not { Length: 6 } ethernetSource
            || target.InboundEthernetDestination is not { Length: 6 } ethernetDestination)
        {
            LogDetail(
                $"TCP inject skipped because ethernet addresses are unknown app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"tcp-inject-no-ethernet:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        var payloadSpan = payload.Span;
        var ipHeaderLength = clientAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        var tcpHeaderLength = 20;
        var packetLength = PacketView.EthernetHeaderLength + ipHeaderLength + tcpHeaderLength + payloadSpan.Length;
        if (packetLength > NdisApi.MaxEtherFrame)
        {
            LogDetail(
                $"TCP inject skipped because packet is too large length={packetLength} app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"tcp-inject-too-large:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
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
            BuildIpv4TcpPacket(
                frame.Slice(PacketView.EthernetHeaderLength),
                remoteAddress,
                clientAddress,
                target.RemotePort,
                target.ClientPort,
                sequenceNumber,
                acknowledgmentNumber,
                flags,
                window,
                payloadSpan);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(frame.Slice(12, 2), PacketView.EtherTypeIpv6);
            BuildIpv6TcpPacket(
                frame.Slice(PacketView.EthernetHeaderLength),
                remoteAddress,
                clientAddress,
                target.RemotePort,
                target.ClientPort,
                sequenceNumber,
                acknowledgmentNumber,
                flags,
                window,
                payloadSpan);
        }

        var request = CreateRequest(&buffer);
        if (!NdisApi.SendPacketToMstcp(_driverHandle, ref request))
        {
            LogDetail(
                $"TCP inject SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} length={packetLength} win32={NdisApi.LastWin32Error}",
                $"tcp-inject-send-failed:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return;
        }

        LogDetail(
            $"RESTORE TCP RECV flags={FormatTcpFlags(flags)} app={target.AppLabel} appLocal={target.ClientEndpoint} from={target.RemoteEndpoint} injectedBytes={payloadSpan.Length}",
            $"tcp-inject:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}:{flags}:{payloadSpan.Length > 0}",
            payloadSpan.Length > 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(2));
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

    private static void BuildIpv4TcpPacket(Span<byte> packet, IPAddress sourceAddress, IPAddress destinationAddress, ushort sourcePort, ushort destinationPort, uint sequenceNumber, uint acknowledgmentNumber, byte flags, ushort window, ReadOnlySpan<byte> payload)
    {
        var totalLength = 20 + 20 + payload.Length;
        packet[0] = 0x45;
        packet[1] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(2, 2), (ushort)totalLength);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(4, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(6, 2), 0);
        packet[8] = 64;
        packet[9] = PacketView.ProtocolTcp;
        sourceAddress.GetAddressBytes().CopyTo(packet.Slice(12, 4));
        destinationAddress.GetAddressBytes().CopyTo(packet.Slice(16, 4));
        var ipChecksum = ComputeOnesComplement(packet[..20]);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(10, 2), ipChecksum);

        var tcp = packet.Slice(20, 20 + payload.Length);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(4, 4), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(8, 4), acknowledgmentNumber);
        tcp[12] = 0x50;
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(14, 2), window == 0 ? (ushort)65535 : window);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(18, 2), 0);
        payload.CopyTo(tcp[20..]);
        var checksum = ComputeTransportChecksum(sourceAddress, destinationAddress, PacketView.ProtocolTcp, tcp);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(16, 2), checksum);
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

    private static void BuildIpv6TcpPacket(Span<byte> packet, IPAddress sourceAddress, IPAddress destinationAddress, ushort sourcePort, ushort destinationPort, uint sequenceNumber, uint acknowledgmentNumber, byte flags, ushort window, ReadOnlySpan<byte> payload)
    {
        var payloadLength = 20 + payload.Length;
        packet[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(4, 2), (ushort)payloadLength);
        packet[6] = PacketView.ProtocolTcp;
        packet[7] = 64;
        sourceAddress.GetAddressBytes().CopyTo(packet.Slice(8, 16));
        destinationAddress.GetAddressBytes().CopyTo(packet.Slice(24, 16));

        var tcp = packet.Slice(40, payloadLength);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(4, 4), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(8, 4), acknowledgmentNumber);
        tcp[12] = 0x50;
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(14, 2), window == 0 ? (ushort)65535 : window);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(18, 2), 0);
        payload.CopyTo(tcp[20..]);
        var checksum = ComputeTransportChecksum(sourceAddress, destinationAddress, PacketView.ProtocolTcp, tcp);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(16, 2), checksum);
    }

    private static ushort ComputeUdpChecksum(IPAddress sourceAddress, IPAddress destinationAddress, byte protocol, ReadOnlySpan<byte> udpDatagram)
    {
        var checksum = ComputeTransportChecksum(sourceAddress, destinationAddress, protocol, udpDatagram);
        return checksum == 0 ? (ushort)0xFFFF : checksum;
    }

    private static ushort ComputeTransportChecksum(IPAddress sourceAddress, IPAddress destinationAddress, byte protocol, ReadOnlySpan<byte> datagram)
    {
        uint sum = 0;
        var sourceBytes = sourceAddress.GetAddressBytes();
        var destinationBytes = destinationAddress.GetAddressBytes();
        sum = AddChecksumBytes(sum, sourceBytes);
        sum = AddChecksumBytes(sum, destinationBytes);
        if (sourceAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            sum += protocol;
            sum += (uint)datagram.Length;
        }
        else
        {
            sum += (uint)(datagram.Length >> 16);
            sum += (uint)(datagram.Length & 0xFFFF);
            sum += protocol;
        }

        sum = AddChecksumBytes(sum, datagram);
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

    private void LogThrottled(string message, string key, TimeSpan interval)
    {
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

        if (_driverHandle != IntPtr.Zero)
        {
            NdisApi.ResetPacketFilterTable(_driverHandle);
        }

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
