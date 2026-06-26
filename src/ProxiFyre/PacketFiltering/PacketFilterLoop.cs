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
        var processInfo = _processLookup.LookupUdpOwner(packet.UdpEndpoint);
        var processName = processInfo?.Name ?? "unknown";
        var processId = processInfo?.ProcessId ?? 0;

        // 1. Log Leigod's own UDP traffic
        if (processName.Contains("leishen", StringComparison.OrdinalIgnoreCase) || processName.Contains("leigod", StringComparison.OrdinalIgnoreCase))
        {
            _log($"[LEIGOD UDP OUT] {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} (Process={processName} PID={processId} PayloadLen={packet.UdpPayload.Length})");
        }

        // 2. Log any DNS queries (dest port 53 or parses as DNS query)
        bool isPort53 = packet.SourcePort == 53 || packet.DestinationPort == 53;
        bool isDnsQuery = TryGetDnsQueryDomain(packet.UdpPayload, out var domain);
        if (isPort53 || isDnsQuery)
        {
            _log($"[UDP DNS OUT] {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} (Process={processName} PID={processId} DnsQuery={isDnsQuery} Domain={domain})");
        }

        if (TryHandleDnsSpoof(buffer, packet))
        {
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
        var localEndpoint = new UdpEndpointKey(packet.DestinationAddress, packet.DestinationPort);
        var processInfo = _processLookup.LookupUdpOwner(localEndpoint);
        var processName = processInfo?.Name ?? "unknown";
        var processId = processInfo?.ProcessId ?? 0;

        // 1. Log Leigod's own UDP traffic
        if (processName.Contains("leishen", StringComparison.OrdinalIgnoreCase) || processName.Contains("leigod", StringComparison.OrdinalIgnoreCase))
        {
            _log($"[LEIGOD UDP IN] {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} (Process={processName} PID={processId} PayloadLen={packet.UdpPayload.Length})");
        }

        // 2. Log any DNS traffic (source/dest port 53)
        bool isPort53 = packet.SourcePort == 53 || packet.DestinationPort == 53;
        if (isPort53)
        {
            _log($"[UDP DNS IN] {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} (Process={processName} PID={processId})");
        }

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

    private bool TryHandleDnsSpoof(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        if (!_configuration.Current.EnableFakeIpWhitelist)
        {
            return false;
        }

        bool isDnsPort = packet.DestinationPort == 53 || packet.DestinationPort == 5353;
        if (!isDnsPort || !packet.IsUdp)
        {
            return false;
        }

        var process = _processLookup.LookupUdpOwner(packet.UdpEndpoint);

        var payload = packet.UdpPayload;
        if (payload.Length < 12)
        {
            return false;
        }

        // Read DNS Header
        ushort transactionId = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        ushort flags = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        ushort qCount = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));

        if (qCount == 0 || (flags & 0x8000) != 0) // Only query, not response
        {
            return false;
        }

        // Parse QNAME
        int offset = 12;
        var domain = new System.Text.StringBuilder();
        while (offset < payload.Length)
        {
            byte len = payload[offset];
            if (len == 0)
            {
                offset++;
                break;
            }
            if (offset + 1 + len > payload.Length)
            {
                return false;
            }

            if (domain.Length > 0)
            {
                domain.Append('.');
            }
            domain.Append(System.Text.Encoding.ASCII.GetString(payload.Slice(offset + 1, len)));
            offset += 1 + len;
        }

        if (offset + 4 > payload.Length)
        {
            return false;
        }

        ushort qType = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
        offset += 4;

        string queryDomain = domain.ToString();
        // Check if query is fakeip format, e.g. fakeip-140-82-113-3.store.steampowered.com
        if ((qType == 1 || qType == 28) && queryDomain.StartsWith("fakeip-", StringComparison.OrdinalIgnoreCase))
        {
            int firstDot = queryDomain.IndexOf('.');
            if (firstDot == -1) return false;

            string firstLabel = queryDomain[..firstDot]; // "fakeip-140-82-113-3"
            string[] parts = firstLabel.Split('-');
            if (parts.Length != 5) return false; // Must be "fakeip", "140", "82", "113", "3"

            if (!IPAddress.TryParse($"{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}", out var fakeIp))
            {
                return false;
            }

            int questionLength = offset - 12;
            int ipLength = qType == 1 ? 4 : 16;
            int dnsResponseLength = 12 + questionLength + 12 + ipLength;
            byte[] dnsResponse = new byte[dnsResponseLength];

            // 1. Header
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(0, 2), transactionId);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(2, 2), 0x8180); // Response, No error
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(4, 2), 1);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(6, 2), 1);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(8, 2), 0);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(10, 2), 0);

            // 2. Question
            payload.Slice(12, questionLength).CopyTo(dnsResponse.AsSpan(12));

            // 3. Answer
            int answerOffset = 12 + questionLength;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(answerOffset, 2), 0xC00C);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(answerOffset + 2, 2), qType); // Type A (1) or AAAA (28)
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(answerOffset + 4, 2), 1);    // Class IN
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(dnsResponse.AsSpan(answerOffset + 6, 4), 60);   // TTL 60
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(dnsResponse.AsSpan(answerOffset + 10, 2), (ushort)ipLength);

            if (qType == 1)
            {
                fakeIp.GetAddressBytes().CopyTo(dnsResponse.AsSpan(answerOffset + 12, 4));
            }
            else
            {
                // Write IPv4-mapped IPv6 address (16 bytes)
                byte[] ipv6Bytes = new byte[16];
                ipv6Bytes[10] = 0xFF;
                ipv6Bytes[11] = 0xFF;
                fakeIp.GetAddressBytes().CopyTo(ipv6Bytes.AsSpan(12, 4));
                ipv6Bytes.CopyTo(dnsResponse.AsSpan(answerOffset + 12, 16));
            }

            // 1. Send the response with the original queried port to satisfy the client application
            InjectUdpResponse(buffer->AdapterOrListFlink, packet, packet.DestinationPort, dnsResponse);

            // 2. If the query came from a non-standard port (like 5353), also inject a response with source port 53 
            // to trigger Leigod's WFP driver to whitelist the IP
            if (packet.DestinationPort != 53)
            {
                InjectUdpResponse(buffer->AdapterOrListFlink, packet, 53, dnsResponse);
            }

            var processInfoStr = process != null ? $"process={process.Name} pid={process.ProcessId}" : "process=unknown";
            _log($"[DNS SPOOF] Spoofed {queryDomain} (Type={qType}) -> {fakeIp} ({processInfoStr}) (TargetPort={packet.DestinationPort})");
            return true;
        }

        return false;
    }

    private void InjectUdpResponse(IntPtr adapterHandle, PacketView originalQuery, ushort sourcePort, ReadOnlySpan<byte> dnsPayload)
    {
        var clientAddress = originalQuery.SourceAddress;
        var dnsAddress = originalQuery.DestinationAddress;
        var clientPort = originalQuery.SourcePort;

        var ethernetSource = originalQuery.GetEthernetSource();
        var ethernetDestination = originalQuery.GetEthernetDestination();

        var ipHeaderLength = clientAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        var packetLength = PacketView.EthernetHeaderLength + ipHeaderLength + 8 + dnsPayload.Length;

        var buffer = default(NdisApi.IntermediateBuffer);
        buffer.AdapterOrListFlink = adapterHandle;
        buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
        buffer.Length = (uint)packetLength;

        var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
        frame[..packetLength].Clear();

        ethernetSource.CopyTo(frame[..6]); // Destination MAC of response = Source MAC of query
        ethernetDestination.CopyTo(frame.Slice(6, 6)); // Source MAC of response = Destination MAC of query

        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(frame.Slice(12, 2), PacketView.EtherTypeIpv4);
            BuildIpv4UdpPacket(
                frame.Slice(PacketView.EthernetHeaderLength),
                dnsAddress,
                clientAddress,
                sourcePort,
                clientPort,
                dnsPayload);
        }
        else
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(frame.Slice(12, 2), PacketView.EtherTypeIpv6);
            BuildIpv6UdpPacket(
                frame.Slice(PacketView.EthernetHeaderLength),
                dnsAddress,
                clientAddress,
                sourcePort,
                clientPort,
                dnsPayload);
        }

        var request = CreateRequest(&buffer);
        NdisApi.SendPacketToMstcp(_driverHandle, ref request);
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

    private static bool TryGetDnsQueryDomain(ReadOnlySpan<byte> payload, out string domain)
    {
        domain = string.Empty;
        if (payload.Length < 12)
        {
            return false;
        }

        ushort flags = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        ushort qCount = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
        ushort ansCount = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(6, 2));
        ushort nsCount = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(8, 2));
        ushort addCount = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(10, 2));

        // Basic DNS query checks
        if (qCount == 0 || (flags & 0x8000) != 0 || ansCount != 0 || nsCount != 0 || addCount > 1)
        {
            return false;
        }

        try
        {
            int offset = 12;
            var sb = new System.Text.StringBuilder();
            while (offset < payload.Length)
            {
                byte len = payload[offset];
                if (len == 0)
                {
                    offset++;
                    break;
                }

                if ((len & 0xC0) != 0 || len > 63)
                {
                    return false;
                }

                if (offset + 1 + len > payload.Length)
                {
                    return false;
                }

                for (int i = 0; i < len; i++)
                {
                    char c = (char)payload[offset + 1 + i];
                    if (!char.IsLetterOrDigit(c) && c != '-' && c != '_' && c != '.')
                    {
                        return false;
                    }
                }

                if (sb.Length > 0)
                {
                    sb.Append('.');
                }
                sb.Append(System.Text.Encoding.ASCII.GetString(payload.Slice(offset + 1, len)));
                offset += 1 + len;
            }

            if (sb.Length > 0)
            {
                domain = sb.ToString();
                return true;
            }
        }
        catch
        {
        }

        return false;
    }
}
