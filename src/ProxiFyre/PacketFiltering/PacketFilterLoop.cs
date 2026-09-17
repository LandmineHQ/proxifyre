using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace ProxiFyre;

internal sealed unsafe class PacketFilterLoop : IDisposable
{
    private readonly DynamicAppConfiguration _configuration;
    private readonly TcpDirectRelay _tcpRelay;
    private readonly UdpDirectRelay _udpRelay;
    private readonly PacketWakeSignal _wakeSignal;
    private readonly ProcessLookup _processLookup;
    private readonly IpFragmentReassembler _fragmentReassembler;
    private readonly HashSet<IntPtr> _adapters = [];
    private readonly Dictionary<IntPtr, int> _adapterMtus = [];
    private readonly Dictionary<IntPtr, int> _adapterInterfaceIndices = [];
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _detailLogTimes = new();
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
        _fragmentReassembler = new IpFragmentReassembler(_timeProvider);
        _tcpRelay.SetPacketInjector(InjectTcpSegmentToClient);
        _udpRelay.SetResponseInjector(InjectUdpResponseToClient);
        _udpRelay.SetResponseValidator(IsUdpTargetCurrent);
        _udpRelay.SetErrorInjector(InjectUdpErrorToClient);
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
            _adapterMtus[adapter] = adapterList.GetMtu(i) is > 0 and <= ushort.MaxValue
                ? (int)adapterList.GetMtu(i)
                : 1500;
            var interfaceIndex = ResolveInterfaceIndex(
                adapterList.GetName(i),
                adapterList.GetMacAddress(i));
            if (interfaceIndex > 0)
            {
                _adapterInterfaceIndices[adapter] = interfaceIndex;
            }
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

    private static int ResolveInterfaceIndex(string adapterName, byte[] macAddress)
    {
        if (string.IsNullOrWhiteSpace(adapterName))
        {
            return 0;
        }

        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!networkInterface.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase)
                && !networkInterface.Description.Equals(adapterName, StringComparison.OrdinalIgnoreCase)
                && !networkInterface.GetPhysicalAddress().GetAddressBytes().SequenceEqual(macAddress))
            {
                continue;
            }

            var properties = networkInterface.GetIPProperties().GetIPv6Properties();
            if (properties is not null && properties.Index > 0)
            {
                return properties.Index;
            }
        }

        return 0;
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
            if (flow.Dot1q != 0)
            {
                continue;
            }

            var adapters = flow.AdapterHandle != IntPtr.Zero
                ? [flow.AdapterHandle]
                : _adapters;
            foreach (var adapter in adapters)
            {
                filters.Add(NdisApi.CreateOutboundPassFilter(
                    adapter,
                    flow.Protocol,
                    flow.LocalAddress,
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

    private bool IsRelayOutboundFragment(
        ReadOnlySpan<byte> frame,
        int packetLength,
        IntPtr adapterHandle,
        uint dot1q)
    {
        if (!IpFragmentReassembler.TryGetIdentity(
                frame,
                packetLength,
                out var sourceAddress,
                out var destinationAddress,
                out var protocol))
        {
            return false;
        }

        lock (_outboundBypassSync)
        {
            foreach (var flow in _outboundBypassFlows.Keys)
            {
                if (flow.AdapterHandle != adapterHandle
                    || flow.Dot1q != dot1q
                    || flow.Protocol != protocol
                    || !AddressesEqual(flow.LocalAddress, sourceAddress)
                    || !flow.RemoteAddress.Equals(destinationAddress))
                {
                    continue;
                }

                return true;
            }
        }

        return false;
    }

    private static bool AddressesEqual(IPAddress expected, IPAddress actual)
    {
        expected = NetworkAddress.Normalize(expected);
        actual = NetworkAddress.Normalize(actual);
        return expected.Equals(IPAddress.Any)
            || expected.Equals(IPAddress.IPv6Any)
            || expected.Equals(actual);
    }

    private bool TryReadAndProcessPacket()
    {
        _fragmentReassembler.FlushExpired(SendCapturedFragmentToAdapter);

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

        if (buffer->Length > NdisApi.MaxEtherFrame)
        {
            LogThrottled(
                $"Packet exceeds the configured Ethernet buffer length={buffer->Length}.",
                "packet-too-large",
                TimeSpan.FromSeconds(5));
            Pass(buffer);
            return;
        }

        var length = (int)buffer->Length;
        var frame = new Span<byte>(buffer->Data, NdisApi.MaxEtherFrame);

        if (!PacketView.TryParse(frame, length, out var packet))
        {
            if (buffer->DeviceFlags == NdisApi.PacketFlagOnSend)
            {
                if (IsRelayOutboundFragment(
                        frame,
                        length,
                        buffer->AdapterOrListFlink,
                        buffer->Dot1q))
                {
                    Pass(buffer);
                    return;
                }

                var status = _fragmentReassembler.Add(
                    frame,
                    length,
                    buffer->AdapterOrListFlink,
                    buffer->DeviceFlags,
                    buffer->Dot1q,
                    out var reassembled,
                    out var fragmentsToPass);
                if (fragmentsToPass is not null)
                {
                    foreach (var fragment in fragmentsToPass)
                    {
                        SendCapturedFragmentToAdapter(fragment);
                    }
                }

                if (status == FragmentAddStatus.Incomplete)
                {
                    return;
                }

                if (status == FragmentAddStatus.Invalid)
                {
                    return;
                }

                if (status == FragmentAddStatus.Complete && reassembled is not null)
                {
                    ProcessReassembledOutgoing(reassembled);
                    return;
                }
            }

            Pass(buffer);
            return;
        }

        if (buffer->DeviceFlags == NdisApi.PacketFlagOnSend)
        {
            if (!ProcessOutgoing(packet, buffer->AdapterOrListFlink, buffer->Dot1q))
            {
                Pass(buffer);
            }

            return;
        }

        if (buffer->DeviceFlags == NdisApi.PacketFlagOnReceive)
        {
            ProcessIncoming(buffer, packet);
            return;
        }

        Pass(buffer);
    }

    private void ProcessReassembledOutgoing(ReassembledIpPacket reassembled)
    {
        var frame = reassembled.Frame.AsSpan();
        if (!PacketView.TryParse(frame, reassembled.Length, out var packet)
            || !ProcessOutgoing(packet, reassembled.AdapterHandle, reassembled.Dot1q))
        {
            foreach (var fragment in reassembled.Fragments)
            {
                SendCapturedFragmentToAdapter(fragment);
            }
        }
    }

    private void SendCapturedFragmentToAdapter(CapturedPacketFragment fragment)
    {
        var buffer = default(NdisApi.IntermediateBuffer);
        buffer.AdapterOrListFlink = fragment.AdapterHandle;
        buffer.DeviceFlags = fragment.DeviceFlags;
        buffer.Dot1q = fragment.Dot1q;
        buffer.Length = (uint)fragment.Length;
        fragment.Frame.AsSpan(0, fragment.Length).CopyTo(new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame));
        SendToAdapter(&buffer);
    }

    private bool ProcessOutgoing(PacketView packet, IntPtr adapterHandle, uint dot1q)
    {
        if (packet.IsTcp)
        {
            return ProcessOutgoingTcp(packet, adapterHandle, dot1q);
        }

        if (packet.IsUdp)
        {
            return ProcessOutgoingUdp(packet, adapterHandle, dot1q);
        }

        return false;
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

    private bool ProcessOutgoingTcp(PacketView packet, IntPtr adapterHandle, uint dot1q)
    {
        var relayKey = new TcpRelayKey(
            adapterHandle,
            dot1q,
            packet.SourceAddress,
            packet.DestinationAddress,
            packet.SourcePort,
            packet.DestinationPort);
        if (_tcpRelay.IsRelayOutboundFlow(relayKey))
        {
            LogDetail(
                $"PASS RELAY TCP OUT flags={FormatTcpFlags(packet.TcpFlags)} payload={packet.TcpPayloadLength} flow={packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}",
                $"tcp-relay-out:{packet.SourceAddress}:{packet.SourcePort}:{packet.DestinationAddress}:{packet.DestinationPort}:{packet.TcpFlags}:{packet.TcpPayloadLength > 0}",
                packet.TcpPayloadLength > 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(2));
            return false;
        }

        if (_tcpRelay.TryGetConnection(relayKey, out var existingConnection))
        {
            if (existingConnection.IsClosed)
            {
                _tcpRelay.Remove(existingConnection);
            }
            else if (packet.IsInitialSyn
                && packet.TcpPayloadLength == 0
                && existingConnection.ClientInitialSequence != packet.TcpSequenceNumber)
            {
                _tcpRelay.Remove(existingConnection);
            }
            else
            {
                existingConnection.SendClientSegment(CreateTcpSegment(packet));
                return true;
            }
        }

        if (!packet.IsInitialSyn)
        {
            return false;
        }

        if (packet.TcpPayloadLength > 0)
        {
            _tcpRelay.MarkBypassedFlow(relayKey);
            return false;
        }

        if (_tcpRelay.IsBypassedFlow(relayKey))
        {
            return false;
        }

        var process = LookupTcpOwner(packet);
        if (process is null)
        {
            _tcpRelay.MarkBypassedFlow(relayKey);
            return false;
        }

        if (!_configuration.Current.TryGetMatchingPattern(process, out var matchedPattern, out _))
        {
            return false;
        }

        LogAppConnection("TCP", packet, process, matchedPattern);
        LogDetail(
            $"TCP APP MATCH {packet.Session} pid={process.ProcessId} name={process.Name} path={process.Path} pattern={matchedPattern}",
            $"tcp-app-match:{process.ProcessId}:{packet.DestinationAddress}:{packet.DestinationPort}",
            TimeSpan.FromSeconds(2));
        var target = CreateTarget(adapterHandle, dot1q, packet, process, matchedPattern);
        var clientKey = new TcpClientKey(packet.SourceAddress, packet.SourcePort);
        var clientMss = TryGetTcpMss(packet.TcpOptions, out var parsedMss)
            ? parsedMss
            : (ushort)536;
        _tcpRelay.RegisterSyn(
            relayKey,
            clientKey,
            target,
            packet.TcpSequenceNumber,
            packet.TcpWindow,
            _cancellationToken,
            clientMss);
        _packetsRedirected++;
        LogPacketStats();
        return true;
    }

    private void ProcessIncomingTcp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        var relayKey = new TcpRelayKey(
            buffer->AdapterOrListFlink,
            buffer->Dot1q,
            packet.DestinationAddress,
            packet.SourceAddress,
            packet.DestinationPort,
            packet.SourcePort);
        if (_tcpRelay.IsRelayOutboundFlow(relayKey))
        {
            LogDetail(
                $"PASS RELAY TCP IN flags={FormatTcpFlags(packet.TcpFlags)} payload={packet.TcpPayloadLength} flow={packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}",
                $"tcp-relay-in:{packet.SourceAddress}:{packet.SourcePort}:{packet.DestinationAddress}:{packet.DestinationPort}:{packet.TcpFlags}:{packet.TcpPayloadLength > 0}",
                packet.TcpPayloadLength > 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(2));
        }

        Pass(buffer);
    }

    private static TcpSegment CreateTcpSegment(PacketView packet)
    {
        return new TcpSegment(
            packet.TcpSequenceNumber,
            packet.TcpAcknowledgmentNumber,
            packet.TcpFlags,
            packet.TcpWindow,
            packet.TcpUrgentPointer,
            packet.TcpPayload.ToArray(),
            packet.TcpOptions.ToArray());
    }

    private static bool TryGetTcpMss(ReadOnlySpan<byte> options, out ushort mss)
    {
        mss = 0;
        var offset = 0;
        while (offset < options.Length)
        {
            var kind = options[offset++];
            if (kind == 0)
            {
                return false;
            }

            if (kind == 1)
            {
                continue;
            }

            if (offset >= options.Length)
            {
                return false;
            }

            var length = options[offset++];
            if (length < 2 || offset + length - 2 > options.Length)
            {
                return false;
            }

            if (kind == 2 && length == 4)
            {
                mss = BinaryPrimitives.ReadUInt16BigEndian(options.Slice(offset, 2));
                return mss >= 536;
            }

            offset += length - 2;
        }

        return false;
    }

    private bool ProcessOutgoingUdp(PacketView packet, IntPtr adapterHandle, uint dot1q)
    {
        var processInfo = _processLookup.LookupUdpOwner(
            CreateUdpEndpointKey(packet.SourceAddress, packet.SourcePort, adapterHandle));
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

        if (packet.IsLinkLayerBroadcastOrMulticast())
        {
            return false;
        }

        if (TryHandleDnsSpoof(adapterHandle, dot1q, packet))
        {
            return true;
        }

        var relayKey = new UdpRelayKey(
            adapterHandle,
            dot1q,
            packet.SourceAddress,
            packet.SourcePort,
            packet.DestinationAddress,
            packet.DestinationPort);
        if (_udpRelay.IsRelayOutboundFlow(relayKey))
        {
            return false;
        }

        if (_udpRelay.TryGetTarget(relayKey, out var existingTarget))
        {
            var existingProcess = processInfo ?? _processLookup.GetProcessInfo(existingTarget.ProcessId);
            if (existingProcess is not null
                && existingTarget.ProcessId == existingProcess.ProcessId
                && existingTarget.ProcessName.Equals(existingProcess.Name, StringComparison.OrdinalIgnoreCase)
                && existingTarget.ProcessPath.Equals(existingProcess.Path, StringComparison.OrdinalIgnoreCase)
                && existingTarget.AdapterHandle == adapterHandle
                && Equals(existingTarget.ClientAddress, packet.SourceAddress)
                && existingTarget.ClientPort == packet.SourcePort)
            {
                _udpRelay.Refresh(relayKey);
                SendUdpClientToRemote(packet, relayKey, existingTarget);
                return true;
            }
        }

        if (_udpRelay.TryGetTarget(relayKey, out _))
        {
            _udpRelay.Remove(relayKey);
        }

        var process = processInfo ?? _processLookup.LookupUdpOwner(
            CreateUdpEndpointKey(packet.SourceAddress, packet.SourcePort, adapterHandle));
        if (process is null)
        {
            if (packet.SourcePort == 53 || packet.DestinationPort == 53)
            {
                LogDetail(
                    $"UDP DNS owner miss {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}; packet will pass without relay.",
                    "udp-dns-owner-miss",
                    TimeSpan.FromSeconds(5));
            }

            return false;
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

            return false;
        }

        LogAppConnection("UDP", packet, process, matchedPattern);
        LogDetail(
            $"UDP APP MATCH {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} pid={process.ProcessId} name={process.Name} path={process.Path} pattern={matchedPattern}",
            $"udp-app-match:{process.ProcessId}:{packet.DestinationAddress}:{packet.DestinationPort}",
            TimeSpan.FromSeconds(2));
        var target = CreateTarget(adapterHandle, dot1q, packet, process, matchedPattern);
        SendUdpClientToRemote(packet, relayKey, target);
        return true;
    }

    private void ProcessIncomingUdp(NdisApi.IntermediateBuffer* buffer, PacketView packet)
    {
        var localEndpoint = CreateUdpEndpointKey(
            packet.DestinationAddress,
            packet.DestinationPort,
            buffer->AdapterOrListFlink);
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
                    _udpRelay.RemoveIfMatches(relayKey, target);
                },
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted,
                TaskScheduler.Default);
    }

    private bool IsUdpTargetCurrent(DirectRelayTarget target)
    {
        if (target.ClientAddress is null || target.ClientPort == 0)
        {
            return false;
        }

        var owner = _processLookup.LookupUdpOwner(
            CreateUdpEndpointKey(
                target.ClientAddress,
                target.ClientPort,
                target.AdapterHandle,
                target.InterfaceIndex),
            forceRefresh: true);
        return owner is not null
            && owner.ProcessId == target.ProcessId
            && owner.Name.Equals(target.ProcessName, StringComparison.OrdinalIgnoreCase)
            && owner.Path.Equals(target.ProcessPath, StringComparison.OrdinalIgnoreCase);
    }

    private UdpEndpointKey CreateUdpEndpointKey(
        IPAddress address,
        ushort port,
        IntPtr adapterHandle,
        int interfaceIndex = 0)
    {
        if (interfaceIndex <= 0)
        {
            _adapterInterfaceIndices.TryGetValue(adapterHandle, out interfaceIndex);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6
            && address.ScopeId == 0
            && interfaceIndex > 0
            && (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal))
        {
            address = new IPAddress(address.GetAddressBytes(), interfaceIndex);
        }

        return new UdpEndpointKey(address, port);
    }

    private bool InjectTcpSegmentToClient(DirectRelayTarget target, TcpSegment segment)
    {
        if (target.ClientAddress is null || target.ClientPort == 0)
        {
            LogDetail(
                $"TCP inject skipped because client endpoint is unknown app={target.AppLabel}",
                $"tcp-inject-no-client:{target.ProcessId}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        if (target.AdapterHandle == IntPtr.Zero)
        {
            LogDetail(
                $"TCP inject skipped because adapter is unknown app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"tcp-inject-no-adapter:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var clientAddress = NetworkAddress.Normalize(target.ClientAddress);
        var remoteAddress = NetworkAddress.Normalize(target.RemoteAddress);
        if (clientAddress.AddressFamily != remoteAddress.AddressFamily)
        {
            LogDetail(
                $"TCP inject skipped because address families differ app={target.AppLabel} client={clientAddress} remote={remoteAddress}",
                $"tcp-inject-family-mismatch:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        if (target.LinkHeader is not { Length: >= PacketView.EthernetHeaderLength }
            && (target.InboundEthernetSource is not { Length: 6 }
                || target.InboundEthernetDestination is not { Length: 6 }))
        {
            LogDetail(
                $"TCP inject skipped because ethernet addresses are unknown app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"tcp-inject-no-ethernet:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var payloadSpan = segment.Payload.Span;
        var optionSpan = segment.Options.Span;
        if (optionSpan.Length % 4 != 0 || optionSpan.Length > 40)
        {
            LogDetail(
                $"TCP inject skipped because options are invalid app={target.AppLabel} appLocal={target.ClientEndpoint} options={optionSpan.Length}",
                $"tcp-inject-invalid-options:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var linkHeaderLength = target.LinkHeader is { Length: >= PacketView.EthernetHeaderLength } linkHeader
            ? linkHeader.Length
            : PacketView.EthernetHeaderLength;
        var ipHeaderLength = clientAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        var tcpHeaderLength = 20 + optionSpan.Length;
        var packetLength = linkHeaderLength + ipHeaderLength + tcpHeaderLength + payloadSpan.Length;
        if (packetLength > NdisApi.MaxEtherFrame)
        {
            LogDetail(
                $"TCP inject skipped because packet is too large length={packetLength} app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"tcp-inject-too-large:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var buffer = default(NdisApi.IntermediateBuffer);
        buffer.AdapterOrListFlink = target.AdapterHandle;
        buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
        buffer.Dot1q = target.Dot1q;
        buffer.Length = (uint)packetLength;
        var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
        frame[..packetLength].Clear();
        WriteInboundLinkHeader(frame, target, linkHeaderLength);

        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv4);
            BuildIpv4TcpPacket(
                frame.Slice(linkHeaderLength),
                remoteAddress,
                clientAddress,
                target.RemotePort,
                target.ClientPort,
                segment.SequenceNumber,
                segment.AcknowledgmentNumber,
                segment.Flags,
                segment.Window,
                segment.UrgentPointer,
                optionSpan,
                payloadSpan);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv6);
            BuildIpv6TcpPacket(
                frame.Slice(linkHeaderLength),
                remoteAddress,
                clientAddress,
                target.RemotePort,
                target.ClientPort,
                segment.SequenceNumber,
                segment.AcknowledgmentNumber,
                segment.Flags,
                segment.Window,
                segment.UrgentPointer,
                optionSpan,
                payloadSpan);
        }

        var request = CreateRequest(&buffer);
        if (!NdisApi.SendPacketToMstcp(_driverHandle, ref request))
        {
            LogDetail(
                $"TCP inject SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} length={packetLength} win32={NdisApi.LastWin32Error}",
                $"tcp-inject-send-failed:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        LogDetail(
            $"RESTORE TCP RECV flags={FormatTcpFlags(segment.Flags)} app={target.AppLabel} appLocal={target.ClientEndpoint} from={target.RemoteEndpoint} injectedBytes={payloadSpan.Length}",
            $"tcp-inject:{target.ProcessId}:{target.ClientEndpoint}:{target.RemoteEndpoint}:{segment.Flags}:{payloadSpan.Length > 0}",
            payloadSpan.Length > 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(2));
        return true;
    }

    private static void WriteInboundLinkHeader(
        Span<byte> frame,
        DirectRelayTarget target,
        int linkHeaderLength)
    {
        if (target.LinkHeader is { Length: >= PacketView.EthernetHeaderLength } linkHeader)
        {
            linkHeader.AsSpan(6, 6).CopyTo(frame[..6]);
            linkHeader.AsSpan(0, 6).CopyTo(frame.Slice(6, 6));
            if (linkHeader.Length > 12)
            {
                linkHeader.AsSpan(12).CopyTo(frame.Slice(12));
            }

            return;
        }

        target.InboundEthernetDestination!.CopyTo(frame[..6]);
        target.InboundEthernetSource!.CopyTo(frame.Slice(6, 6));
    }

    private bool InjectUdpResponseToClient(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        ReadOnlyMemory<byte> payload)
    {
        if (target.ClientAddress is null || target.ClientPort == 0)
        {
            LogDetail(
                $"UDP inject skipped because client endpoint is unknown app={target.AppLabel} from={remoteEndPoint}",
                $"udp-inject-no-client:{target.ProcessId}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        if (target.AdapterHandle == IntPtr.Zero)
        {
            LogDetail(
                $"UDP inject skipped because adapter is unknown app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint}",
                $"udp-inject-no-adapter:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var clientAddress = NetworkAddress.Normalize(target.ClientAddress);
        var remoteAddress = NetworkAddress.Normalize(remoteEndPoint.Address);
        if (clientAddress.AddressFamily != remoteAddress.AddressFamily)
        {
            LogDetail(
                $"UDP inject skipped because address families differ app={target.AppLabel} client={clientAddress} remote={remoteAddress}",
                $"udp-inject-family-mismatch:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        if (target.LinkHeader is not { Length: >= PacketView.EthernetHeaderLength }
            && (target.InboundEthernetSource is not { Length: 6 }
                || target.InboundEthernetDestination is not { Length: 6 }))
        {
            LogDetail(
                $"UDP inject skipped because ethernet addresses are unknown app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint}",
                $"udp-inject-no-ethernet:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var payloadSpan = payload.Span;
        if (payloadSpan.Length > ushort.MaxValue - 8)
        {
            LogDetail(
                $"UDP inject skipped because datagram is too large length={payloadSpan.Length} app={target.AppLabel} appLocal={target.ClientEndpoint}",
                $"udp-inject-datagram-too-large:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        var linkHeaderLength = target.LinkHeader is { Length: >= PacketView.EthernetHeaderLength } linkHeader
            ? linkHeader.Length
            : PacketView.EthernetHeaderLength;
        var ipHeaderLength = clientAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        var mtu = _adapterMtus.TryGetValue(target.AdapterHandle, out var configuredMtu)
            ? configuredMtu
            : 1500;
        var maxFramePayload = NdisApi.MaxEtherFrame - linkHeaderLength;
        var maxDatagramDataLength = Math.Max(
            8,
            Math.Min(mtu, maxFramePayload) - ipHeaderLength - 8);

        if (payloadSpan.Length > maxDatagramDataLength)
        {
            return InjectFragmentedUdpResponse(
                target,
                remoteEndPoint,
                clientAddress,
                remoteAddress,
                linkHeaderLength,
                ipHeaderLength,
                maxDatagramDataLength,
                payloadSpan);
        }

        var packetLength = linkHeaderLength + ipHeaderLength + 8 + payloadSpan.Length;
        var buffer = default(NdisApi.IntermediateBuffer);
        buffer.AdapterOrListFlink = target.AdapterHandle;
        buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
        buffer.Dot1q = target.Dot1q;
        buffer.Length = (uint)packetLength;
        var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
        frame[..packetLength].Clear();
        WriteInboundLinkHeader(frame, target, linkHeaderLength);

        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv4);
            BuildIpv4UdpPacket(frame.Slice(linkHeaderLength), remoteAddress, clientAddress, (ushort)remoteEndPoint.Port, target.ClientPort, payloadSpan);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv6);
            BuildIpv6UdpPacket(frame.Slice(linkHeaderLength), remoteAddress, clientAddress, (ushort)remoteEndPoint.Port, target.ClientPort, payloadSpan);
        }

        var request = CreateRequest(&buffer);
        if (!NdisApi.SendPacketToMstcp(_driverHandle, ref request))
        {
            LogDetail(
                $"UDP inject SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint} length={packetLength} win32={NdisApi.LastWin32Error}",
                $"udp-inject-send-failed:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        LogDetail(
            $"RESTORE UDP RECV app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint} injectedBytes={payloadSpan.Length}",
            $"udp-inject:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
            TimeSpan.FromSeconds(2));
        return true;
    }

    private void InjectUdpErrorToClient(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        ReadOnlyMemory<byte> originalPayload,
        SocketError socketError)
    {
        if (target.ClientAddress is null || target.ClientPort == 0 || target.AdapterHandle == IntPtr.Zero)
        {
            return;
        }

        if (target.LinkHeader is not { Length: >= PacketView.EthernetHeaderLength }
            && (target.InboundEthernetSource is not { Length: 6 }
                || target.InboundEthernetDestination is not { Length: 6 }))
        {
            return;
        }

        var clientAddress = NetworkAddress.Normalize(target.ClientAddress);
        var remoteAddress = NetworkAddress.Normalize(remoteEndPoint.Address);
        if (clientAddress.AddressFamily != remoteAddress.AddressFamily)
        {
            return;
        }

        var linkHeaderLength = target.LinkHeader is { Length: >= PacketView.EthernetHeaderLength } linkHeader
            ? linkHeader.Length
            : PacketView.EthernetHeaderLength;
        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            var icmp = BuildIpv4IcmpError(
                clientAddress,
                target.ClientPort,
                remoteAddress,
                (ushort)remoteEndPoint.Port,
                originalPayload.Span,
                MapIpv4IcmpCode(socketError));
            InjectIcmpPacket(target, remoteAddress, clientAddress, PacketView.EtherTypeIpv4, linkHeaderLength, icmp);
            return;
        }

        var icmpv6 = BuildIpv6IcmpError(
            clientAddress,
            target.ClientPort,
            remoteAddress,
            (ushort)remoteEndPoint.Port,
            originalPayload.Span,
            MapIpv6IcmpCode(socketError));
        InjectIcmpPacket(target, remoteAddress, clientAddress, PacketView.EtherTypeIpv6, linkHeaderLength, icmpv6);
    }

    private void InjectIcmpPacket(
        DirectRelayTarget target,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ushort etherType,
        int linkHeaderLength,
        byte[] icmpPayload)
    {
        var ipHeaderLength = sourceAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
        var packetLength = linkHeaderLength + ipHeaderLength + icmpPayload.Length;
        if (packetLength > NdisApi.MaxEtherFrame)
        {
            return;
        }

        var buffer = default(NdisApi.IntermediateBuffer);
        buffer.AdapterOrListFlink = target.AdapterHandle;
        buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
        buffer.Dot1q = target.Dot1q;
        buffer.Length = (uint)packetLength;
        var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
        frame[..packetLength].Clear();
        WriteInboundLinkHeader(frame, target, linkHeaderLength);
        BinaryPrimitives.WriteUInt16BigEndian(frame.Slice(linkHeaderLength - 2, 2), etherType);
        var ip = frame.Slice(linkHeaderLength);
        if (sourceAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            ip[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)(20 + icmpPayload.Length));
            ip[8] = 64;
            ip[9] = 1;
            sourceAddress.GetAddressBytes().CopyTo(ip.Slice(12, 4));
            destinationAddress.GetAddressBytes().CopyTo(ip.Slice(16, 4));
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), ComputeOnesComplement(ip[..20]));
            icmpPayload.CopyTo(ip.Slice(20));
        }
        else
        {
            ip[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), (ushort)icmpPayload.Length);
            ip[6] = 58;
            ip[7] = 64;
            sourceAddress.GetAddressBytes().CopyTo(ip.Slice(8, 16));
            destinationAddress.GetAddressBytes().CopyTo(ip.Slice(24, 16));
            icmpPayload.CopyTo(ip.Slice(40));
        }

        var request = CreateRequest(&buffer);
        if (!NdisApi.SendPacketToMstcp(_driverHandle, ref request))
        {
            LogDetail(
                $"ICMP inject SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} from={sourceAddress} win32={NdisApi.LastWin32Error}",
                $"icmp-inject-send-failed:{target.ProcessId}:{target.ClientEndpoint}",
                TimeSpan.FromSeconds(2));
        }
    }

    private static byte[] BuildIpv4IcmpError(
        IPAddress clientAddress,
        ushort clientPort,
        IPAddress remoteAddress,
        ushort remotePort,
        ReadOnlySpan<byte> originalPayload,
        byte code)
    {
        var quoteLength = Math.Min(8, originalPayload.Length);
        var originalLength = checked((ushort)(20 + 8 + Math.Min(originalPayload.Length, ushort.MaxValue - 28)));
        var original = new byte[20 + 8 + quoteLength];
        original[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(2, 2), originalLength);
        original[8] = 64;
        original[9] = PacketView.ProtocolUdp;
        clientAddress.GetAddressBytes().CopyTo(original.AsSpan(12, 4));
        remoteAddress.GetAddressBytes().CopyTo(original.AsSpan(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(
            original.AsSpan(10, 2),
            ComputeOnesComplement(original.AsSpan(0, 20)));
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(20, 2), clientPort);
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(22, 2), remotePort);
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(24, 2), (ushort)(8 + Math.Min(originalPayload.Length, ushort.MaxValue - 28)));
        originalPayload[..quoteLength].CopyTo(original.AsSpan(28));

        var icmp = new byte[8 + original.Length];
        icmp[0] = 3;
        icmp[1] = code;
        original.CopyTo(icmp, 8);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2, 2), ComputeOnesComplement(icmp));
        return icmp;
    }

    private static byte[] BuildIpv6IcmpError(
        IPAddress clientAddress,
        ushort clientPort,
        IPAddress remoteAddress,
        ushort remotePort,
        ReadOnlySpan<byte> originalPayload,
        byte code)
    {
        var quoteLength = Math.Min(8, originalPayload.Length);
        var original = new byte[40 + 8 + quoteLength];
        original[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(4, 2), (ushort)(8 + originalPayload.Length));
        original[6] = PacketView.ProtocolUdp;
        original[7] = 64;
        clientAddress.GetAddressBytes().CopyTo(original.AsSpan(8, 16));
        remoteAddress.GetAddressBytes().CopyTo(original.AsSpan(24, 16));
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(40, 2), clientPort);
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(42, 2), remotePort);
        BinaryPrimitives.WriteUInt16BigEndian(original.AsSpan(44, 2), (ushort)(8 + originalPayload.Length));
        originalPayload[..quoteLength].CopyTo(original.AsSpan(48));

        var icmp = new byte[8 + original.Length];
        icmp[0] = 1;
        icmp[1] = code;
        original.CopyTo(icmp, 8);
        var checksum = ComputeTransportChecksum(
            remoteAddress,
            clientAddress,
            58,
            icmp);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2, 2), checksum);
        return icmp;
    }

    private static byte MapIpv4IcmpCode(SocketError error)
    {
        return error switch
        {
            SocketError.ConnectionRefused => 3,
            SocketError.HostUnreachable => 1,
            SocketError.MessageSize => 4,
            _ => 0
        };
    }

    private static byte MapIpv6IcmpCode(SocketError error)
    {
        return error switch
        {
            SocketError.ConnectionRefused => 4,
            SocketError.HostUnreachable => 3,
            SocketError.MessageSize => 2,
            _ => 0
        };
    }

    private bool InjectFragmentedUdpResponse(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        IPAddress clientAddress,
        IPAddress remoteAddress,
        int linkHeaderLength,
        int ipHeaderLength,
        int maxDatagramDataLength,
        ReadOnlySpan<byte> payload)
    {
        var udpDatagram = new byte[8 + payload.Length];
        var success = true;
        BinaryPrimitives.WriteUInt16BigEndian(udpDatagram.AsSpan(0, 2), (ushort)remoteEndPoint.Port);
        BinaryPrimitives.WriteUInt16BigEndian(udpDatagram.AsSpan(2, 2), target.ClientPort);
        BinaryPrimitives.WriteUInt16BigEndian(udpDatagram.AsSpan(4, 2), checked((ushort)udpDatagram.Length));
        payload.CopyTo(udpDatagram.AsSpan(8));
        var checksum = ComputeUdpChecksum(remoteAddress, clientAddress, PacketView.ProtocolUdp, udpDatagram);
        BinaryPrimitives.WriteUInt16BigEndian(udpDatagram.AsSpan(6, 2), checksum);

        if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            var maxFragmentData = Math.Max(8, maxDatagramDataLength & ~7);
            var identification = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
            var moreFragments = true;
            var offset = 0;
            while (moreFragments)
            {
                var fragmentLength = Math.Min(maxFragmentData, udpDatagram.Length - offset);
                moreFragments = offset + fragmentLength < udpDatagram.Length;
                var packetLength = linkHeaderLength + 20 + fragmentLength;
                var buffer = default(NdisApi.IntermediateBuffer);
                buffer.AdapterOrListFlink = target.AdapterHandle;
                buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
                buffer.Dot1q = target.Dot1q;
                buffer.Length = (uint)packetLength;
                var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
                frame[..packetLength].Clear();
                WriteInboundLinkHeader(frame, target, linkHeaderLength);
                BinaryPrimitives.WriteUInt16BigEndian(
                    frame.Slice(linkHeaderLength - 2, 2),
                    PacketView.EtherTypeIpv4);

                var ip = frame.Slice(linkHeaderLength, 20);
                ip[0] = 0x45;
                ip[1] = 0;
                BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2, 2), (ushort)(20 + fragmentLength));
                BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4, 2), identification);
                BinaryPrimitives.WriteUInt16BigEndian(
                    ip.Slice(6, 2),
                    (ushort)((offset / 8) | (moreFragments ? 0x2000 : 0)));
                ip[8] = 64;
                ip[9] = PacketView.ProtocolUdp;
                remoteAddress.GetAddressBytes().CopyTo(ip.Slice(12, 4));
                clientAddress.GetAddressBytes().CopyTo(ip.Slice(16, 4));
                var ipChecksum = ComputeOnesComplement(ip);
                BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(10, 2), ipChecksum);
                udpDatagram.AsSpan(offset, fragmentLength).CopyTo(ip.Slice(20));
                success &= SendInjectedUdpFragment(target, remoteEndPoint, &buffer);
                offset += fragmentLength;
            }

            return success;
        }

        var maxIpv6FragmentData = Math.Max(8, (maxDatagramDataLength - 8) & ~7);
        Span<byte> identificationBytes = stackalloc byte[4];
        RandomNumberGenerator.Fill(identificationBytes);
        var ipv6Identification = BinaryPrimitives.ReadUInt32BigEndian(identificationBytes);
        var ipv6MoreFragments = true;
        var ipv6Offset = 0;
        while (ipv6MoreFragments)
        {
            var fragmentLength = Math.Min(maxIpv6FragmentData, udpDatagram.Length - ipv6Offset);
            ipv6MoreFragments = ipv6Offset + fragmentLength < udpDatagram.Length;
            var packetLength = linkHeaderLength + 40 + 8 + fragmentLength;
            var buffer = default(NdisApi.IntermediateBuffer);
            buffer.AdapterOrListFlink = target.AdapterHandle;
            buffer.DeviceFlags = NdisApi.PacketFlagOnReceive;
            buffer.Dot1q = target.Dot1q;
            buffer.Length = (uint)packetLength;
            var frame = new Span<byte>(buffer.Data, NdisApi.MaxEtherFrame);
            frame[..packetLength].Clear();
            WriteInboundLinkHeader(frame, target, linkHeaderLength);
            BinaryPrimitives.WriteUInt16BigEndian(
                frame.Slice(linkHeaderLength - 2, 2),
                PacketView.EtherTypeIpv6);

            var ipv6 = frame.Slice(linkHeaderLength, 40);
            ipv6[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(ipv6.Slice(4, 2), (ushort)(8 + fragmentLength));
            ipv6[6] = 44;
            ipv6[7] = 64;
            remoteAddress.GetAddressBytes().CopyTo(ipv6.Slice(8, 16));
            clientAddress.GetAddressBytes().CopyTo(ipv6.Slice(24, 16));

            var fragment = frame.Slice(linkHeaderLength + 40, 8);
            fragment[0] = PacketView.ProtocolUdp;
            BinaryPrimitives.WriteUInt16BigEndian(
                fragment.Slice(2, 2),
                (ushort)(((ipv6Offset / 8) << 3) | (ipv6MoreFragments ? 1 : 0)));
            BinaryPrimitives.WriteUInt32BigEndian(fragment.Slice(4, 4), ipv6Identification);
            udpDatagram.AsSpan(ipv6Offset, fragmentLength).CopyTo(frame.Slice(linkHeaderLength + 48));
            success &= SendInjectedUdpFragment(target, remoteEndPoint, &buffer);
            ipv6Offset += fragmentLength;
        }

        return success;
    }

    private bool SendInjectedUdpFragment(
        DirectRelayTarget target,
        IPEndPoint remoteEndPoint,
        NdisApi.IntermediateBuffer* buffer)
    {
        var request = CreateRequest(buffer);
        if (!NdisApi.SendPacketToMstcp(_driverHandle, ref request))
        {
            LogDetail(
                $"UDP fragment SendPacketToMstcp failed app={target.AppLabel} appLocal={target.ClientEndpoint} from={remoteEndPoint} length={buffer->Length} win32={NdisApi.LastWin32Error}",
                $"udp-fragment-send-failed:{target.ProcessId}:{target.ClientEndpoint}:{remoteEndPoint}",
                TimeSpan.FromSeconds(2));
            return false;
        }

        return true;
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

    private static void BuildIpv4TcpPacket(
        Span<byte> packet,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        uint sequenceNumber,
        uint acknowledgmentNumber,
        byte flags,
        ushort window,
        ushort urgentPointer,
        ReadOnlySpan<byte> options,
        ReadOnlySpan<byte> payload)
    {
        var tcpHeaderLength = 20 + options.Length;
        var totalLength = 20 + tcpHeaderLength + payload.Length;
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

        var tcp = packet.Slice(20, tcpHeaderLength + payload.Length);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(4, 4), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.Slice(8, 4), acknowledgmentNumber);
        tcp[12] = (byte)((tcpHeaderLength / 4) << 4);
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(14, 2), window);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(18, 2), urgentPointer);
        options.CopyTo(tcp.Slice(20, options.Length));
        payload.CopyTo(tcp.Slice(tcpHeaderLength));
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

    private static void BuildIpv6TcpPacket(
        Span<byte> packet,
        IPAddress sourceAddress,
        IPAddress destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        uint sequenceNumber,
        uint acknowledgmentNumber,
        byte flags,
        ushort window,
        ushort urgentPointer,
        ReadOnlySpan<byte> options,
        ReadOnlySpan<byte> payload)
    {
        var tcpHeaderLength = 20 + options.Length;
        var payloadLength = tcpHeaderLength + payload.Length;
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
        tcp[12] = (byte)((tcpHeaderLength / 4) << 4);
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(14, 2), window);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.Slice(18, 2), urgentPointer);
        options.CopyTo(tcp.Slice(20, options.Length));
        payload.CopyTo(tcp.Slice(tcpHeaderLength));
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

    private DirectRelayTarget CreateTarget(
        IntPtr adapterHandle,
        uint dot1q,
        PacketView packet,
        ProcessInfo process,
        string? matchedPattern)
    {
        var adapterMtu = _adapterMtus.TryGetValue(adapterHandle, out var configuredMtu)
            ? configuredMtu
            : 1500;
        var interfaceIndex = _adapterInterfaceIndices.TryGetValue(adapterHandle, out var configuredIndex)
            ? configuredIndex
            : 0;
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
            adapterHandle,
            packet.GetLinkHeader(),
            packet.GetEthernetDestination(),
            packet.GetEthernetSource(),
            adapterMtu,
            dot1q,
            interfaceIndex);
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

    private bool TryHandleDnsSpoof(IntPtr adapterHandle, uint dot1q, PacketView packet)
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

        var process = _processLookup.LookupUdpOwner(
            CreateUdpEndpointKey(packet.SourceAddress, packet.SourcePort, adapterHandle));

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
            InjectUdpResponse(adapterHandle, dot1q, packet, packet.DestinationPort, dnsResponse);

            // 2. If the query came from a non-standard port (like 5353), also inject a response with source port 53 
            // to trigger Leigod's WFP driver to whitelist the IP
            if (packet.DestinationPort != 53)
            {
                InjectUdpResponse(adapterHandle, dot1q, packet, 53, dnsResponse);
            }

            var processInfoStr = process != null ? $"process={process.Name} pid={process.ProcessId}" : "process=unknown";
            _log($"[DNS SPOOF] Spoofed {queryDomain} (Type={qType}) -> {fakeIp} ({processInfoStr}) (TargetPort={packet.DestinationPort})");
            return true;
        }

        return false;
    }

    private void InjectUdpResponse(
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
        InjectUdpResponseToClient(
            target,
            new IPEndPoint(originalQuery.DestinationAddress, sourcePort),
            dnsPayload.ToArray());
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
