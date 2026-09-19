using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace ProxiFyre;

internal sealed unsafe class PacketFilterLoop : IDisposable, IAdapterPacketProcessor
{
    private const int MaxTcpRelayConnections = 4096;
    private const int MaxPacketsPerDrainBatch = 4096;
    private const int WatchdogIntervalMs = 5000;
    private const int WatchdogStallThresholdMs = 30000;
    private static readonly TimeSpan MaxDrainBatchDuration = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan AdapterValidationInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan PassFlowMaintenanceInterval = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan PendingRedirectTtl = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan HealthLogInterval = TimeSpan.FromSeconds(30);

    private readonly DynamicAppConfiguration _configuration;
    private readonly TcpDirectRelay _tcpRelay;
    private readonly UdpDirectRelay _udpRelay;
    private readonly PacketWakeSignal _wakeSignal;
    private readonly ProcessLookup _processLookup;
    private readonly IpFragmentReassembler _fragmentReassembler;
    private readonly OutboundFilterController _outboundFilters;
    private readonly PacketInjector _packetInjector;
    private readonly DnsSpoofHandler _dnsSpoofHandler;
    private AdapterPipelineSet? _adapterPipelines;
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly bool _requestWfpClassifier;
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _detailLogTimes = new();
    private DateTimeOffset _lastPacketStatsLog;
    private DateTimeOffset _nextHealthLog;
    private long _packetsRead;
    private long _packetsPassed;
    private long _packetsRedirected;
    private long _lastHealthQueueTotal;
    private uint _lastHealthQueueMax;
    private string? _lastHealthQueueMaxName;
    private long _adapterSendSucceeded;
    private long _adapterSendFailed;
    private long _mstcpPassSucceeded;
    private long _mstcpPassFailed;
    private IntPtr _driverHandle;
    private ManualResetEvent? _packetEvent;
    private DateTimeOffset _nextAdapterValidation;
    private long _lastProgressTimestamp;
    private long _stallReported;
    private long _stallDetectedTimestamp;
    private string _currentStage = "initializing";
    private CancellationToken _cancellationToken;
    private bool _disposed;
    private readonly TaskCompletionSource<bool> _started =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task Started => _started.Task;

    public bool WfpModeActive => _outboundFilters.UseWfpClassifier;

    public PacketFilterLoop(
        DynamicAppConfiguration configuration,
        TcpDirectRelay tcpRelay,
        UdpDirectRelay udpRelay,
        PacketWakeSignal wakeSignal,
        Action<string>? log = null,
        bool detailedLogging = false,
        TimeProvider? timeProvider = null,
        bool useWfpClassifier = false)
    {
        _configuration = configuration;
        _tcpRelay = tcpRelay;
        _udpRelay = udpRelay;
        _wakeSignal = wakeSignal;
        _log = log ?? Console.WriteLine;
        _detailedLogging = detailedLogging;
        _requestWfpClassifier = useWfpClassifier;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _processLookup = new ProcessLookup(timeProvider: _timeProvider);
        _fragmentReassembler = new IpFragmentReassembler(_timeProvider);
        _outboundFilters = new OutboundFilterController(
            () => _driverHandle,
            () => _adapterPipelines,
            () => _configuration.Generation,
            wakeSignal,
            LogDetail,
            LogThrottled,
            _timeProvider);
        _packetInjector = new PacketInjector(
            () => _driverHandle,
            () => _adapterPipelines,
            LogDetail);
        _dnsSpoofHandler = new DnsSpoofHandler(
            _configuration,
            _processLookup,
            _packetInjector,
            () => _adapterPipelines,
            _log,
            _timeProvider);
        _tcpRelay.SetPacketInjector(_packetInjector.InjectTcpSegmentToClient);
        _udpRelay.SetResponseInjector(_packetInjector.InjectUdpResponseToClient);
        _udpRelay.SetResponseValidator(IsUdpTargetCurrent);
        _udpRelay.SetErrorInjector(_packetInjector.InjectUdpErrorToClient);
        _tcpRelay.SetOutboundBypass(
            _outboundFilters.RegisterOutboundBypass,
            _outboundFilters.UnregisterOutboundBypass);
        _udpRelay.SetOutboundBypass(
            _outboundFilters.RegisterOutboundBypass,
            _outboundFilters.UnregisterOutboundBypass);
        _tcpRelay.SetTargetRedirectUnregister(_outboundFilters.UnregisterTargetRedirect);
        _udpRelay.SetTargetRedirectUnregister(_outboundFilters.UnregisterTargetRedirect);
    }

    public Task RunAsync(CancellationToken cancellationToken)
    {
        return Task.Factory.StartNew(
            () => Run(cancellationToken),
            cancellationToken,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
    }

    private void Run(CancellationToken cancellationToken)
    {
        _cancellationToken = cancellationToken;
        OpenDriver();
        _adapterPipelines = new AdapterPipelineSet(_driverHandle, _log);
        ConfigureAdapters();
        _started.TrySetResult(true);

        using var packetEvent = new ManualResetEvent(false);
        _packetEvent = packetEvent;
        using var passFlowMaintenanceTimer = new Timer(
            static state => ((PacketWakeSignal)state!).Pulse(),
            _wakeSignal,
            PassFlowMaintenanceInterval,
            PassFlowMaintenanceInterval);
        using var watchdogTimer = new Timer(
            static state => ((PacketFilterLoop)state!).WatchdogTick(),
            this,
            WatchdogIntervalMs,
            WatchdogIntervalMs);
        WaitHandle[] waitHandles = [packetEvent, _wakeSignal.WaitHandle, cancellationToken.WaitHandle];
        try
        {
            _adapterPipelines.BindPacketEvent(packetEvent.SafeWaitHandle);

            _log("Packet filter started.");
            LogHealth(force: true);
            MarkProgress();

            while (!cancellationToken.IsCancellationRequested)
            {
                SetStage("waiting-for-event");
                var signaledIndex = WaitHandle.WaitAny(waitHandles);
                if (signaledIndex == 2)
                {
                    break;
                }

                MarkProgress();
                var driverSignaled = signaledIndex == 0;
                if (driverSignaled)
                {
                    packetEvent.Reset();
                }

                bool drainedAny;
                var drainedCount = 0;
                var batchStartedAt = _timeProvider.GetTimestamp();
                do
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    SetStage("reading-adapters");
                    drainedAny = TryReadAndProcessPacket();
                    if (drainedAny)
                    {
                        drainedCount++;
                    }

                    if (drainedCount >= MaxPacketsPerDrainBatch
                        || _timeProvider.GetElapsedTime(batchStartedAt) >= MaxDrainBatchDuration)
                    {
                        packetEvent.Set();
                        break;
                    }
                }
                while (drainedAny);

                SetStage("validating-adapters");
                ValidateAdapters();
                SetStage("logging-health");
                LogHealth();
                MarkProgress();

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
            _packetEvent = null;
            _adapterPipelines?.Restore();
        }
    }

    private void SetStage(string stage)
    {
        Volatile.Write(ref _currentStage, stage);
    }

    private void MarkProgress()
    {
        Interlocked.Exchange(ref _lastProgressTimestamp, Environment.TickCount64);
        var wasStalled = Interlocked.Exchange(ref _stallReported, 0);
        if (wasStalled != 0)
        {
            var detectedAt = Interlocked.Read(ref _stallDetectedTimestamp);
            var elapsed = Math.Max(0, Environment.TickCount64 - detectedAt);
            _log($"Packet loop watchdog: progress resumed after {elapsed} ms; stage={Volatile.Read(ref _currentStage)}.");
        }
    }

    private void WatchdogTick()
    {
        var lastProgress = Interlocked.Read(ref _lastProgressTimestamp);
        if (lastProgress == 0)
        {
            return;
        }

        var elapsed = Environment.TickCount64 - lastProgress;
        if (elapsed < WatchdogStallThresholdMs
            || Interlocked.Exchange(ref _stallReported, 1) != 0)
        {
            return;
        }

        Interlocked.Exchange(ref _stallDetectedTimestamp, Environment.TickCount64);
        _log(
            $"Packet loop watchdog: no progress for {elapsed} ms; stage={Volatile.Read(ref _currentStage)} read={_packetsRead} passed={_packetsPassed} redirected={_packetsRedirected} adapterQueueLast={_lastHealthQueueTotal} adapterQueueMaxLast={_lastHealthQueueMax} adapterQueueMaxNameLast={_lastHealthQueueMaxName ?? "none"}.");
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
        NdisApi.ResetPacketFilterTable(_driverHandle);
        if (_requestWfpClassifier)
        {
            var fragmentCacheEnabled = _outboundFilters.Initialize(requestWfpClassifier: true);
            _log(fragmentCacheEnabled
                ? "WinpkFilter fragment cache enabled for WFP target redirect flows."
                : "WinpkFilter fragment cache is unavailable; WFP target-only mode cannot use kernel redirects.");
        }
        else
        {
            _ = _outboundFilters.Initialize(requestWfpClassifier: false);
            _log("WinpkFilter fragment and kernel pass cache disabled in userspace send-tunnel mode.");
        }
    }

    private void ConfigureAdapters()
    {
        if (_outboundFilters.UseWfpClassifier && !_outboundFilters.FragmentCacheEnabled)
        {
            _outboundFilters.DisableWfpFallback();
            _log("WFP target-only mode disabled because WinpkFilter fragment cache is unavailable; using userspace send tunnel.");
        }

        _adapterPipelines!.Configure(_outboundFilters.UseWfpClassifier);
    }

    internal bool HandleWfpFlow(WfpFlowEvent flowEvent)
    {
        if (!_outboundFilters.UseWfpClassifier
            || flowEvent.Protocol is not (PacketView.ProtocolTcp or PacketView.ProtocolUdp)
            || !TryResolveAdapterHandle(flowEvent.InterfaceIndex, out var adapterHandle)
            || CreateAddress(flowEvent.AddressFamily, flowEvent.LocalAddress) is not { } localAddress
            || CreateAddress(flowEvent.AddressFamily, flowEvent.RemoteAddress) is not { } remoteAddress)
        {
            return false;
        }

        var process = _processLookup.GetProcessInfo((int)flowEvent.ProcessId);
        if (process is null
            || !_configuration.Current.TryGetMatchingPattern(process, out _, out _))
        {
            return false;
        }

        var flow = new RelayOutboundFlow(
            adapterHandle,
            flowEvent.Protocol,
            localAddress,
            remoteAddress,
            flowEvent.LocalPort,
            flowEvent.RemotePort);
        if (!_outboundFilters.RegisterTargetRedirect(
                flow,
                process,
                _timeProvider.GetUtcNow() + PendingRedirectTtl))
        {
            return false;
        }

        LogDetail(
            $"WFP classified target flow pid={flowEvent.ProcessId} {flow}",
            $"wfp-classified:{flowEvent.ProcessId}:{flow}",
            TimeSpan.FromSeconds(2));
        return true;
    }

    private bool TryResolveAdapterHandle(uint interfaceIndex, out IntPtr adapterHandle)
    {
        return _adapterPipelines!.TryResolveHandle((int)interfaceIndex, out adapterHandle);
    }

    private static IPAddress? CreateAddress(ushort addressFamily, byte[]? bytes)
    {
        if (bytes is null)
        {
            return null;
        }

        if (addressFamily == WfpProtocol.AddressFamilyInterNetwork && bytes.Length >= 4)
        {
            return new IPAddress(bytes.AsSpan(0, 4));
        }

        if (addressFamily == WfpProtocol.AddressFamilyInterNetworkV6 && bytes.Length >= 16)
        {
            return new IPAddress(bytes.AsSpan(0, 16));
        }

        return null;
    }

    private static RelayOutboundFlow CreateOutboundFlow(
        PacketView packet,
        IntPtr adapterHandle,
        uint dot1q)
    {
        return new RelayOutboundFlow(
            adapterHandle,
            packet.IsTcp ? PacketView.ProtocolTcp : PacketView.ProtocolUdp,
            packet.SourceAddress,
            packet.DestinationAddress,
            packet.SourcePort,
            packet.DestinationPort,
            dot1q);
    }

    private bool TryReadAndProcessPacket()
    {
        _fragmentReassembler.FlushExpired(SendCapturedFragmentToAdapter);
        SetStage("maintaining-outbound-filters");
        _outboundFilters.Maintain();
        return _adapterPipelines!.TryReadAndProcess(this);
    }

    public void ProcessPacket(NdisApi.IntermediateBuffer* buffer)
    {
        SetStage("processing-packet");
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
            || !ProcessOutgoing(
                packet,
                reassembled.AdapterHandle,
                reassembled.Dot1q,
                allowPassFilter: false))
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

    private bool ProcessOutgoing(
        PacketView packet,
        IntPtr adapterHandle,
        uint dot1q,
        bool allowPassFilter = true)
    {
        if (packet.IsTcp)
        {
            return ProcessOutgoingTcp(packet, adapterHandle, dot1q, allowPassFilter);
        }

        if (packet.IsUdp)
        {
            return ProcessOutgoingUdp(packet, adapterHandle, dot1q, allowPassFilter);
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

    private bool ProcessOutgoingTcp(
        PacketView packet,
        IntPtr adapterHandle,
        uint dot1q,
        bool allowPassFilter)
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

        var outboundFlow = CreateOutboundFlow(packet, adapterHandle, dot1q);
        if (_outboundFilters.UseWfpClassifier)
        {
            _outboundFilters.RefreshTargetRedirect(outboundFlow);
        }

        _outboundFilters.RemoveTemporaryPassFlow(packet, adapterHandle, dot1q);

        if (_tcpRelay.TryGetConnection(relayKey, out var existingConnection))
        {
            if (existingConnection.CanBeRemoved)
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
                _outboundFilters.MarkTargetRedirectActive(outboundFlow);
                return true;
            }
        }

        if (!packet.IsInitialSyn)
        {
            var nonSynProcess = _outboundFilters.TryGetWfpProcess(outboundFlow, out var wfpProcess)
                ? wfpProcess
                : LookupTcpOwner(packet);
            if (nonSynProcess is not null
                && !_configuration.Current.TryGetMatchingPattern(nonSynProcess, out _, out _))
            {
                _outboundFilters.RegisterTemporaryPassFlow(packet, adapterHandle, dot1q, allowPassFilter);
            }
            else if (_outboundFilters.UseWfpClassifier)
            {
                _outboundFilters.UnregisterTargetRedirect(outboundFlow);
            }

            return false;
        }

        if (packet.TcpPayloadLength > 0)
        {
            _tcpRelay.MarkBypassedFlow(relayKey);
            if (_outboundFilters.UseWfpClassifier)
            {
                _outboundFilters.UnregisterTargetRedirect(outboundFlow);
            }
            return false;
        }

        if (_tcpRelay.IsBypassedFlow(relayKey))
        {
            if (_outboundFilters.UseWfpClassifier)
            {
                _outboundFilters.UnregisterTargetRedirect(outboundFlow);
            }
            return false;
        }

        var process = _outboundFilters.TryGetWfpProcess(outboundFlow, out var wfpTargetProcess)
            ? wfpTargetProcess
            : LookupTcpOwner(packet);
        if (process is null)
        {
            _tcpRelay.MarkBypassedFlow(relayKey);
            if (_outboundFilters.UseWfpClassifier)
            {
                _outboundFilters.UnregisterTargetRedirect(outboundFlow);
            }
            return false;
        }

        if (!_configuration.Current.TryGetMatchingPattern(process, out var matchedPattern, out _))
        {
            _outboundFilters.RegisterTemporaryPassFlow(packet, adapterHandle, dot1q, allowPassFilter);
            if (_outboundFilters.UseWfpClassifier)
            {
                _outboundFilters.UnregisterTargetRedirect(outboundFlow);
            }
            return false;
        }

        if (_tcpRelay.ConnectionCount >= MaxTcpRelayConnections)
        {
            _tcpRelay.MarkBypassedFlow(relayKey);
            LogThrottled(
                $"TCP relay connection limit reached ({MaxTcpRelayConnections}); passing new target flow directly.",
                "tcp-relay-limit",
                TimeSpan.FromSeconds(5));
            if (_outboundFilters.UseWfpClassifier)
            {
                _outboundFilters.UnregisterTargetRedirect(outboundFlow);
            }
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
        _outboundFilters.MarkTargetRedirectActive(outboundFlow);
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

    private bool ProcessOutgoingUdp(
        PacketView packet,
        IntPtr adapterHandle,
        uint dot1q,
        bool allowPassFilter)
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
        bool isDnsQuery = DnsSpoofHandler.TryGetQueryDomain(packet.UdpPayload, out var domain);
        if (isPort53 || isDnsQuery)
        {
            _log($"[UDP DNS OUT] {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort} (Process={processName} PID={processId} DnsQuery={isDnsQuery} Domain={domain})");
        }

        if (packet.IsLinkLayerBroadcastOrMulticast()
            || packet.IsNetworkLayerBroadcastOrMulticast())
        {
            return false;
        }

        if (_dnsSpoofHandler.TryHandle(adapterHandle, dot1q, packet))
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

        var outboundFlow = CreateOutboundFlow(packet, adapterHandle, dot1q);
        if (_outboundFilters.UseWfpClassifier)
        {
            _outboundFilters.RefreshTargetRedirect(outboundFlow);
            if (_outboundFilters.TryGetWfpProcess(outboundFlow, out var wfpProcess))
            {
                processInfo = wfpProcess;
            }
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
                _outboundFilters.MarkTargetRedirectActive(outboundFlow);
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

            if (_outboundFilters.UseWfpClassifier)
            {
                _outboundFilters.UnregisterTargetRedirect(outboundFlow);
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

            if (_outboundFilters.UseWfpClassifier)
            {
                _outboundFilters.UnregisterTargetRedirect(outboundFlow);
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
        _outboundFilters.MarkTargetRedirectActive(outboundFlow);
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
        if (owner is not null)
        {
            return owner.ProcessId == target.ProcessId
                && owner.Name.Equals(target.ProcessName, StringComparison.OrdinalIgnoreCase)
                && owner.Path.Equals(target.ProcessPath, StringComparison.OrdinalIgnoreCase);
        }

        // UDP endpoint tables can briefly omit a live socket while the process
        // still exists. Do not tear down the relay flow solely on that miss.
        var process = _processLookup.GetProcessInfo(target.ProcessId);
        return process is not null
            && process.Name.Equals(target.ProcessName, StringComparison.OrdinalIgnoreCase)
            && process.Path.Equals(target.ProcessPath, StringComparison.OrdinalIgnoreCase);
    }

    private UdpEndpointKey CreateUdpEndpointKey(
        IPAddress address,
        ushort port,
        IntPtr adapterHandle,
        int interfaceIndex = 0)
    {
        if (interfaceIndex <= 0)
        {
            _ = _adapterPipelines!.TryGetInterfaceIndex(adapterHandle, out interfaceIndex);
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

    private DirectRelayTarget CreateTarget(
        IntPtr adapterHandle,
        uint dot1q,
        PacketView packet,
        ProcessInfo process,
        string? matchedPattern)
    {
        _ = _adapterPipelines!.TryGetMtu(adapterHandle, out var adapterMtu);
        _ = _adapterPipelines.TryGetInterfaceIndex(adapterHandle, out var interfaceIndex);
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
            SetStage("returning-packet-to-adapter");
            SendToAdapter(buffer);
        }
        else
        {
            SetStage("returning-packet-to-mstcp");
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
        _log($"Packet stats: read={_packetsRead}, passed={_packetsPassed}, redirected={_packetsRedirected}, kernelPassFlows={_outboundFilters.KernelPassFlowCount}");
    }

    private void LogHealth(bool force = false)
    {
        var now = _timeProvider.GetUtcNow();
        if (!force
            && _nextHealthLog != default
            && now < _nextHealthLog)
        {
            return;
        }

        _nextHealthLog = now + HealthLogInterval;
        long queueTotal = 0;
        uint queueMax = 0;
        long adapterReadMin = long.MaxValue;
        long adapterReadMax = 0;
        string? queueMaxAdapter = null;
        foreach (var adapter in _adapterPipelines!.Pipelines)
        {
            adapterReadMin = Math.Min(adapterReadMin, adapter.PacketsRead);
            adapterReadMax = Math.Max(adapterReadMax, adapter.PacketsRead);
            if (!NdisApi.GetAdapterPacketQueueSize(_driverHandle, adapter.Handle, out var queueSize))
            {
                continue;
            }

            queueTotal += queueSize;
            if (queueSize <= queueMax)
            {
                continue;
            }

            queueMax = queueSize;
            queueMaxAdapter = adapter.Name;
        }

        if (adapterReadMin == long.MaxValue)
        {
            adapterReadMin = 0;
        }

        _lastHealthQueueTotal = queueTotal;
        _lastHealthQueueMax = queueMax;
        _lastHealthQueueMaxName = queueMaxAdapter;

        var mode = _outboundFilters.UseWfpClassifier ? "wfp-target-only" : "userspace-send-tunnel";
        _log(
            $"Packet loop health: mode={mode} adapters={_adapterPipelines.Count} read={_packetsRead} passed={_packetsPassed} redirected={_packetsRedirected} adapterReadMin={adapterReadMin} adapterReadMax={adapterReadMax} adapterSends={_adapterSendSucceeded} adapterSendFailures={_adapterSendFailed} mstcpSends={_packetInjector.MstcpSendSucceeded + _mstcpPassSucceeded} mstcpSendFailures={_packetInjector.MstcpSendFailed + _mstcpPassFailed} kernelPassFlows={_outboundFilters.KernelPassFlowCount} filterApplyFailures={_outboundFilters.FilterApplyFailures} adapterQueueTotal={queueTotal} adapterQueueMax={queueMax} adapterQueueMaxName={queueMaxAdapter ?? "none"}");
    }

    private void ValidateAdapters()
    {
        var now = _timeProvider.GetUtcNow();
        if (now < _nextAdapterValidation)
        {
            return;
        }

        _nextAdapterValidation = now + AdapterValidationInterval;
        if (_packetEvent is null
            || !_adapterPipelines!.RebindIfChanged(_packetEvent.SafeWaitHandle))
        {
            return;
        }

        _outboundFilters.MarkDirty(force: true);
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

    private void SendToMstcp(NdisApi.IntermediateBuffer* buffer)
    {
        var request = CreateRequest(buffer);
        if (!NdisApi.SendPacketToMstcp(_driverHandle, ref request))
        {
            _mstcpPassFailed++;
            LogThrottled(
                $"SendPacketToMstcp failed. adapter=0x{request.AdapterHandle.ToInt64():X} length={buffer->Length} flags={buffer->DeviceFlags} win32={NdisApi.LastWin32Error}",
                "send-mstcp-failed",
                TimeSpan.FromSeconds(2));
            return;
        }

        _mstcpPassSucceeded++;
    }

    private void SendToAdapter(NdisApi.IntermediateBuffer* buffer)
    {
        var request = CreateRequest(buffer);
        if (!NdisApi.SendPacketToAdapter(_driverHandle, ref request))
        {
            var error = NdisApi.LastWin32Error;
            _adapterSendFailed++;
            LogThrottled(
                $"SendPacketToAdapter failed. adapter=0x{request.AdapterHandle.ToInt64():X} length={buffer->Length} flags={buffer->DeviceFlags} win32={error}",
                "send-adapter-failed",
                TimeSpan.FromSeconds(2));
            throw new IOException(
                $"Failed to return a captured outbound packet to the network adapter. Win32 error {error}.");
        }

        _adapterSendSucceeded++;
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

        _adapterPipelines?.Restore();

        if (_driverHandle != IntPtr.Zero)
        {
            NdisApi.CloseFilterDriver(_driverHandle);
            _driverHandle = IntPtr.Zero;
        }

        GC.SuppressFinalize(this);
    }

}
