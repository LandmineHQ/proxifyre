using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace ProxiFyre;

internal sealed class WinDivertPacketRouter : IAsyncDisposable
{
    private const int MaxTcpRelayConnections = 4096;
    private const int MaxPacketLength = 131072;
    private const int MaxQueuedPackets = 4096;
    private const int MaxUdpPassThroughEntries = 65536;
    private static readonly TimeSpan UdpPassThroughTtl = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan UdpProcessMissPassThroughTtl = TimeSpan.FromMilliseconds(250);
    private const string CaptureFilter = "outbound and !loopback and (tcp or udp)";

    private readonly DynamicAppConfiguration _configuration;
    private readonly ProcessLookup _processLookup;
    private readonly Action<string> _log;
    private readonly Action<string> _warningLog;
    private readonly ConcurrentDictionary<string, long> _warningTimes = new();
    private readonly DetailedLoggingState _detailedLogging;
    private readonly TrafficCounter _trafficCounter;
    private readonly PacketWakeSignal _packetWakeSignal;
    private readonly TimeProvider _timeProvider;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<UdpPassThroughKey, long> _udpPassThroughUntil = new();
    private long _packetsReceived;
    private long _packetsPassed;
    private long _packetsRelayed;
    private long _packetErrors;
    private long _packetQueueFull;
    private long _lastHealthLogTick;
    private long _lastPacketQueueFullLogTick;
    private readonly Channel<CapturedPacket> _packetQueue = Channel.CreateBounded<CapturedPacket>(
        new BoundedChannelOptions(MaxQueuedPackets)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait
        });
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private WinDivertHandle? _networkHandle;
    private WinDivertFlowTracker? _flowTracker;
    private WinDivertPacketInjector? _injector;
    private TcpDirectRelay? _tcpRelay;
    private WinDivertUdpRelay? _udpRelay;
    private Task? _captureTask;
    private Task? _packetProcessingTask;
    private CancellationTokenRegistration _stopRegistration;
    private bool _hasStopRegistration;
    private bool _disposed;

    public WinDivertPacketRouter(
        DynamicAppConfiguration configuration,
        ProcessLookup processLookup,
        Action<string> log,
        TrafficCounter trafficCounter,
        PacketWakeSignal packetWakeSignal,
        TimeProvider timeProvider,
        bool detailedLogging,
        DetailedLoggingState? detailedLoggingState = null,
        Action<string>? warningLog = null)
    {
        _configuration = configuration;
        _processLookup = processLookup;
        _log = log;
        _warningLog = warningLog ?? log;
        _trafficCounter = trafficCounter;
        _packetWakeSignal = packetWakeSignal;
        _timeProvider = timeProvider;
        _detailedLogging = detailedLoggingState ?? new DetailedLoggingState(detailedLogging);
    }

    public Task Completion => _captureTask ?? Task.CompletedTask;

    public WinDivertPacketInjector Injector =>
        _injector ?? throw new InvalidOperationException("WinDivert packet router is not started.");

    internal static WinDivertHandle OpenNetworkHandle()
    {
        var handle = WinDivertNative.Open(
            CaptureFilter,
            WinDivertLayer.Network,
            priority: 0,
            WinDivertOpenFlags.Fragments);
        ConfigureQueue(handle);
        return handle;
    }

    public void Start(
        string? nativeDirectory,
        CancellationToken cancellationToken,
        WinDivertHandle? networkHandle = null,
        WinDivertHandle? flowHandle = null)
    {
        _lifecycleGate.Wait();
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_captureTask is not null)
            {
                return;
            }

            WinDivertNative.Configure(nativeDirectory);
            NetworkInterfaceIndexResolver.PrimeMtuCache();
            _networkHandle = networkHandle ?? OpenNetworkHandle();

            _flowTracker = new WinDivertFlowTracker(
                _processLookup,
                _log,
                flowHandle,
                _warningLog);
            _flowTracker.Start();
            _injector = new WinDivertPacketInjector(
                _networkHandle,
                _log,
                _detailedLogging.Enabled,
                _detailedLogging,
                _warningLog);

            _tcpRelay = new TcpDirectRelay(
                _log,
                _detailedLogging.Enabled,
                _trafficCounter,
                _packetWakeSignal,
                _timeProvider,
                detailedLoggingState: _detailedLogging,
                warningLog: _warningLog);
            _tcpRelay.SetPacketInjector(_injector.InjectTcpSegment);
            _tcpRelay.SetOutboundBypass(static _ => { }, static _ => { });
            _tcpRelay.SetTargetRedirectUnregister(static _ => { });
            _tcpRelay.Start(_cts.Token);

            _udpRelay = new WinDivertUdpRelay(
                _configuration,
                _processLookup,
                _injector,
                _log,
                _trafficCounter,
                _packetWakeSignal,
                _timeProvider,
                _detailedLogging.Enabled,
                _detailedLogging,
                _warningLog);
            _udpRelay.Start(_cts.Token);

            _packetProcessingTask = Task.Factory.StartNew(
                () => ProcessCapturedPackets(_cts.Token),
                _cts.Token,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
            _captureTask = Task.Factory.StartNew(
                () => CaptureLoop(_cts.Token),
                _cts.Token,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);

            _stopRegistration = cancellationToken.Register(
                static state => ((WinDivertPacketRouter)state!).RequestStop(),
                this);
            _hasStopRegistration = true;
            _log("WinDivert packet router started.");
        }
        catch
        {
            CleanupAfterStartFailure();
            throw;
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public void ApplyConfiguration()
    {
        _udpPassThroughUntil.Clear();
        _tcpRelay?.ApplyConfiguration(_configuration.Current);
        _udpRelay?.ApplyConfiguration(_configuration.Current);
    }

    private static void ConfigureQueue(WinDivertHandle handle)
    {
        _ = WinDivertNative.TrySetParameter(handle, WinDivertParameter.QueueLength, 16384);
        _ = WinDivertNative.TrySetParameter(handle, WinDivertParameter.QueueTime, 2000);
        _ = WinDivertNative.TrySetParameter(handle, WinDivertParameter.QueueSize, 16 * 1024 * 1024);
    }

    private void CaptureLoop(CancellationToken cancellationToken)
    {
        var handle = _networkHandle!;
        var buffer = new byte[MaxPacketLength];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (!WinDivertNative.TryReceive(
                        handle,
                        buffer,
                        out var packetLength,
                        out var address,
                        out var error))
                {
                    if (cancellationToken.IsCancellationRequested
                        || error is WinDivertNative.ErrorNoData or WinDivertNative.ErrorOperationAborted)
                    {
                        break;
                    }

                    _log(
                        $"WinDivert receive failed: {new Win32Exception(error).Message}");
                    Thread.Sleep(10);
                    continue;
                }

                Interlocked.Increment(ref _packetsReceived);
                var packet = ArrayPool<byte>.Shared.Rent(packetLength);
                Buffer.BlockCopy(buffer, 0, packet, 0, packetLength);
                if (!_packetQueue.Writer.TryWrite(
                        new CapturedPacket(packet, packetLength, address)))
                {
                    ArrayPool<byte>.Shared.Return(packet);
                    LogPacketQueueFull();
                    try
                    {
                        PassPacket(buffer.AsSpan(0, packetLength), address);
                    }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref _packetErrors);
                        _log($"WinDivert packet queue-full pass-through failed: {ex.Message}");
                    }
                }
            }

            _packetQueue.Writer.TryComplete();
        }
        catch (Exception ex)
        {
            _packetQueue.Writer.TryComplete();
            _log($"WinDivert packet router stopped unexpectedly: {ex}");
        }
    }

    private void ProcessCapturedPackets(CancellationToken cancellationToken)
    {
        try
        {
            while (_packetQueue.Reader.WaitToReadAsync(CancellationToken.None)
                .AsTask()
                .GetAwaiter()
                .GetResult())
            {
                while (_packetQueue.Reader.TryRead(out var captured))
                {
                    try
                    {
                        ProcessPacket(
                            captured.Buffer.AsSpan(0, captured.Length),
                            captured.Address);
                        LogHealthIfDue();
                    }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref _packetErrors);
                        _warningLog(
                            $"WinDivert packet handling failed; falling back to direct pass-through: {ex}");
                        try
                        {
                            PassPacket(
                                captured.Buffer.AsSpan(0, captured.Length),
                                captured.Address);
                        }
                        catch (Exception passException)
                        {
                            _log(
                                $"WinDivert packet recovery pass-through failed: {passException.Message}");
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(captured.Buffer);
                    }
                }
            }
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            _log($"WinDivert packet processing stopped unexpectedly: {ex}");
            RequestStop();
        }
    }

    private void ProcessPacket(Span<byte> packetBytes, WinDivertAddress address)
    {
        if (!PacketView.TryParseIp(packetBytes, packetBytes.Length, out var packet))
        {
            LogWarningThrottled(
                "packet-parse-fallback",
                "WinDivert packet parsing failed; passing the captured packet directly.");
            PassPacket(packetBytes, address);
            return;
        }

        var interfaceIndex = ResolveInterfaceIndex(packet, address);

        if (packet.IsTcp)
        {
            ProcessTcpPacket(packet, packetBytes, address, interfaceIndex);
            return;
        }

        if (packet.IsUdp)
        {
            ProcessUdpPacket(packet, packetBytes, address, interfaceIndex);
            return;
        }

        PassPacket(packetBytes, address);
    }

    private uint ResolveInterfaceIndex(PacketView packet, WinDivertAddress address)
    {
        if (address.NetworkInterfaceIndex != 0)
        {
            return address.NetworkInterfaceIndex;
        }

        var resolved = NetworkInterfaceIndexResolver.FindInterfaceIndexForLocalAddress(
            packet.SourceAddress);
        if (resolved <= 0)
        {
            resolved = NetworkInterfaceIndexResolver.FindBestInterfaceIndex(
                packet.DestinationAddress);
        }

        if (resolved > 0)
        {
            LogWarningThrottled(
                "interface-resolution-fallback",
                $"WinDivert packet did not include an interface index; resolved fallback interfaceIndex={resolved} for {packet.SourceAddress}.");
            return (uint)resolved;
        }

        return address.NetworkInterfaceIndex;
    }

    private void ProcessTcpPacket(
        PacketView packet,
        Span<byte> packetBytes,
        WinDivertAddress address,
        uint interfaceIndex)
    {
        if (_tcpRelay!.IsRelayOutboundLocalEndpoint(packet.SourceAddress, packet.SourcePort))
        {
            PassPacket(packetBytes, address);
            return;
        }

        var relayKey = CreateTcpRelayKey(packet, interfaceIndex, address.NetworkSubInterfaceIndex);
        if (_tcpRelay!.IsRelayOutboundFlow(relayKey))
        {
            PassPacket(packetBytes, address);
            return;
        }

        if (_tcpRelay.TryGetConnection(relayKey, out var existingConnection))
        {
            if (!IsConnectionOwnerCurrent(existingConnection))
            {
                _tcpRelay.Remove(existingConnection);
            }
            else if (existingConnection.CanBeRemoved)
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
                if (_detailedLogging.Enabled)
                {
                    _log(
                        $"TCP relay client segment flags=0x{packet.TcpFlags:X2} seq={packet.TcpSequenceNumber} ack={packet.TcpAcknowledgmentNumber} payload={packet.TcpPayloadLength} session={packet.Session}");
                }

                existingConnection.SendClientSegment(CreateTcpSegment(packet));
                return;
            }
        }

        if (!packet.IsInitialSyn || packet.TcpPayloadLength > 0)
        {
            PassPacket(packetBytes, address);
            return;
        }

        if (_tcpRelay.IsBypassedFlow(relayKey))
        {
            PassPacket(packetBytes, address);
            return;
        }

        if (_tcpRelay.ConnectionCount >= MaxTcpRelayConnections)
        {
            LogWarningThrottled(
                "tcp-connection-limit-fallback",
                $"WinDivert TCP relay connection limit reached ({MaxTcpRelayConnections}); passing new target flows directly.");
            _tcpRelay.MarkBypassedFlow(relayKey);
            PassPacket(packetBytes, address);
            return;
        }

        if (!TryResolveProcess(packet, out var process, out var processId, out var isRelayProcess)
            || isRelayProcess
            || process is null)
        {
            LogWarningThrottled(
                "tcp-owner-fallback",
                $"WinDivert TCP owner lookup failed for {packet.Session}; passing the flow directly.");
            _tcpRelay.MarkBypassedFlow(relayKey);
            PassPacket(packetBytes, address);
            return;
        }

        if (!_configuration.Current.TryGetMatchingPattern(process, out var matchedPattern, out _))
        {
            _tcpRelay.MarkBypassedFlow(relayKey);
            PassPacket(packetBytes, address);
            return;
        }

        if (interfaceIndex == 0)
        {
            LogWarningThrottled(
                "tcp-interface-fallback",
                $"WinDivert TCP relay could not resolve the outbound interface for {packet.Session}; passing directly.");
            _tcpRelay.MarkBypassedFlow(relayKey);
            PassPacket(packetBytes, address);
            return;
        }

        _log(
            $"APP TCP CONNECT app={process.Name} pid={processId} local={packet.SourceAddress}:{packet.SourcePort} target={packet.DestinationAddress}:{packet.DestinationPort} seq={packet.TcpSequenceNumber} window={packet.TcpWindow} pattern={matchedPattern}");
        var target = CreateTarget(
            packet,
            interfaceIndex,
            address.NetworkSubInterfaceIndex,
            process,
            matchedPattern);
        var clientMss = TryGetTcpMss(packet.TcpOptions, out var parsedMss)
            ? parsedMss
            : (ushort)536;
        _tcpRelay.RegisterSyn(
            relayKey,
            new TcpClientKey(packet.SourceAddress, packet.SourcePort),
            target,
            packet.TcpSequenceNumber,
            packet.TcpWindow,
            _cts.Token,
            clientMss);
        Interlocked.Increment(ref _packetsRelayed);
    }

    private bool IsConnectionOwnerCurrent(TcpDirectRelay.TcpRelayConnection connection)
    {
        var target = connection.Target;
        var process = _processLookup.GetProcessInfo(target.ProcessId);
        return process is not null
            && process.Name.Equals(target.ProcessName, StringComparison.OrdinalIgnoreCase)
            && process.Path.Equals(target.ProcessPath, StringComparison.OrdinalIgnoreCase)
            && _processLookup.ValidateProcessIdentity(
                target.ProcessId,
                target.ProcessStartTimeUtcTicks)
            && _configuration.Current.TryGetMatchingPattern(process, out _, out _);
    }

    private void ProcessUdpPacket(
        PacketView packet,
        Span<byte> packetBytes,
        WinDivertAddress address,
        uint interfaceIndex)
    {
        var captureTimestamp = Stopwatch.GetTimestamp();
        if (packet.IsNetworkLayerBroadcastOrMulticast())
        {
            PassPacket(packetBytes, address);
            return;
        }

        var passKey = new UdpPassThroughKey(
            WinDivertFlowKey.FromPacket(packet),
            interfaceIndex,
            address.NetworkSubInterfaceIndex);
        if (_udpPassThroughUntil.TryGetValue(passKey, out var passUntil)
            && Environment.TickCount64 < passUntil)
        {
            PassPacket(packetBytes, address);
            return;
        }

        if (!TryResolveProcess(packet, out var process, out var processId, out var isRelayProcess)
            || isRelayProcess
            || process is null)
        {
            LogWarningThrottled(
                "udp-owner-fallback",
                $"WinDivert UDP owner lookup failed for {packet.UdpEndpoint}; passing the flow directly.");
            MarkUdpPassThrough(passKey, UdpProcessMissPassThroughTtl);
            PassPacket(packetBytes, address);
            return;
        }

        var processResolvedTimestamp = Stopwatch.GetTimestamp();
        if (!_configuration.Current.TryGetMatchingPattern(process, out var matchedPattern, out _))
        {
            MarkUdpPassThrough(passKey, UdpPassThroughTtl);
            PassPacket(packetBytes, address);
            return;
        }

        if (interfaceIndex == 0)
        {
            LogWarningThrottled(
                "udp-interface-fallback",
                $"WinDivert UDP relay could not resolve the outbound interface for {packet.SourceAddress}:{packet.SourcePort} -> {packet.DestinationAddress}:{packet.DestinationPort}; passing directly.");
            PassPacket(packetBytes, address);
            return;
        }

        var relayKey = CreateUdpRelayKey(
            packet,
            interfaceIndex,
            address.NetworkSubInterfaceIndex,
            processId);
        if (_udpRelay!.IsBypassedFlow(relayKey))
        {
            PassPacket(packetBytes, address);
            return;
        }

        if (_udpRelay!.IsRelayOutboundFlow(relayKey))
        {
            _udpPassThroughUntil.TryRemove(passKey, out _);
            PassPacket(packetBytes, address);
            return;
        }

        if (_configuration.Current.EnableFakeIpWhitelist
            && WinDivertDnsSpoofHandler.TryHandle(
                packet,
                interfaceIndex,
                address.NetworkSubInterfaceIndex,
                process,
                _injector!,
                _log,
                _timeProvider))
        {
            Interlocked.Increment(ref _packetsRelayed);
            return;
        }

        _udpPassThroughUntil.TryRemove(passKey, out _);
        if (!_udpRelay.TryHandlePacket(
                packet,
                interfaceIndex,
                address.NetworkSubInterfaceIndex,
                process,
                matchedPattern,
                captureTimestamp,
                processResolvedTimestamp,
                out _))
        {
            PassPacket(packetBytes, address);
            return;
        }

        Interlocked.Increment(ref _packetsRelayed);
    }

    private void MarkUdpPassThrough(UdpPassThroughKey key, TimeSpan ttl)
    {
        if (_udpPassThroughUntil.Count >= MaxUdpPassThroughEntries
            && !_udpPassThroughUntil.ContainsKey(key))
        {
            _udpPassThroughUntil.Clear();
        }

        _udpPassThroughUntil[key] = Environment.TickCount64 + (long)ttl.TotalMilliseconds;
    }

    private bool TryResolveProcess(
        PacketView packet,
        out ProcessInfo? process,
        out uint processId,
        out bool isRelayProcess)
    {
        process = null;
        processId = 0;
        isRelayProcess = false;

        if (_flowTracker?.TryGetProcessId(packet, out processId) == true)
        {
            if (processId == (uint)Environment.ProcessId)
            {
                isRelayProcess = true;
                return true;
            }

            process = _processLookup.GetProcessInfo((int)processId);
            if (process is not null)
            {
                return true;
            }
        }

        var foundOwner = packet.IsTcp
            ? _processLookup.TryGetTcpOwnerPid(
                packet.Session,
                forceRefresh: packet.IsInitialSyn,
                out var ownerPid)
            : _processLookup.TryGetUdpOwnerPid(
                packet.UdpEndpoint,
                forceRefresh: false,
                out ownerPid);
        if (!foundOwner)
        {
            return false;
        }

        processId = (uint)ownerPid;
        isRelayProcess = processId == (uint)Environment.ProcessId;
        process = isRelayProcess
            ? null
            : _processLookup.GetProcessInfo(ownerPid);
        return isRelayProcess || process is not null;
    }

    private DirectRelayTarget CreateTarget(
        PacketView packet,
        uint interfaceIndex,
        uint subInterfaceIndex,
        ProcessInfo process,
        string? matchedPattern)
    {
        var hasResolvedMtu = NetworkInterfaceIndexResolver.TryGetMtu(
            (int)interfaceIndex,
            packet.AddressFamily,
            out var resolvedMtu);
        if (!hasResolvedMtu)
        {
            LogWarningThrottled(
                "mtu-fallback",
                $"WinDivert MTU lookup failed for interfaceIndex={interfaceIndex}; using 1500.");
        }

        var mtu = hasResolvedMtu ? resolvedMtu : 1500;
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
            new IntPtr(interfaceIndex),
            AdapterMtu: mtu,
            InterfaceIndex: (int)interfaceIndex,
            SubInterfaceIndex: subInterfaceIndex,
            WireAddressFamily: (ushort)(packet.AddressFamily == AddressFamily.InterNetwork ? 2 : 23),
            ProcessStartTimeUtcTicks: process.StartTimeUtcTicks);
    }

    private static TcpRelayKey CreateTcpRelayKey(
        PacketView packet,
        uint interfaceIndex,
        uint subInterfaceIndex)
    {
        return new TcpRelayKey(
            new IntPtr(interfaceIndex),
            dot1q: 0,
            packet.SourceAddress,
            packet.DestinationAddress,
            packet.SourcePort,
            packet.DestinationPort,
            subInterfaceIndex);
    }

    private static UdpRelayKey CreateUdpRelayKey(
        PacketView packet,
        uint interfaceIndex,
        uint subInterfaceIndex,
        uint processId)
    {
        return new UdpRelayKey(
            new IntPtr(interfaceIndex),
            dot1q: 0,
            packet.SourceAddress,
            packet.SourcePort,
            packet.DestinationAddress,
            packet.DestinationPort,
            subInterfaceIndex,
            compartmentId: 0,
            (ushort)(packet.AddressFamily == AddressFamily.InterNetwork ? 2 : 23),
            processId,
            flowId: 0);
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

    private void PassPacket(ReadOnlySpan<byte> packet, WinDivertAddress address)
    {
        Interlocked.Increment(ref _packetsPassed);
        if (!WinDivertNative.TrySend(_networkHandle!, packet, address, out var error))
        {
            throw new IOException(
                $"WinDivert could not return a captured packet to the network stack: {new Win32Exception(error).Message}");
        }
    }

    private void LogHealthIfDue()
    {
        if (!_detailedLogging.Enabled)
        {
            return;
        }

        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastHealthLogTick);
        if (last != 0 && now - last < 5000)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _lastHealthLogTick, now, last) != last)
        {
            return;
        }

        _log(
            $"WinDivert health: received={Interlocked.Read(ref _packetsReceived)} passed={Interlocked.Read(ref _packetsPassed)} relayed={Interlocked.Read(ref _packetsRelayed)} errors={Interlocked.Read(ref _packetErrors)}.");
    }

    private void LogPacketQueueFull()
    {
        Interlocked.Increment(ref _packetQueueFull);
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastPacketQueueFullLogTick);
        if (last != 0 && now - last < 5000)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _lastPacketQueueFullLogTick, now, last) != last)
        {
            return;
        }

        _warningLog(
            $"WinDivert packet processing queue is full; passing captured packets directly. queued_full={Interlocked.Read(ref _packetQueueFull)}.");
    }

    private void LogWarningThrottled(string category, string message, int intervalMs = 5000)
    {
        var now = Environment.TickCount64;
        if (_warningTimes.TryGetValue(category, out var last) && now - last < intervalMs)
        {
            return;
        }

        _warningTimes[category] = now;
        _warningLog(message);
    }

    private void RequestStop()
    {
        if (_cts.IsCancellationRequested)
        {
            return;
        }

        _cts.Cancel();
        if (_networkHandle is not null)
        {
            WinDivertNative.ShutdownReceive(_networkHandle);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _lifecycleGate.WaitAsync().ConfigureAwait(false);
        var gateReleased = false;
        try
        {
            if (_disposed)
            {
                return;
            }

            RequestStop();
            var stopped = await WaitForPacketTasksAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            if (!stopped)
            {
                _log(
                    "WinDivert packet router shutdown timed out; forcing the local network handle closed.");
                _networkHandle?.Dispose();
                _networkHandle = null;
                stopped = await WaitForPacketTasksAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
            }

            if (!stopped)
            {
                throw new TimeoutException(
                    "WinDivert capture or packet processing did not stop; relay resources were retained.");
            }

            _packetQueue.Writer.TryComplete();
            _udpRelay?.Dispose();
            _tcpRelay?.Dispose();
            _flowTracker?.Dispose();
            _networkHandle?.Dispose();
            _udpRelay = null;
            _tcpRelay = null;
            _flowTracker = null;
            _injector = null;
            _networkHandle = null;
            _captureTask = null;
            _packetProcessingTask = null;
            if (_hasStopRegistration)
            {
                _stopRegistration.Dispose();
                _stopRegistration = default;
                _hasStopRegistration = false;
            }

            _disposed = true;
            _cts.Dispose();
            _lifecycleGate.Release();
            gateReleased = true;
            _lifecycleGate.Dispose();
            GC.SuppressFinalize(this);
        }
        finally
        {
            if (!gateReleased)
            {
                _lifecycleGate.Release();
            }
        }
    }

    private void CleanupAfterStartFailure()
    {
        _cts.Cancel();
        _packetQueue.Writer.TryComplete();
        if (_networkHandle is not null)
        {
            WinDivertNative.ShutdownReceive(_networkHandle);
        }

        _udpRelay?.Dispose();
        _tcpRelay?.Dispose();
        _flowTracker?.Dispose();
        _networkHandle?.Dispose();
        _udpRelay = null;
        _tcpRelay = null;
        _flowTracker = null;
        _injector = null;
        _networkHandle = null;
        _captureTask = null;
        _packetProcessingTask = null;
        if (_hasStopRegistration)
        {
            _stopRegistration.Dispose();
            _stopRegistration = default;
            _hasStopRegistration = false;
        }
    }

    private async Task<bool> WaitForPacketTasksAsync(TimeSpan timeout)
    {
        var tasks = new List<Task> { Completion };
        if (_packetProcessingTask is not null)
        {
            tasks.Add(_packetProcessingTask);
        }

        try
        {
            await Task.WhenAll(tasks).WaitAsync(timeout).ConfigureAwait(false);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
        catch
        {
            return tasks.All(task => task.IsCompleted);
        }
    }

    private readonly record struct UdpPassThroughKey(
        WinDivertFlowKey Flow,
        uint InterfaceIndex,
        uint SubInterfaceIndex);

    private readonly record struct CapturedPacket(
        byte[] Buffer,
        int Length,
        WinDivertAddress Address);
}
