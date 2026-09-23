using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class WinDivertPacketRouter : IAsyncDisposable
{
    private const int MaxTcpRelayConnections = 4096;
    private const int MaxPacketLength = 131072;
    private const int MaxUdpPassThroughEntries = 65536;
    private static readonly TimeSpan UdpPassThroughTtl = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan UdpProcessMissPassThroughTtl = TimeSpan.FromMilliseconds(250);
    private const string CaptureFilter = "outbound and !loopback and (tcp or udp)";

    private readonly DynamicAppConfiguration _configuration;
    private readonly ProcessLookup _processLookup;
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TrafficCounter _trafficCounter;
    private readonly PacketWakeSignal _packetWakeSignal;
    private readonly TimeProvider _timeProvider;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<UdpPassThroughKey, long> _udpPassThroughUntil = new();
    private long _packetsReceived;
    private long _packetsPassed;
    private long _packetsRelayed;
    private long _packetErrors;
    private long _lastHealthLogTick;
    private readonly TaskCompletionSource _completed =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private WinDivertHandle? _networkHandle;
    private WinDivertFlowTracker? _flowTracker;
    private WinDivertPacketInjector? _injector;
    private TcpDirectRelay? _tcpRelay;
    private WinDivertUdpRelay? _udpRelay;
    private Task? _captureTask;
    private bool _disposed;

    public WinDivertPacketRouter(
        DynamicAppConfiguration configuration,
        ProcessLookup processLookup,
        Action<string> log,
        TrafficCounter trafficCounter,
        PacketWakeSignal packetWakeSignal,
        TimeProvider timeProvider,
        bool detailedLogging)
    {
        _configuration = configuration;
        _processLookup = processLookup;
        _log = log;
        _trafficCounter = trafficCounter;
        _packetWakeSignal = packetWakeSignal;
        _timeProvider = timeProvider;
        _detailedLogging = detailedLogging;
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

            _flowTracker = new WinDivertFlowTracker(_processLookup, _log, flowHandle);
            _flowTracker.Start();
            _injector = new WinDivertPacketInjector(_networkHandle, _log, _detailedLogging);

            _tcpRelay = new TcpDirectRelay(
                _log,
                _detailedLogging,
                _trafficCounter,
                _packetWakeSignal,
                _timeProvider);
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
                _detailedLogging);
            _udpRelay.Start(_cts.Token);

            _captureTask = Task.Factory.StartNew(
                () => CaptureLoop(_cts.Token),
                _cts.Token,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);

            var linkedRegistration = cancellationToken.Register(
                static state => ((WinDivertPacketRouter)state!).RequestStop(),
                this);
            _ = linkedRegistration;
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
                try
                {
                    ProcessPacket(buffer.AsSpan(0, packetLength), address);
                    LogHealthIfDue();
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _packetErrors);
                    _log($"WinDivert packet handling failed: {ex}");
                    try
                    {
                        PassPacket(buffer.AsSpan(0, packetLength), address);
                    }
                    catch (Exception passException)
                    {
                        _log($"WinDivert packet recovery pass-through failed: {passException.Message}");
                    }
                }
            }

            _completed.TrySetResult();
        }
        catch (Exception ex)
        {
            _completed.TrySetException(ex);
            _log($"WinDivert packet router stopped unexpectedly: {ex}");
        }
    }

    private void ProcessPacket(Span<byte> packetBytes, WinDivertAddress address)
    {
        if (!PacketView.TryParseIp(packetBytes, packetBytes.Length, out var packet))
        {
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

        var relayKey = CreateTcpRelayKey(packet, interfaceIndex);
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
                if (_detailedLogging)
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
            _tcpRelay.MarkBypassedFlow(relayKey);
            _log(
                $"WinDivert TCP relay connection limit reached ({MaxTcpRelayConnections}); passing new target flow directly.");
            PassPacket(packetBytes, address);
            return;
        }

        if (!TryResolveProcess(packet, out var process, out var processId, out var isRelayProcess)
            || isRelayProcess
            || process is null)
        {
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
            _tcpRelay.MarkBypassedFlow(relayKey);
            _log(
                $"WinDivert TCP relay could not resolve the outbound interface for {packet.Session}; passing directly.");
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
            _log(
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
        var mtu = NetworkInterfaceIndexResolver.TryGetMtu(
            (int)interfaceIndex,
            packet.AddressFamily,
            out var resolvedMtu)
            ? resolvedMtu
            : 1500;
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

    private static TcpRelayKey CreateTcpRelayKey(PacketView packet, uint interfaceIndex)
    {
        return new TcpRelayKey(
            new IntPtr(interfaceIndex),
            dot1q: 0,
            packet.SourceAddress,
            packet.DestinationAddress,
            packet.SourcePort,
            packet.DestinationPort);
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
        if (!_detailedLogging)
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
        try
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            RequestStop();
            var captureStopped = false;
            try
            {
                await Completion.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
                captureStopped = true;
            }
            catch (TimeoutException)
            {
                _log("WinDivert packet router shutdown timed out; forcing the network handle closed.");
                _networkHandle?.Dispose();
                _networkHandle = null;
            }
            catch
            {
                captureStopped = true;
            }

            if (!captureStopped && _networkHandle is null)
            {
                try
                {
                    await Completion.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                    captureStopped = true;
                }
                catch
                {
                }
            }

            if (!captureStopped)
            {
                throw new TimeoutException(
                    "WinDivert capture loop did not stop; relay resources were retained.");
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
            _cts.Dispose();
            _lifecycleGate.Release();
            _lifecycleGate.Dispose();
            GC.SuppressFinalize(this);
        }
        catch
        {
            _lifecycleGate.Release();
            throw;
        }
    }

    private void CleanupAfterStartFailure()
    {
        _cts.Cancel();
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
    }

    private readonly record struct UdpPassThroughKey(
        WinDivertFlowKey Flow,
        uint InterfaceIndex,
        uint SubInterfaceIndex);
}
