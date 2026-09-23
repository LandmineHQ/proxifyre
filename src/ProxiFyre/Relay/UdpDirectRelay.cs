using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class UdpDirectRelay : IDisposable
{
    private static readonly TimeSpan TargetTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan BypassFlowTtl = TimeSpan.FromSeconds(30);
    private const int MaxSessions = 4096;
    private const int MaxTargets = 16384;
    private const int MaxQueuedSendsPerSession = 2048;
    private const long MaxQueuedBytesPerSession = 32L * 1024 * 1024;

    private readonly ConcurrentDictionary<UdpRelayKey, DirectRelayTarget> _targets = new();
    private readonly ConcurrentDictionary<UdpRelaySessionKey, UdpRelaySocket> _sockets = new();
    private readonly ConcurrentDictionary<UdpRelayKey, long> _targetGenerations = new();
    private readonly ConcurrentDictionary<UdpRelayKey, byte> _relayOutboundFlows = new();
    private readonly ConcurrentDictionary<UdpRelayKey, DateTimeOffset> _bypassedFlows = new();
    private readonly object _socketCreationSync = new();
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TrafficCounter _trafficCounter;
    private readonly PacketWakeSignal? _packetWakeSignal;
    private readonly TimeProvider _timeProvider;
    private Func<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, bool>? _responseInjector;
    private Func<DirectRelayTarget, bool>? _responseValidator;
    private Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, SocketError>? _errorInjector;
    private Action<RelayOutboundFlow>? _outboundBypassRegister;
    private Action<RelayOutboundFlow>? _outboundBypassUnregister;
    private Action<RelayOutboundFlow>? _targetRedirectUnregister;
    private CancellationToken _cancellationToken;
    private bool _disposed;
    private long _nextGeneration;

    public UdpDirectRelay(
        Action<string>? log = null,
        bool detailedLogging = false,
        TrafficCounter? trafficCounter = null,
        PacketWakeSignal? packetWakeSignal = null,
        TimeProvider? timeProvider = null)
    {
        _log = log ?? Console.WriteLine;
        _detailedLogging = detailedLogging;
        _trafficCounter = trafficCounter ?? new TrafficCounter();
        _packetWakeSignal = packetWakeSignal;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public void SetResponseInjector(
        Func<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, bool> responseInjector)
    {
        _responseInjector = responseInjector;
    }

    public void SetErrorInjector(
        Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, SocketError> errorInjector)
    {
        _errorInjector = errorInjector;
    }

    public void SetResponseValidator(Func<DirectRelayTarget, bool> responseValidator)
    {
        _responseValidator = responseValidator;
    }

    public void SetOutboundBypass(
        Action<RelayOutboundFlow> register,
        Action<RelayOutboundFlow> unregister)
    {
        _outboundBypassRegister = register;
        _outboundBypassUnregister = unregister;
    }

    public void SetTargetRedirectUnregister(Action<RelayOutboundFlow> unregister)
    {
        _targetRedirectUnregister = unregister;
    }

    public void Start(CancellationToken cancellationToken)
    {
        _cancellationToken = cancellationToken;
        _ = Task.Run(() => CleanupLoopAsync(cancellationToken), cancellationToken);
        LogDetail(
            "Local direct UDP relay uses one stable outbound socket per local endpoint and packet injection; no local UDP listener is opened.");
    }

    public long Register(UdpRelayKey key, DirectRelayTarget target)
    {
        lock (_socketCreationSync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_targets.ContainsKey(key) && _targets.Count >= MaxTargets)
            {
                throw new InvalidOperationException("UDP relay target limit reached.");
            }

            if (!_targets.TryGetValue(key, out var current)
                || !TargetMatches(current, target))
            {
                var generation = Interlocked.Increment(ref _nextGeneration);
                _targetGenerations[key] = generation;
                _targets[key] = target;
                return generation;
            }

            _targets[key] = current with { CreatedAt = _timeProvider.GetUtcNow() };
            return _targetGenerations.TryGetValue(key, out var existingGeneration)
                ? existingGeneration
                : 0;
        }
    }

    public bool Refresh(UdpRelayKey key)
    {
        if (!_targets.TryGetValue(key, out var target))
        {
            return false;
        }

        return _targets.TryUpdate(
            key,
            target with { CreatedAt = _timeProvider.GetUtcNow() },
            target);
    }

    public bool TryGetTarget(UdpRelayKey key, out DirectRelayTarget target)
    {
        return _targets.TryGetValue(key, out target!);
    }

    public bool IsRelayOutboundFlow(UdpRelayKey key)
    {
        if (_relayOutboundFlows.ContainsKey(key))
        {
            return true;
        }

        var wildcardAddress = key.ClientAddress.AddressFamily == AddressFamily.InterNetwork
            ? IPAddress.Any
            : IPAddress.IPv6Any;
        return _relayOutboundFlows.ContainsKey(new UdpRelayKey(
            key.AdapterHandle,
            key.Dot1q,
            wildcardAddress,
            key.ClientPort,
            key.RemoteAddress,
            key.RemotePort,
            key.SubInterfaceIndex,
            key.CompartmentId,
            key.WireAddressFamily,
            key.ProcessId));
    }

    public void MarkBypassedFlow(UdpRelayKey key)
    {
        _bypassedFlows[key] = _timeProvider.GetUtcNow();
    }

    public bool IsBypassedFlow(UdpRelayKey key)
    {
        if (!_bypassedFlows.TryGetValue(key, out var markedAt))
        {
            return false;
        }

        if (_timeProvider.GetUtcNow() - markedAt <= BypassFlowTtl)
        {
            _bypassedFlows[key] = _timeProvider.GetUtcNow();
            return true;
        }

        _bypassedFlows.TryRemove(key, out _);
        return false;
    }

    public bool TrySubmit(
        UdpRelayKey key,
        DirectRelayTarget target,
        ReadOnlyMemory<byte> payload,
        IPAddress remoteAddress,
        ushort remotePort,
        out string? failureReason)
    {
        return TrySubmit(key, target, payload, remoteAddress, remotePort, out failureReason, out _);
    }

    public bool TrySubmit(
        UdpRelayKey key,
        DirectRelayTarget target,
        ReadOnlyMemory<byte> payload,
        IPAddress remoteAddress,
        ushort remotePort,
        out string? failureReason,
        out bool retryable)
    {
        // Reuse the socket and external port for every destination reached by
        // the same captured local UDP endpoint.
        failureReason = null;
        retryable = false;
        var payloadCopy = payload.ToArray();
        var submittedTimestamp = Stopwatch.GetTimestamp();
        var targetRegistered = false;
        try
        {
            lock (_socketCreationSync)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (!_targets.ContainsKey(key) && _targets.Count >= MaxTargets)
                {
                    failureReason = "UDP relay target limit reached.";
                    return false;
                }

                var generation = Register(key, target);
                targetRegistered = true;

                var sessionKey = UdpRelaySessionKey.FromRelayKey(key);
                var relaySocket = GetOrCreateSocketLocked(sessionKey, target);
                var remoteEndPoint = NetworkEndpointResolver.CreateRemoteEndPoint(
                    target,
                    remoteAddress,
                    remotePort);
                if (relaySocket.TargetCount == 0)
                {
                    relaySocket.SendInitial(
                        key,
                        target,
                        generation,
                        payloadCopy,
                        remoteEndPoint,
                        submittedTimestamp);
                }
                else
                {
                    relaySocket.Enqueue(
                        key,
                        target,
                        generation,
                        payloadCopy,
                        remoteEndPoint,
                        submittedTimestamp);
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            failureReason = ex.Message;
            retryable = ex is UdpQueueFullException;
            if (targetRegistered)
            {
                if (!retryable)
                {
                    Remove(key);
                }
            }

            return false;
        }
    }

    public async Task SendToRemoteAsync(
        UdpRelayKey key,
        DirectRelayTarget target,
        ReadOnlyMemory<byte> payload,
        IPAddress remoteAddress,
        ushort remotePort)
    {
        if (!TrySubmit(key, target, payload, remoteAddress, remotePort, out var failureReason))
        {
            throw new IOException(failureReason ?? "UDP relay submission failed.");
        }

        await Task.Yield();
    }

    public void ApplyConfiguration(AppConfiguration configuration)
    {
        foreach (var pair in _targets.ToArray())
        {
            var process = new ProcessInfo(
                pair.Value.ProcessId,
                pair.Value.ProcessName,
                pair.Value.ProcessPath);
            if (!configuration.TryGetMatchingPattern(process, out _, out _))
            {
                Remove(pair.Key);
            }
        }

        _bypassedFlows.Clear();
    }

    public void RemoveTargetsWithMissingAdapters(IReadOnlySet<IntPtr> adapterHandles)
    {
        foreach (var key in _targets.Keys)
        {
            if (!adapterHandles.Contains(key.AdapterHandle))
            {
                Remove(key);
            }
        }

        foreach (var key in _bypassedFlows.Keys)
        {
            if (!adapterHandles.Contains(key.AdapterHandle))
            {
                _bypassedFlows.TryRemove(key, out _);
            }
        }
    }

    public void Remove(UdpRelayKey key)
    {
        RemoveCore(key, notifyDriver: true);
    }

    public void RemoveOwnedTarget(UdpRelayKey key)
    {
        RemoveCore(key, notifyDriver: false);
    }

    private void RemoveCore(UdpRelayKey key, bool notifyDriver)
    {
        UdpRelaySocket? emptySocket = null;
        var removed = false;
        lock (_socketCreationSync)
        {
            if (_targets.TryRemove(key, out _))
            {
                _targetGenerations.TryRemove(key, out _);
                removed = true;
            }

            var sessionKey = UdpRelaySessionKey.FromRelayKey(key);
            if (_sockets.TryGetValue(sessionKey, out var socket))
            {
                socket.RemoveTarget(key);
                if (socket.TargetCount == 0)
                {
                    _sockets.TryRemove(sessionKey, out _);
                    emptySocket = socket;
                }
            }
        }

        emptySocket?.Dispose();
        if (removed && notifyDriver)
        {
            _targetRedirectUnregister?.Invoke(ToRelayFlow(key));
        }
    }

    private UdpRelaySocket GetOrCreateSocketLocked(
        UdpRelaySessionKey sessionKey,
        DirectRelayTarget target)
    {
        if (_sockets.TryGetValue(sessionKey, out var existing))
        {
            if (existing.MatchesSession(target))
            {
                return existing;
            }

            RemoveSession(sessionKey, existing);
        }

        if (_sockets.Count >= MaxSessions)
        {
            throw new InvalidOperationException("UDP relay session limit reached.");
        }

        var socket = CreateSocket(sessionKey, target);
        try
        {
            _sockets[sessionKey] = socket;
            socket.Start(_cancellationToken);
            return socket;
        }
        catch
        {
            _sockets.TryRemove(sessionKey, out _);
            socket.Dispose();
            throw;
        }
    }

    private UdpRelaySocket CreateSocket(
        UdpRelaySessionKey sessionKey,
        DirectRelayTarget target)
    {
        var remoteEndPoint = NetworkEndpointResolver.CreateRemoteEndPoint(target);
        var socket = CreateUdpSocket(remoteEndPoint.AddressFamily, target.CompartmentId);
        var bindEndPoint = NetworkEndpointResolver.CreateBindEndPoint(target);
        try
        {
            ApplyOutboundInterface(socket, target, remoteEndPoint.AddressFamily);
            socket.Bind(
                bindEndPoint is not null && bindEndPoint.AddressFamily == remoteEndPoint.AddressFamily
                    ? bindEndPoint
                    : NetworkEndpointResolver.CreateAnyEndPoint(remoteEndPoint.AddressFamily));

            UdpRelaySocket? relaySocket = null;
            try
            {
                relaySocket = new UdpRelaySocket(
                    socket,
                    sessionKey,
                    target,
                    _relayOutboundFlows,
                    key => _targets.TryGetValue(key, out var currentTarget) ? currentTarget : null,
                    key => _targetGenerations.TryGetValue(key, out var generation) ? generation : null,
                    key => _ = Refresh(key),
                    Remove,
                    RemoveSession,
                    _outboundBypassRegister,
                    _outboundBypassUnregister,
                    _trafficCounter,
                    _packetWakeSignal,
                    _responseInjector,
                    _responseValidator,
                    _errorInjector,
                    _detailedLogging ? LogDetail : null,
                    _log,
                    _timeProvider,
                    MaxQueuedSendsPerSession);
                return relaySocket;
            }
            catch
            {
                relaySocket?.Dispose();
                throw;
            }
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private void RemoveSession(UdpRelaySessionKey sessionKey, UdpRelaySocket socket)
    {
        List<UdpRelayKey> removedTargets = [];
        lock (_socketCreationSync)
        {
            if (!_sockets.TryGetValue(sessionKey, out var current)
                || !ReferenceEquals(current, socket))
            {
                return;
            }

            _sockets.TryRemove(sessionKey, out _);
            foreach (var pair in _targets)
            {
                if (UdpRelaySessionKey.FromRelayKey(pair.Key) == sessionKey)
                {
                    removedTargets.Add(pair.Key);
                }
            }

            foreach (var key in removedTargets)
            {
                _targets.TryRemove(key, out _);
                _targetGenerations.TryRemove(key, out _);
            }
        }

        socket.Dispose();
        foreach (var key in removedTargets)
        {
            _targetRedirectUnregister?.Invoke(ToRelayFlow(key));
        }
    }

    private void ApplyOutboundInterface(
        Socket socket,
        DirectRelayTarget target,
        AddressFamily remoteFamily)
    {
        if (target.AdapterHandle == IntPtr.Zero)
        {
            return;
        }

        if (target.InterfaceIndex <= 0)
        {
            throw new InvalidOperationException(
                $"UDP relay cannot pin interface for {target.ClientEndpoint} -> {target.RemoteEndpoint}: the interface index is unavailable.");
        }

        try
        {
            var optionValue = remoteFamily == AddressFamily.InterNetwork
                ? IPAddress.HostToNetworkOrder(target.InterfaceIndex)
                : target.InterfaceIndex;
            socket.SetSocketOption(
                remoteFamily == AddressFamily.InterNetwork
                    ? SocketOptionLevel.IP
                    : SocketOptionLevel.IPv6,
                (SocketOptionName)31,
                optionValue);
        }
        catch (Exception ex) when (ex is SocketException or PlatformNotSupportedException or ArgumentException)
        {
            throw new InvalidOperationException(
                $"UDP relay could not pin interfaceIndex={target.InterfaceIndex} for {target.ClientEndpoint} -> {target.RemoteEndpoint}: {ex.Message}",
                ex);
        }
    }

    private void LogDetail(string message)
    {
        if (_detailedLogging)
        {
            _log(message);
        }
    }

    private Socket CreateUdpSocket(AddressFamily addressFamily, uint compartmentId)
    {
        Socket? socket = null;
        var previousCompartment = 0u;
        var compartmentChanged = false;
        if (compartmentId != 0)
        {
            try
            {
                previousCompartment = GetCurrentThreadCompartmentId();
                if (previousCompartment != compartmentId)
                {
                    var status = SetCurrentThreadCompartmentId(compartmentId);
                    if (status != 0)
                    {
                        throw new InvalidOperationException(
                            $"Could not enter network compartment {compartmentId}: {new System.ComponentModel.Win32Exception((int)status).Message}");
                    }

                    compartmentChanged = true;
                }
            }
            catch (EntryPointNotFoundException ex)
            {
                throw new InvalidOperationException(
                    "The current Windows version cannot reproduce the captured UDP network compartment.",
                    ex);
            }
        }

        try
        {
            socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (addressFamily == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = true;
            }

            return socket;
        }
        finally
        {
            if (compartmentChanged)
            {
                var restoreStatus = SetCurrentThreadCompartmentId(previousCompartment);
                if (restoreStatus != 0)
                {
                    socket?.Dispose();
                    throw new InvalidOperationException(
                        $"Could not restore the previous UDP network compartment {previousCompartment}.");
                }
            }
        }
    }

    private async Task CleanupLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(CleanupInterval, _timeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            var now = _timeProvider.GetUtcNow();
            foreach (var pair in _targets)
            {
                if (now - pair.Value.CreatedAt > TargetTtl)
                {
                    Remove(pair.Key);
                }
            }

            foreach (var pair in _bypassedFlows)
            {
                if (now - pair.Value > BypassFlowTtl)
                {
                    _bypassedFlows.TryRemove(pair.Key, out _);
                }
            }
        }
    }

    public void Dispose()
    {
        UdpRelaySocket[] sockets;
        KeyValuePair<UdpRelayKey, DirectRelayTarget>[] targets;
        lock (_socketCreationSync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            sockets = _sockets.Values.ToArray();
            targets = _targets.ToArray();
            _sockets.Clear();
            _targets.Clear();
            _targetGenerations.Clear();
            _relayOutboundFlows.Clear();
            _bypassedFlows.Clear();
        }

        foreach (var socket in sockets)
        {
            socket.Dispose();
        }

        foreach (var pair in targets)
        {
            _targetRedirectUnregister?.Invoke(ToRelayFlow(pair.Key));
        }
    }

    internal sealed class UdpRelaySocket : IDisposable
    {
        private readonly Socket _socket;
        private readonly UdpRelaySessionKey _sessionKey;
        private readonly Func<UdpRelayKey, DirectRelayTarget?> _getTarget;
        private readonly Func<UdpRelayKey, long?> _getGeneration;
        private readonly Action<UdpRelayKey> _refreshTarget;
        private readonly Action<UdpRelayKey> _removeTarget;
        private readonly Action<UdpRelaySessionKey, UdpRelaySocket> _removeSession;
        private readonly ConcurrentDictionary<UdpRelayKey, byte> _relayOutboundFlows;
        private readonly Action<RelayOutboundFlow>? _outboundBypassRegister;
        private readonly Action<RelayOutboundFlow>? _outboundBypassUnregister;
        private readonly TrafficCounter _trafficCounter;
        private readonly PacketWakeSignal? _packetWakeSignal;
        private readonly Func<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, bool>? _responseInjector;
        private readonly Func<DirectRelayTarget, bool>? _responseValidator;
        private readonly Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, SocketError>? _errorInjector;
        private readonly Action<string>? _detailLog;
        private readonly Action<string> _errorLog;
        private readonly TimeProvider _timeProvider;
        private CancellationTokenSource? _runCts;
        private readonly object _sync = new();
        private readonly Queue<UdpSendItem> _sendQueue = [];
        private readonly SemaphoreSlim _sendSignal = new(0);
        private readonly Dictionary<UdpRelayKey, RelayOutboundFlow[]> _outboundFlows = [];
        private readonly int _maxQueuedSends;
        private long _queuedBytes;
        private DirectRelayTarget _sessionTarget;
        private DateTimeOffset _lastSendStatsLog;
        private DateTimeOffset _lastReceiveStatsLog;
        private DateTimeOffset _lastUnregisteredResponseLog;
        private long _upBytes;
        private long _downBytes;
        private long _firstSendTimestamp;
        private long _firstResponseTimestamp;
        private bool _sniProbeFinished;
        private int _disposed;

        public UdpRelaySocket(
            Socket socket,
            UdpRelaySessionKey sessionKey,
            DirectRelayTarget target,
            ConcurrentDictionary<UdpRelayKey, byte> relayOutboundFlows,
            Func<UdpRelayKey, DirectRelayTarget?> getTarget,
            Func<UdpRelayKey, long?> getGeneration,
            Action<UdpRelayKey> refreshTarget,
            Action<UdpRelayKey> removeTarget,
            Action<UdpRelaySessionKey, UdpRelaySocket> removeSession,
            Action<RelayOutboundFlow>? outboundBypassRegister,
            Action<RelayOutboundFlow>? outboundBypassUnregister,
            TrafficCounter trafficCounter,
            PacketWakeSignal? packetWakeSignal,
            Func<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, bool>? responseInjector,
            Func<DirectRelayTarget, bool>? responseValidator,
            Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, SocketError>? errorInjector,
            Action<string>? detailLog,
            Action<string> errorLog,
            TimeProvider timeProvider,
            int maxQueuedSends)
        {
            _socket = socket;
            _sessionKey = sessionKey;
            _sessionTarget = target;
            _getTarget = getTarget;
            _getGeneration = getGeneration;
            _refreshTarget = refreshTarget;
            _removeTarget = removeTarget;
            _removeSession = removeSession;
            _relayOutboundFlows = relayOutboundFlows;
            _outboundBypassRegister = outboundBypassRegister;
            _outboundBypassUnregister = outboundBypassUnregister;
            _trafficCounter = trafficCounter;
            _packetWakeSignal = packetWakeSignal;
            _responseInjector = responseInjector;
            _responseValidator = responseValidator;
            _errorInjector = errorInjector;
            _detailLog = detailLog;
            _errorLog = errorLog;
            _timeProvider = timeProvider;
            _maxQueuedSends = maxQueuedSends;
        }

        public int TargetCount
        {
            get
            {
                lock (_sync)
                {
                    return _outboundFlows.Count;
                }
            }
        }

        public bool MatchesSession(DirectRelayTarget target)
        {
            return target.AdapterHandle == _sessionKey.AdapterHandle
                && target.Dot1q == _sessionKey.Dot1q
                && target.SubInterfaceIndex == _sessionKey.SubInterfaceIndex
                && target.CompartmentId == _sessionKey.CompartmentId
                && (target.WireAddressFamily == 0
                    || _sessionKey.WireAddressFamily == 0
                    || target.WireAddressFamily == _sessionKey.WireAddressFamily)
                && (target.ProcessId == 0
                    || _sessionKey.ProcessId == 0
                    || (uint)target.ProcessId == _sessionKey.ProcessId)
                && Equals(target.ClientAddress, _sessionKey.ClientAddress)
                && target.ClientPort == _sessionKey.ClientPort;
        }

        public void Start(CancellationToken cancellationToken)
        {
            if (_runCts is not null)
            {
                throw new InvalidOperationException("UDP relay socket is already running.");
            }

            var runCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _runCts = runCts;
            var token = runCts.Token;
            _ = Task.Run(() => SendLoopAsync(token), CancellationToken.None);
            _ = Task.Run(() => ReceiveRemoteLoopAsync(token), CancellationToken.None);
        }

        public void Enqueue(
            UdpRelayKey key,
            DirectRelayTarget target,
            long generation,
            byte[] payload,
            IPEndPoint remoteEndPoint,
            long submittedTimestamp)
        {
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                if (_sendQueue.Count >= _maxQueuedSends
                    || payload.Length > MaxQueuedBytesPerSession - _queuedBytes)
                {
                    throw new UdpQueueFullException(
                        $"UDP relay send queue is full for {_sessionKey}.");
                }

                _sessionTarget = target;
                RegisterOutboundFlowsLocked(key, remoteEndPoint);
                _sendQueue.Enqueue(new UdpSendItem(
                    key,
                    target,
                    generation,
                    payload,
                    remoteEndPoint,
                    submittedTimestamp));
                _queuedBytes += payload.Length;
            }

            Pulse(_sendSignal);
        }

        public void SendInitial(
            UdpRelayKey key,
            DirectRelayTarget target,
            long generation,
            byte[] payload,
            IPEndPoint remoteEndPoint,
            long submittedTimestamp)
        {
            var item = new UdpSendItem(
                key,
                target,
                generation,
                payload,
                remoteEndPoint,
                submittedTimestamp);
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                _sessionTarget = target;
                RegisterOutboundFlowsLocked(key, remoteEndPoint);
            }

            try
            {
                SendItemCore(item, CancellationToken.None);
            }
            catch
            {
                RemoveTarget(key);
                throw;
            }
        }

        public void RemoveTarget(UdpRelayKey key)
        {
            RelayOutboundFlow[]? flows;
            List<UdpSendItem>? kept = null;
            lock (_sync)
            {
                if (!_outboundFlows.Remove(key, out flows))
                {
                    return;
                }

                if (_sendQueue.Count > 0)
                {
                    kept = [];
                    while (_sendQueue.Count > 0)
                    {
                        var item = _sendQueue.Dequeue();
                        if (item.Key.Equals(key))
                        {
                            _queuedBytes -= item.Payload.Length;
                        }
                        else
                        {
                            kept.Add(item);
                        }
                    }

                    foreach (var item in kept)
                    {
                        _sendQueue.Enqueue(item);
                    }
                }
            }

            UnregisterOutboundFlows(flows);
        }

        private void RegisterOutboundFlowsLocked(UdpRelayKey key, IPEndPoint remoteEndPoint)
        {
            if (_outboundFlows.ContainsKey(key))
            {
                return;
            }

            if (_socket.LocalEndPoint is not IPEndPoint localEndPoint)
            {
                throw new InvalidOperationException("UDP relay socket has no local endpoint.");
            }

            var localAddress = NetworkAddress.Normalize(localEndPoint.Address);
            var wildcardAddress = localAddress.AddressFamily == AddressFamily.InterNetwork
                ? IPAddress.Any
                : IPAddress.IPv6Any;
            List<RelayOutboundFlow> flows =
            [
                new RelayOutboundFlow(
                    key.AdapterHandle,
                    PacketView.ProtocolUdp,
                    localAddress,
                    remoteEndPoint.Address,
                    (ushort)localEndPoint.Port,
                    (ushort)remoteEndPoint.Port,
                    key.Dot1q,
                    key.SubInterfaceIndex,
                    key.CompartmentId,
                    key.WireAddressFamily,
                    processId: key.ProcessId,
                    flowId: key.FlowId)
            ];

            if (!localAddress.Equals(wildcardAddress))
            {
                flows.Add(new RelayOutboundFlow(
                    key.AdapterHandle,
                    PacketView.ProtocolUdp,
                    wildcardAddress,
                    remoteEndPoint.Address,
                    (ushort)localEndPoint.Port,
                    (ushort)remoteEndPoint.Port,
                    key.Dot1q,
                    key.SubInterfaceIndex,
                    key.CompartmentId,
                    key.WireAddressFamily,
                    processId: key.ProcessId,
                    flowId: key.FlowId));
            }

            _outboundFlows[key] = flows.ToArray();
            foreach (var flow in _outboundFlows[key])
            {
                _relayOutboundFlows[new UdpRelayKey(
                    flow.AdapterHandle,
                    flow.Dot1q,
                    flow.LocalAddress,
                    flow.LocalPort,
                    flow.RemoteAddress,
                    flow.RemotePort,
                    flow.SubInterfaceIndex,
                    flow.CompartmentId,
                    flow.WireAddressFamily,
                    flow.ProcessId)] = 0;
                _outboundBypassRegister?.Invoke(flow);
            }
        }

        private void UnregisterOutboundFlows(IReadOnlyList<RelayOutboundFlow> flows)
        {
            foreach (var flow in flows)
            {
                _relayOutboundFlows.TryRemove(
                    new UdpRelayKey(
                        flow.AdapterHandle,
                        flow.Dot1q,
                        flow.LocalAddress,
                        flow.LocalPort,
                        flow.RemoteAddress,
                        flow.RemotePort,
                        flow.SubInterfaceIndex,
                        flow.CompartmentId,
                        flow.WireAddressFamily,
                        flow.ProcessId),
                    out _);
                try
                {
                    _outboundBypassUnregister?.Invoke(flow);
                }
                catch (Exception ex)
                {
                    _errorLog($"UDP relay outbound bypass cleanup failed flow={flow}: {ex.Message}");
                }
            }
        }

        private async Task SendLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    await _sendSignal.WaitAsync(cancellationToken).ConfigureAwait(false);
                    UdpSendItem? item;
                    lock (_sync)
                    {
                        if (Volatile.Read(ref _disposed) != 0)
                        {
                            return;
                        }

                        item = _sendQueue.Count > 0 ? _sendQueue.Dequeue() : null;
                        if (item is not null)
                        {
                            _queuedBytes -= item.Payload.Length;
                        }
                    }

                    if (item is null)
                    {
                        continue;
                    }

                    if (_getGeneration(item.Key) != item.Generation)
                    {
                        continue;
                    }

                    await SendItemAsync(item, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private async Task SendItemAsync(UdpSendItem item, CancellationToken cancellationToken)
        {
            try
            {
                SendItemCore(item, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (SocketException ex)
            {
                _errorInjector?.Invoke(item.Target, item.RemoteEndPoint, item.Payload, ex.SocketErrorCode);
                _errorLog(
                    $"UDP relay send failed for {item.Key.ClientAddress}:{item.Key.ClientPort} -> {item.Key.RemoteAddress}:{item.Key.RemotePort}: {ex.Message}");
                if (_getGeneration(item.Key) == item.Generation)
                {
                    _removeTarget(item.Key);
                }
            }
            catch (Exception ex)
            {
                _errorLog(
                    $"UDP relay send failed for {item.Key.ClientAddress}:{item.Key.ClientPort} -> {item.Key.RemoteAddress}:{item.Key.RemotePort}: {ex.Message}");
                if (_getGeneration(item.Key) == item.Generation)
                {
                    _removeTarget(item.Key);
                }
            }
        }

        private int SendItemCore(UdpSendItem item, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ProbeClientSni(item.Target, item.Payload);
            var sent = _socket.SendTo(
                item.Payload,
                SocketFlags.None,
                item.RemoteEndPoint);
            if (sent != item.Payload.Length)
            {
                throw new IOException($"UDP relay sent {sent} of {item.Payload.Length} bytes.");
            }

            try
            {
                Interlocked.Add(ref _upBytes, sent);
                Interlocked.CompareExchange(ref _firstSendTimestamp, Stopwatch.GetTimestamp(), 0);
                _trafficCounter.AddUdpUpload(sent);
                _packetWakeSignal?.Pulse();
                LogStats(
                    "SEND",
                    item.Target,
                    Stopwatch.GetElapsedTime(item.EnqueuedTimestamp).TotalMilliseconds);
            }
            catch (Exception ex)
            {
                try
                {
                    _errorLog($"UDP relay post-send accounting failed: {ex.Message}");
                }
                catch
                {
                }
            }

            return sent;
        }

        private void ProbeClientSni(DirectRelayTarget target, ReadOnlySpan<byte> payload)
        {
            if (_sniProbeFinished || payload.IsEmpty)
            {
                return;
            }

            _sniProbeFinished = true;
            if (TlsSniParser.TryGetDtlsServerName(payload, out var serverName))
            {
                _errorLog(
                    $"APP UDP SNI app={target.AppLabel} appLocal={target.ClientEndpoint} client={_sessionKey.ClientAddress}:{_sessionKey.ClientPort} target={target.RemoteEndpoint} domain={serverName}");
            }
        }

        private async Task ReceiveRemoteLoopAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[65535];
            EndPoint sourceEndPoint = new IPEndPoint(
                _socket.AddressFamily == AddressFamily.InterNetwork
                    ? IPAddress.Any
                    : IPAddress.IPv6Any,
                0);

            while (!cancellationToken.IsCancellationRequested)
            {
                SocketReceiveFromResult result;
                try
                {
                    result = await _socket.ReceiveFromAsync(
                        buffer,
                        SocketFlags.None,
                        sourceEndPoint,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (SocketException ex)
                {
                    if (Volatile.Read(ref _disposed) != 0)
                    {
                        return;
                    }

                    _errorLog(
                        $"UDP relay remote receive failed for {_sessionKey.ClientAddress}:{_sessionKey.ClientPort}: {ex.Message}");
                    _removeSession(_sessionKey, this);
                    return;
                }
                catch (Exception ex)
                {
                    if (Volatile.Read(ref _disposed) != 0)
                    {
                        return;
                    }

                    _errorLog(
                        $"UDP relay remote receive failed for {_sessionKey.ClientAddress}:{_sessionKey.ClientPort}: {ex.Message}");
                    _removeSession(_sessionKey, this);
                    return;
                }

                if (result.RemoteEndPoint is not IPEndPoint remoteEndPoint
                    || remoteEndPoint.Port == 0
                    || remoteEndPoint.AddressFamily != _socket.AddressFamily)
                {
                    continue;
                }

                var responseKey = new UdpRelayKey(
                    _sessionKey.AdapterHandle,
                    _sessionKey.Dot1q,
                    _sessionKey.ClientAddress,
                    _sessionKey.ClientPort,
                    remoteEndPoint.Address,
                    (ushort)remoteEndPoint.Port,
                    _sessionKey.SubInterfaceIndex,
                    _sessionKey.CompartmentId,
                    _sessionKey.WireAddressFamily,
                    _sessionKey.ProcessId);
                var knownTarget = _getTarget(responseKey);
                var responseTarget = knownTarget;
                UdpRelayKey? alternateSourceKey = null;
                var responseOwnerKey = responseKey;
                var responseGeneration = knownTarget is null
                    ? null
                    : _getGeneration(responseKey);
                if (knownTarget is null)
                {
                    var normalizedRemoteAddress = NetworkAddress.Normalize(remoteEndPoint.Address);
                    lock (_sync)
                    {
                        foreach (var key in _outboundFlows.Keys)
                        {
                            if (!key.RemoteAddress.Equals(normalizedRemoteAddress))
                            {
                                continue;
                            }

                            var sameAddressTarget = _getTarget(key);
                            if (sameAddressTarget is null)
                            {
                                continue;
                            }

                            responseTarget = sameAddressTarget with
                            {
                                RemoteAddress = normalizedRemoteAddress,
                                RemotePort = (ushort)remoteEndPoint.Port,
                                CreatedAt = _timeProvider.GetUtcNow()
                            };
                            alternateSourceKey = key;
                            responseOwnerKey = key;
                            responseGeneration = _getGeneration(key);
                            break;
                        }
                    }
                }

                if (responseTarget is null)
                {
                    var now = _timeProvider.GetUtcNow();
                    if (now - _lastUnregisteredResponseLog >= TimeSpan.FromSeconds(5))
                    {
                        _lastUnregisteredResponseLog = now;
                        _errorLog(
                            $"UDP relay dropped response from unregistered endpoint {remoteEndPoint} for {_sessionKey}.");
                    }
                    continue;
                }

                if (responseGeneration is null
                    || _getGeneration(responseOwnerKey) != responseGeneration)
                {
                    continue;
                }

                responseTarget = responseTarget with { CreatedAt = _timeProvider.GetUtcNow() };
                if (knownTarget is not null)
                {
                    _refreshTarget(responseKey);
                }
                else if (alternateSourceKey is { } alternativeKey)
                {
                    _refreshTarget(alternativeKey);
                }

                Interlocked.Add(ref _downBytes, result.ReceivedBytes);
                _trafficCounter.AddUdpDownload(result.ReceivedBytes);

                if (_responseInjector is null)
                {
                    _errorLog(
                        $"UDP relay has no response injector for app={responseTarget.AppLabel} appLocal={responseTarget.ClientEndpoint} from={remoteEndPoint}.");
                    _removeSession(_sessionKey, this);
                    return;
                }

                try
                {
                    if (_responseValidator is not null && !_responseValidator(responseTarget))
                    {
                        _errorLog(
                            $"UDP relay response owner is no longer valid for app={responseTarget.AppLabel} appLocal={responseTarget.ClientEndpoint} from={remoteEndPoint}.");
                        _removeSession(_sessionKey, this);
                        return;
                    }

                    var payload = buffer.AsMemory(0, result.ReceivedBytes).ToArray();
                    if (!_responseInjector(responseTarget, remoteEndPoint, payload))
                    {
                        _errorLog(
                            $"UDP relay response injection failed for app={responseTarget.AppLabel} appLocal={responseTarget.ClientEndpoint} from={remoteEndPoint}.");
                        if (knownTarget is not null
                            && _getGeneration(responseKey) == responseGeneration)
                        {
                            _removeTarget(responseKey);
                        }

                        continue;
                    }
                }
                catch (Exception ex)
                {
                    _errorLog(
                        $"UDP relay response handling failed for app={responseTarget.AppLabel} appLocal={responseTarget.ClientEndpoint} from={remoteEndPoint}: {ex.Message}");
                    if (knownTarget is not null
                        && _getGeneration(responseKey) == responseGeneration)
                    {
                        _removeTarget(responseKey);
                    }

                    continue;
                }

                _packetWakeSignal?.Pulse();
                var receivedAt = Stopwatch.GetTimestamp();
                Interlocked.CompareExchange(ref _firstResponseTimestamp, receivedAt, 0);
                var firstSendAt = Interlocked.Read(ref _firstSendTimestamp);
                var responseLatencyMs = firstSendAt == 0
                    ? 0
                    : Stopwatch.GetElapsedTime(firstSendAt, receivedAt).TotalMilliseconds;
                LogStats("RECV", responseTarget, responseLatencyMs);
            }
        }

        private void LogStats(string direction, DirectRelayTarget target, double latencyMs)
        {
            var now = _timeProvider.GetUtcNow();
            if (_detailLog is null)
            {
                return;
            }

            ref var lastStatsLog = ref (direction == "RECV" ? ref _lastReceiveStatsLog : ref _lastSendStatsLog);
            if (lastStatsLog != default && now - lastStatsLog < TimeSpan.FromSeconds(5))
            {
                return;
            }

            lastStatsLog = now;
            _detailLog(
                $"DIRECT UDP {direction} app={target.AppLabel} appLocal={target.ClientEndpoint} client={_sessionKey.ClientAddress}:{_sessionKey.ClientPort} target={target.RemoteEndpoint} relayProcess={Environment.ProcessId} latencyMs={latencyMs:F2} up={Interlocked.Read(ref _upBytes)} down={Interlocked.Read(ref _downBytes)}");
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            RelayOutboundFlow[] flows;
            lock (_sync)
            {
                _sendQueue.Clear();
                _queuedBytes = 0;
                flows = _outboundFlows.Values.SelectMany(static item => item).ToArray();
                _outboundFlows.Clear();
            }

            var runCts = Interlocked.Exchange(ref _runCts, null);
            runCts?.Cancel();
            runCts?.Dispose();
            _socket.Dispose();
            Pulse(_sendSignal);
            UnregisterOutboundFlows(flows);
        }

        private static void Pulse(SemaphoreSlim semaphore)
        {
            try
            {
                semaphore.Release();
            }
            catch (SemaphoreFullException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private sealed record UdpSendItem(
            UdpRelayKey Key,
            DirectRelayTarget Target,
            long Generation,
            byte[] Payload,
            IPEndPoint RemoteEndPoint,
            long EnqueuedTimestamp);

    }

    private sealed class UdpQueueFullException : InvalidOperationException
    {
        public UdpQueueFullException(string message)
            : base(message)
        {
        }
    }

    [System.Runtime.InteropServices.DllImport("iphlpapi.dll")]
    private static extern uint GetCurrentThreadCompartmentId();

    [System.Runtime.InteropServices.DllImport("iphlpapi.dll")]
    private static extern uint SetCurrentThreadCompartmentId(uint compartmentId);

    private static bool TargetMatches(DirectRelayTarget left, DirectRelayTarget right)
    {
        return left.ProcessId == right.ProcessId
            && left.ProcessName.Equals(right.ProcessName, StringComparison.OrdinalIgnoreCase)
            && left.ProcessPath.Equals(right.ProcessPath, StringComparison.OrdinalIgnoreCase)
            && left.AdapterHandle == right.AdapterHandle
            && left.Dot1q == right.Dot1q
            && Equals(left.ClientAddress, right.ClientAddress)
            && left.ClientPort == right.ClientPort
            && Equals(left.RemoteAddress, right.RemoteAddress)
            && left.RemotePort == right.RemotePort
            && left.WireAddressFamily == right.WireAddressFamily
            && left.ProcessStartTimeUtcTicks == right.ProcessStartTimeUtcTicks;
    }

    private static RelayOutboundFlow ToRelayFlow(UdpRelayKey key)
    {
        return new RelayOutboundFlow(
            key.AdapterHandle,
            PacketView.ProtocolUdp,
            key.ClientAddress,
            key.RemoteAddress,
            key.ClientPort,
            key.RemotePort,
            key.Dot1q,
            key.SubInterfaceIndex,
            key.CompartmentId,
            key.WireAddressFamily,
            key.ProcessId,
            key.FlowId);
    }
}
