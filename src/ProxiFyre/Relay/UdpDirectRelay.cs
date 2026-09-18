using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class UdpDirectRelay : IDisposable
{
    private static readonly TimeSpan TargetTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(30);
    private const int MaxFlows = 4096;

    private readonly ConcurrentDictionary<UdpRelayKey, DirectRelayTarget> _targets = new();
    private readonly ConcurrentDictionary<UdpRelayKey, UdpRelaySocket> _sockets = new();
    private readonly ConcurrentDictionary<UdpRelayKey, long> _targetGenerations = new();
    private readonly ConcurrentDictionary<UdpRelayKey, byte> _relayOutboundFlows = new();
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
        LogDetail("Local direct UDP relay uses packet injection; no local UDP listener is opened.");
    }

    public long Register(UdpRelayKey key, DirectRelayTarget target)
    {
        lock (_socketCreationSync)
        {
            if (!_targets.TryGetValue(key, out var current)
                || !TargetMatches(current, target))
            {
                var generation = Interlocked.Increment(ref _nextGeneration);
                _targetGenerations[key] = generation;
                _targets[key] = target;
                return generation;
            }

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
            key.RemotePort));
    }

    public void Remove(UdpRelayKey key)
    {
        _ = Remove(key, expectedSocket: null);
    }

    private bool Remove(UdpRelayKey key, UdpRelaySocket? expectedSocket)
    {
        UdpRelaySocket? socket;
        var removed = false;
        lock (_socketCreationSync)
        {
            _sockets.TryGetValue(key, out socket);
            if (expectedSocket is not null
                && !ReferenceEquals(socket, expectedSocket))
            {
                return false;
            }

            if (socket is not null)
            {
                _sockets.TryRemove(key, out _);
                removed = true;
            }

            if (_targets.TryRemove(key, out _))
            {
                _targetGenerations.TryRemove(key, out _);
                removed = true;
            }
        }

        socket?.Dispose();
        if (removed)
        {
            _targetRedirectUnregister?.Invoke(ToRelayFlow(key));
        }

        return removed;
    }

    private void RemoveIfNoSocket(UdpRelayKey key, DirectRelayTarget target, long generation)
    {
        var removed = false;
        lock (_socketCreationSync)
        {
            if (_sockets.ContainsKey(key))
            {
                return;
            }

            if (_targets.TryGetValue(key, out var current)
                && TargetMatches(current, target)
                && _targetGenerations.TryGetValue(key, out var currentGeneration)
                && currentGeneration == generation
                && _targets.TryRemove(key, out _))
            {
                _targetGenerations.TryRemove(key, out _);
                removed = true;
            }
        }

        if (removed)
        {
            _targetRedirectUnregister?.Invoke(ToRelayFlow(key));
        }
    }

    public async Task SendToRemoteAsync(
        UdpRelayKey key,
        DirectRelayTarget target,
        ReadOnlyMemory<byte> payload,
        IPAddress remoteAddress,
        ushort remotePort)
    {
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var generation = Register(key, target);
            if (!_sockets.ContainsKey(key) && _sockets.Count >= MaxFlows)
            {
                throw new InvalidOperationException("UDP relay flow limit reached.");
            }

            var relaySocket = GetOrCreateSocket(key, target);
            var remoteEndPoint = NetworkEndpointResolver.CreateRemoteEndPoint(
                target,
                remoteAddress,
                remotePort);
            try
            {
                await relaySocket.SendToRemoteAsync(
                    payload,
                    remoteEndPoint,
                    _cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                _ = Remove(key, relaySocket);
                throw;
            }
        }
        catch (Exception)
        {
            RemoveIfNoSocket(key, target, generation);
            throw;
        }
    }

    private UdpRelaySocket GetOrCreateSocket(UdpRelayKey key, DirectRelayTarget target)
    {
        lock (_socketCreationSync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_sockets.TryGetValue(key, out var existing) && existing.Matches(target))
            {
                return existing;
            }

            if (existing is not null)
            {
                _sockets.TryRemove(key, out _);
                existing.Dispose();
            }

            if (_sockets.Count >= MaxFlows)
            {
                throw new InvalidOperationException("UDP relay flow limit reached.");
            }

            var socket = CreateSocket(key, target);
            _sockets[key] = socket;
            return socket;
        }
    }

    private UdpRelaySocket CreateSocket(UdpRelayKey key, DirectRelayTarget target)
    {
        var remoteEndPoint = NetworkEndpointResolver.CreateRemoteEndPoint(target);
        var socket = CreateUdpSocket(remoteEndPoint.AddressFamily);

        var bindEndPoint = NetworkEndpointResolver.CreateBindEndPoint(target);
        try
        {
            socket.Bind(
                bindEndPoint is not null && bindEndPoint.AddressFamily == remoteEndPoint.AddressFamily
                    ? bindEndPoint
                    : NetworkEndpointResolver.CreateAnyEndPoint(remoteEndPoint.AddressFamily));
        }
        catch (SocketException ex)
        {
            _log($"DIRECT UDP bind failed, retrying any app={target.AppLabel} appLocal={target.ClientEndpoint} target={target.RemoteEndpoint} bind={bindEndPoint}: {ex.Message}");
            socket.Dispose();
            socket = CreateUdpSocket(remoteEndPoint.AddressFamily);
            socket.Bind(NetworkEndpointResolver.CreateAnyEndPoint(remoteEndPoint.AddressFamily));
        }

        var outboundFlows = new List<RelayOutboundFlow>();
        if (socket.LocalEndPoint is IPEndPoint localEndPoint)
        {
            var localPort = (ushort)localEndPoint.Port;
            var localAddress = NetworkAddress.Normalize(localEndPoint.Address);
            var wildcardAddress = localAddress.AddressFamily == AddressFamily.InterNetwork
                ? IPAddress.Any
                : IPAddress.IPv6Any;

            var exact = new RelayOutboundFlow(
                target.AdapterHandle,
                PacketView.ProtocolUdp,
                localAddress,
                remoteEndPoint.Address,
                localPort,
                (ushort)remoteEndPoint.Port,
                target.Dot1q);
            outboundFlows.Add(exact);
            _relayOutboundFlows[new UdpRelayKey(
                target.AdapterHandle,
                target.Dot1q,
                localAddress,
                localPort,
                remoteEndPoint.Address,
                (ushort)remoteEndPoint.Port)] = 0;

            if (!localAddress.Equals(wildcardAddress))
            {
                var wildcard = new RelayOutboundFlow(
                    target.AdapterHandle,
                    PacketView.ProtocolUdp,
                    wildcardAddress,
                    remoteEndPoint.Address,
                    localPort,
                    (ushort)remoteEndPoint.Port,
                    target.Dot1q);
                outboundFlows.Add(wildcard);
                _relayOutboundFlows[new UdpRelayKey(
                    target.AdapterHandle,
                    target.Dot1q,
                    wildcardAddress,
                    localPort,
                    remoteEndPoint.Address,
                    (ushort)remoteEndPoint.Port)] = 0;
            }

            foreach (var flow in outboundFlows)
            {
                _outboundBypassRegister?.Invoke(flow);
            }
        }

        UdpRelaySocket? relaySocket = null;
        relaySocket = new UdpRelaySocket(
            socket,
            key,
            target,
            remoteEndPoint,
            outboundFlows,
            () => Refresh(key),
            key => Remove(key, relaySocket),
            _relayOutboundFlows,
            _outboundBypassUnregister,
            _trafficCounter,
            _packetWakeSignal,
            _responseInjector,
            _responseValidator,
            _errorInjector,
            _detailedLogging ? LogDetail : null,
            _log,
            _timeProvider);
        relaySocket.Start(_cancellationToken);
        return relaySocket;
    }

    private void LogDetail(string message)
    {
        if (_detailedLogging)
        {
            _log(message);
        }
    }

    private static Socket CreateUdpSocket(AddressFamily addressFamily)
    {
        var socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (addressFamily == AddressFamily.InterNetworkV6)
        {
            socket.DualMode = true;
        }

        return socket;
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
        }
    }

    public void Dispose()
    {
        UdpRelaySocket[] sockets;
        lock (_socketCreationSync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            sockets = _sockets.Values.ToArray();
            foreach (var pair in _targets)
            {
                _targetRedirectUnregister?.Invoke(new RelayOutboundFlow(
                    pair.Key.AdapterHandle,
                    PacketView.ProtocolUdp,
                    pair.Key.ClientAddress,
                    pair.Key.RemoteAddress,
                    pair.Key.ClientPort,
                    pair.Key.RemotePort,
                    pair.Key.Dot1q));
            }
            _sockets.Clear();
        }

        foreach (var socket in sockets)
        {
            try
            {
                socket.Dispose();
            }
            catch
            {
            }
        }

        _targets.Clear();
        _targetGenerations.Clear();
        _relayOutboundFlows.Clear();
    }

    private sealed class UdpRelaySocket : IDisposable
    {
        private readonly Socket _socket;
        private readonly UdpRelayKey _key;
        private readonly DirectRelayTarget _target;
        private readonly Action _refreshTarget;
        private readonly Action<UdpRelayKey> _remove;
        private readonly ConcurrentDictionary<UdpRelayKey, byte> _relayOutboundFlows;
        private readonly Action<RelayOutboundFlow>? _outboundBypassUnregister;
        private readonly TrafficCounter _trafficCounter;
        private readonly PacketWakeSignal? _packetWakeSignal;
        private readonly Func<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, bool>? _responseInjector;
        private readonly Func<DirectRelayTarget, bool>? _responseValidator;
        private readonly Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, SocketError>? _errorInjector;
        private readonly Action<string>? _detailLog;
        private readonly Action<string> _errorLog;
        private readonly TimeProvider _timeProvider;
        private readonly IReadOnlyList<RelayOutboundFlow> _outboundFlows;
        private IPEndPoint _remoteEndPoint;
        private DateTimeOffset _lastActivity;
        private DateTimeOffset _lastSendStatsLog;
        private DateTimeOffset _lastReceiveStatsLog;
        private long _upBytes;
        private long _downBytes;
        private byte[] _lastSentPayload = [];
        private bool _sniProbeFinished;
        private bool _disposed;

        public UdpRelaySocket(
            Socket socket,
            UdpRelayKey key,
            DirectRelayTarget target,
            IPEndPoint remoteEndPoint,
            IReadOnlyList<RelayOutboundFlow> outboundFlows,
            Action refreshTarget,
            Action<UdpRelayKey> remove,
            ConcurrentDictionary<UdpRelayKey, byte> relayOutboundFlows,
            Action<RelayOutboundFlow>? outboundBypassUnregister,
            TrafficCounter trafficCounter,
            PacketWakeSignal? packetWakeSignal,
            Func<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, bool>? responseInjector,
            Func<DirectRelayTarget, bool>? responseValidator,
            Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, SocketError>? errorInjector,
            Action<string>? detailLog,
            Action<string> errorLog,
            TimeProvider timeProvider)
        {
            _socket = socket;
            _key = key;
            _target = target;
            _remoteEndPoint = remoteEndPoint;
            _outboundFlows = outboundFlows;
            _refreshTarget = refreshTarget;
            _remove = remove;
            _relayOutboundFlows = relayOutboundFlows;
            _outboundBypassUnregister = outboundBypassUnregister;
            _trafficCounter = trafficCounter;
            _packetWakeSignal = packetWakeSignal;
            _responseInjector = responseInjector;
            _responseValidator = responseValidator;
            _errorInjector = errorInjector;
            _detailLog = detailLog;
            _errorLog = errorLog;
            _timeProvider = timeProvider;
            _lastActivity = _timeProvider.GetUtcNow();
        }

        public bool Matches(DirectRelayTarget target)
        {
            return TargetMatches(target, _target);
        }

        public void Start(CancellationToken cancellationToken)
        {
            _ = Task.Run(() => ReceiveRemoteLoopAsync(cancellationToken), cancellationToken);
        }

        public async Task SendToRemoteAsync(
            ReadOnlyMemory<byte> payload,
            IPEndPoint remoteEndPoint,
            CancellationToken cancellationToken)
        {
            _remoteEndPoint = remoteEndPoint;
            _lastActivity = _timeProvider.GetUtcNow();
            _refreshTarget();
            ProbeClientSni(payload.Span);
            _lastSentPayload = payload.ToArray();
            int sent;
            try
            {
                sent = await _socket.SendToAsync(
                    payload,
                    SocketFlags.None,
                    remoteEndPoint,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                _errorInjector?.Invoke(_target, remoteEndPoint, _lastSentPayload, ex.SocketErrorCode);
                throw;
            }

            if (sent != payload.Length)
            {
                _errorInjector?.Invoke(_target, remoteEndPoint, _lastSentPayload, SocketError.MessageSize);
                throw new IOException($"UDP relay sent {sent} of {payload.Length} bytes.");
            }

            _upBytes += sent;
            _trafficCounter.AddUpload(sent);
            _packetWakeSignal?.Pulse();
            LogStats("SEND");
        }

        private void ProbeClientSni(ReadOnlySpan<byte> payload)
        {
            if (_sniProbeFinished || payload.IsEmpty)
            {
                return;
            }

            _sniProbeFinished = true;
            if (TlsSniParser.TryGetDtlsServerName(payload, out var serverName))
            {
                _errorLog($"APP UDP SNI app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_key.ClientAddress}:{_key.ClientPort} target={_target.RemoteEndpoint} domain={serverName}");
            }
        }

        private async Task ReceiveRemoteLoopAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[65535];
            EndPoint sourceEndPoint = new IPEndPoint(
                _remoteEndPoint.AddressFamily == AddressFamily.InterNetwork
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
                    _errorInjector?.Invoke(_target, _remoteEndPoint, _lastSentPayload, ex.SocketErrorCode);
                    _errorLog($"UDP relay remote receive failed for {_key.ClientAddress}:{_key.ClientPort} -> {_key.RemoteAddress}:{_key.RemotePort}: {ex.Message}");
                    _remove(_key);
                    return;
                }
                catch (Exception ex)
                {
                    _errorLog($"UDP relay remote receive failed for {_key.ClientAddress}:{_key.ClientPort} -> {_key.RemoteAddress}:{_key.RemotePort}: {ex.Message}");
                    _remove(_key);
                    return;
                }

                if (result.RemoteEndPoint is not IPEndPoint remoteEndPoint)
                {
                    continue;
                }

                if (!IsAllowedResponseSource(remoteEndPoint))
                {
                    _detailLog?.Invoke(
                        $"DIRECT UDP ignored response from unexpected endpoint app={_target.AppLabel} expected={_remoteEndPoint} actual={remoteEndPoint}");
                    continue;
                }

                _lastActivity = _timeProvider.GetUtcNow();
                _refreshTarget();
                _remoteEndPoint = remoteEndPoint;
                _downBytes += result.ReceivedBytes;
                _trafficCounter.AddDownload(result.ReceivedBytes);

                if (_responseInjector is null)
                {
                    _errorLog($"UDP relay has no response injector for app={_target.AppLabel} appLocal={_target.ClientEndpoint} from={remoteEndPoint}.");
                    _remove(_key);
                    return;
                }

                try
                {
                    if (_responseValidator is not null && !_responseValidator(_target))
                    {
                        _errorLog($"UDP relay response owner is no longer valid for app={_target.AppLabel} appLocal={_target.ClientEndpoint} from={remoteEndPoint}.");
                        _remove(_key);
                        return;
                    }

                    var payload = buffer.AsMemory(0, result.ReceivedBytes).ToArray();
                    if (!_responseInjector(_target, remoteEndPoint, payload))
                    {
                        _errorLog($"UDP relay response injection failed for app={_target.AppLabel} appLocal={_target.ClientEndpoint} from={remoteEndPoint}.");
                        _remove(_key);
                        return;
                    }
                }
                catch (Exception ex)
                {
                    _errorLog($"UDP relay response handling failed for app={_target.AppLabel} appLocal={_target.ClientEndpoint} from={remoteEndPoint}: {ex.Message}");
                    _remove(_key);
                    return;
                }

                _packetWakeSignal?.Pulse();
                LogStats("RECV");
            }
        }

        private bool IsAllowedResponseSource(IPEndPoint remoteEndPoint)
        {
            if (remoteEndPoint.Equals(_remoteEndPoint))
            {
                return true;
            }

            return remoteEndPoint.Address.Equals(_remoteEndPoint.Address)
                && remoteEndPoint.Port != 0;
        }

        private void LogStats(string direction)
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
            _detailLog($"DIRECT UDP {direction} app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_key.ClientAddress}:{_key.ClientPort} target={_target.RemoteEndpoint} relayProcess={Environment.ProcessId} up={_upBytes} down={_downBytes}");
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            foreach (var flow in _outboundFlows)
            {
                _relayOutboundFlows.TryRemove(
                    new UdpRelayKey(
                        flow.AdapterHandle,
                        _target.Dot1q,
                        flow.LocalAddress,
                        flow.LocalPort,
                        flow.RemoteAddress,
                        flow.RemotePort),
                    out _);
                _outboundBypassUnregister?.Invoke(flow);
            }

            _socket.Dispose();
        }
    }

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
            && left.RemotePort == right.RemotePort;
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
            key.Dot1q);
    }
}
