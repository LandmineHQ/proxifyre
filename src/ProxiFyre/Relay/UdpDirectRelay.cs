using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class UdpDirectRelay : IDisposable
{
    private static readonly TimeSpan TargetTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<UdpRelayKey, DirectRelayTarget> _targets = new();
    private readonly ConcurrentDictionary<UdpRelayKey, Lazy<UdpRelaySocket>> _sockets = new();
    private readonly ConcurrentDictionary<UdpRelayKey, byte> _relayOutboundFlows = new();
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TrafficCounter _trafficCounter;
    private readonly PacketWakeSignal? _packetWakeSignal;
    private readonly TimeProvider _timeProvider;
    private Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>>? _responseInjector;
    private Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, SocketError>? _errorInjector;
    private Action<RelayOutboundFlow>? _outboundBypassRegister;
    private Action<RelayOutboundFlow>? _outboundBypassUnregister;
    private CancellationToken _cancellationToken;

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

    public void SetResponseInjector(Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>> responseInjector)
    {
        _responseInjector = responseInjector;
    }

    public void SetErrorInjector(
        Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>, SocketError> errorInjector)
    {
        _errorInjector = errorInjector;
    }

    public void SetOutboundBypass(
        Action<RelayOutboundFlow> register,
        Action<RelayOutboundFlow> unregister)
    {
        _outboundBypassRegister = register;
        _outboundBypassUnregister = unregister;
    }

    public void Start(CancellationToken cancellationToken)
    {
        _cancellationToken = cancellationToken;
        _ = Task.Run(() => CleanupLoopAsync(cancellationToken), cancellationToken);
        LogDetail("Local direct UDP relay uses packet injection; no local UDP listener is opened.");
    }

    public void Register(UdpRelayKey key, DirectRelayTarget target)
    {
        _targets[key] = target;
    }

    public bool Refresh(UdpRelayKey key)
    {
        if (!_targets.TryGetValue(key, out var target))
        {
            return false;
        }

        _targets[key] = target with { CreatedAt = _timeProvider.GetUtcNow() };
        return true;
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
            wildcardAddress,
            key.ClientPort,
            key.RemoteAddress,
            key.RemotePort));
    }

    public void Remove(UdpRelayKey key)
    {
        _targets.TryRemove(key, out _);
        if (_sockets.TryRemove(key, out var socket) && socket.IsValueCreated)
        {
            socket.Value.Dispose();
        }
    }

    public async Task SendToRemoteAsync(
        UdpRelayKey key,
        DirectRelayTarget target,
        ReadOnlyMemory<byte> payload,
        IPAddress remoteAddress,
        ushort remotePort)
    {
        Register(key, target);
        var relaySocket = GetOrCreateSocket(key, target);
        await relaySocket.SendToRemoteAsync(
            payload,
            new IPEndPoint(remoteAddress, remotePort),
            _cancellationToken).ConfigureAwait(false);
    }

    private UdpRelaySocket GetOrCreateSocket(UdpRelayKey key, DirectRelayTarget target)
    {
        while (true)
        {
            var lazy = _sockets.GetOrAdd(
                key,
                _ => new Lazy<UdpRelaySocket>(
                    () => CreateSocket(key, target),
                    LazyThreadSafetyMode.ExecutionAndPublication));
            UdpRelaySocket socket;
            try
            {
                socket = lazy.Value;
            }
            catch
            {
                _sockets.TryRemove(key, out _);
                throw;
            }

            if (socket.Matches(target))
            {
                return socket;
            }

            Remove(key);
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
                (ushort)remoteEndPoint.Port);
            outboundFlows.Add(exact);
            _relayOutboundFlows[new UdpRelayKey(
                target.AdapterHandle,
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
                    (ushort)remoteEndPoint.Port);
                outboundFlows.Add(wildcard);
                _relayOutboundFlows[new UdpRelayKey(
                    target.AdapterHandle,
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

        var relaySocket = new UdpRelaySocket(
            socket,
            key,
            target,
            remoteEndPoint,
            outboundFlows,
            () => Refresh(key),
            Remove,
            _relayOutboundFlows,
            _outboundBypassUnregister,
            _trafficCounter,
            _packetWakeSignal,
            _responseInjector,
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
        foreach (var socket in _sockets.Values)
        {
            try
            {
                if (socket.IsValueCreated)
                {
                    socket.Value.Dispose();
                }
            }
            catch
            {
            }
        }

        _sockets.Clear();
        _targets.Clear();
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
        private readonly Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>>? _responseInjector;
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
            Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>>? responseInjector,
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
            _errorInjector = errorInjector;
            _detailLog = detailLog;
            _errorLog = errorLog;
            _timeProvider = timeProvider;
            _lastActivity = _timeProvider.GetUtcNow();
        }

        public bool Matches(DirectRelayTarget target)
        {
            return target.ProcessId == _target.ProcessId
                && target.ProcessName.Equals(_target.ProcessName, StringComparison.OrdinalIgnoreCase)
                && target.ProcessPath.Equals(_target.ProcessPath, StringComparison.OrdinalIgnoreCase)
                && target.AdapterHandle == _target.AdapterHandle;
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

                var payload = buffer.AsMemory(0, result.ReceivedBytes).ToArray();
                _responseInjector(_target, remoteEndPoint, payload);
                _packetWakeSignal?.Pulse();
                LogStats("RECV");
            }
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
}
