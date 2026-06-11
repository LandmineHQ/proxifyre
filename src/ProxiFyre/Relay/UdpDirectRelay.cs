using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class UdpDirectRelay : IDisposable
{
    private readonly ConcurrentDictionary<UdpRelayKey, DirectRelayTarget> _targets = new();
    private readonly ConcurrentDictionary<UdpRelayKey, UdpRelaySocket> _sockets = new();
    private readonly ConcurrentDictionary<UdpRelayRouteKey, UdpRelayKey> _routes = new();
    private readonly ConcurrentDictionary<UdpEndpointKey, byte> _relayOutboundEndpoints = new();
    private readonly TimeSpan _targetTtl = TimeSpan.FromMinutes(5);
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TrafficCounter _trafficCounter;
    private readonly PacketWakeSignal? _packetWakeSignal;
    private readonly TimeProvider _timeProvider;
    private Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>>? _responseInjector;
    private Socket? _listener;

    public UdpDirectRelay(Action<string>? log = null, bool detailedLogging = false, TrafficCounter? trafficCounter = null, PacketWakeSignal? packetWakeSignal = null, TimeProvider? timeProvider = null)
    {
        _log = log ?? Console.WriteLine;
        _detailedLogging = detailedLogging;
        _trafficCounter = trafficCounter ?? new TrafficCounter();
        _packetWakeSignal = packetWakeSignal;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public ushort Port { get; private set; }

    public void SetResponseInjector(Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>> responseInjector)
    {
        _responseInjector = responseInjector;
    }

    public void Start(CancellationToken cancellationToken)
    {
        if (_listener is not null)
        {
            return;
        }

        _listener = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        _listener.DualMode = true;
        _listener.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        Port = (ushort)((IPEndPoint)_listener.LocalEndPoint!).Port;

        LogDetail($"Local direct UDP relay listening on [::]:{Port}");
        _ = Task.Run(() => ReceiveLoopAsync(_listener, cancellationToken), cancellationToken);
        _ = Task.Run(() => CleanupLoopAsync(cancellationToken), cancellationToken);
    }

    public void Register(UdpRelayKey key, DirectRelayTarget target)
    {
        _targets[key] = target;
        _routes[new UdpRelayRouteKey(key.ClientPort, key.RemoteAddress, key.RemotePort)] = key;
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

    public bool HasTarget(UdpRelayKey key) => _targets.ContainsKey(key);

    public bool TryGetTarget(UdpRelayKey key, out DirectRelayTarget target)
    {
        return _targets.TryGetValue(key, out target!);
    }

    public bool IsRelayOutboundEndpoint(UdpEndpointKey endpoint)
    {
        return _relayOutboundEndpoints.ContainsKey(endpoint);
    }

    public void Remove(UdpRelayKey key)
    {
        _targets.TryRemove(key, out _);
        _routes.TryRemove(new UdpRelayRouteKey(key.ClientPort, key.RemoteAddress, key.RemotePort), out _);
        if (_sockets.TryRemove(key, out var socket))
        {
            socket.Dispose();
        }
    }

    private async Task ReceiveLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        var buffer = new byte[65535];

        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await listener.ReceiveFromAsync(
                    buffer,
                    SocketFlags.None,
                    new IPEndPoint(IPAddress.IPv6Any, 0),
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
            catch (Exception ex)
            {
                _log($"UDP relay receive failed: {ex.Message}");
                continue;
            }

            if (received.RemoteEndPoint is not IPEndPoint clientEndPoint)
            {
                continue;
            }

            var syntheticSourceAddress = NetworkAddress.Normalize(clientEndPoint.Address);
            if (!TryParseHeader(buffer.AsSpan(0, received.ReceivedBytes), syntheticSourceAddress.AddressFamily, out var header, out var payloadOffset))
            {
                continue;
            }

            var routeKey = new UdpRelayRouteKey((ushort)clientEndPoint.Port, header.RemoteAddress, header.RemotePort);
            if (!_routes.TryGetValue(routeKey, out var key))
            {
                key = new UdpRelayKey(syntheticSourceAddress, (ushort)clientEndPoint.Port, header.RemoteAddress, header.RemotePort);
            }

            if (!_targets.TryGetValue(key, out var target))
            {
                target = new DirectRelayTarget(header.RemoteAddress, header.RemotePort, _timeProvider.GetUtcNow());
                Register(key, target);
            }
            else
            {
                Refresh(key);
            }

            var actualClientEndPoint = CreateClientEndPoint(key, target);
            var relaySocket = _sockets.GetOrAdd(key, _ => CreateSocket(listener, key, target, actualClientEndPoint, cancellationToken));
            relaySocket.Refresh();
            try
            {
                await relaySocket.SendToRemoteAsync(buffer.AsMemory(payloadOffset, received.ReceivedBytes - payloadOffset), header.RemoteAddress, header.RemotePort, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log($"DIRECT UDP send failed app={target.AppLabel} appLocal={target.ClientEndpoint} client={key.ClientAddress}:{key.ClientPort} syntheticSource={syntheticSourceAddress}:{clientEndPoint.Port} target={target.RemoteEndpoint}: {ex.Message}");
                Remove(key);
            }
        }
    }

    private static IPEndPoint CreateClientEndPoint(UdpRelayKey key, DirectRelayTarget target)
    {
        var clientAddress = target.ClientAddress is null
            ? key.ClientAddress
            : NetworkAddress.Normalize(target.ClientAddress);
        return new IPEndPoint(clientAddress, key.ClientPort);
    }

    private UdpRelaySocket CreateSocket(Socket listener, UdpRelayKey key, DirectRelayTarget target, IPEndPoint clientEndPoint, CancellationToken cancellationToken)
    {
        var remoteEndPoint = NetworkEndpointResolver.CreateRemoteEndPoint(target);
        var socket = CreateUdpSocket(remoteEndPoint.AddressFamily);

        var bindEndPoint = NetworkEndpointResolver.CreateBindEndPoint(target);
        try
        {
            socket.Bind(bindEndPoint is not null && bindEndPoint.AddressFamily == remoteEndPoint.AddressFamily
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

        if (socket.LocalEndPoint is IPEndPoint localEndPoint)
        {
            _relayOutboundEndpoints[new UdpEndpointKey(localEndPoint.Address, (ushort)localEndPoint.Port)] = 0;
        }

        var relaySocket = new UdpRelaySocket(socket, key, target, clientEndPoint, Remove, _relayOutboundEndpoints, _trafficCounter, _packetWakeSignal, _responseInjector, _detailedLogging ? LogDetail : null, _log, _timeProvider);
        relaySocket.Start(cancellationToken);
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

    private static bool TryParseHeader(ReadOnlySpan<byte> datagram, AddressFamily fallbackFamily, out UdpRelayHeader header, out int payloadOffset)
    {
        header = default;
        payloadOffset = 0;

        if (datagram.Length < 4 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0)
        {
            return false;
        }

        var addressType = datagram[3];
        if (addressType == 1)
        {
            if (datagram.Length < 10)
            {
                return false;
            }

            header = new UdpRelayHeader(new IPAddress(datagram.Slice(4, 4)), BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(8, 2)));
            payloadOffset = 10;
            return true;
        }

        if (addressType == 4)
        {
            if (datagram.Length < 22)
            {
                return false;
            }

            header = new UdpRelayHeader(new IPAddress(datagram.Slice(4, 16)), BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(20, 2)));
            payloadOffset = 22;
            return true;
        }

        if (fallbackFamily == AddressFamily.InterNetwork && datagram.Length >= 10)
        {
            header = new UdpRelayHeader(new IPAddress(datagram.Slice(4, 4)), BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(8, 2)));
            payloadOffset = 10;
            return true;
        }

        return false;
    }

    private async Task CleanupLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30), _timeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            var now = _timeProvider.GetUtcNow();
            foreach (var pair in _targets)
            {
                if (now - pair.Value.CreatedAt > _targetTtl)
                {
                    Remove(pair.Key);
                }
            }
        }
    }

    public void Dispose()
    {
        _listener?.Dispose();
        foreach (var socket in _sockets.Values)
        {
            socket.Dispose();
        }

        _sockets.Clear();
        _targets.Clear();
        _relayOutboundEndpoints.Clear();
    }

    private readonly record struct UdpRelayHeader(IPAddress RemoteAddress, ushort RemotePort);

    private readonly record struct UdpRelayRouteKey
    {
        public UdpRelayRouteKey(ushort clientPort, IPAddress remoteAddress, ushort remotePort)
        {
            ClientPort = clientPort;
            RemoteAddress = NetworkAddress.Normalize(remoteAddress);
            RemotePort = remotePort;
        }

        public ushort ClientPort { get; }

        public IPAddress RemoteAddress { get; }

        public ushort RemotePort { get; }
    }

    private sealed class UdpRelaySocket : IDisposable
    {
        private readonly Socket _remoteSocket;
        private readonly UdpRelayKey _key;
        private readonly DirectRelayTarget _target;
        private readonly IPEndPoint _clientEndPoint;
        private readonly Action<UdpRelayKey> _remove;
        private readonly ConcurrentDictionary<UdpEndpointKey, byte> _relayOutboundEndpoints;
        private readonly TrafficCounter _trafficCounter;
        private readonly PacketWakeSignal? _packetWakeSignal;
        private readonly Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>>? _responseInjector;
        private readonly Action<string>? _detailLog;
        private readonly Action<string> _errorLog;
        private readonly TimeProvider _timeProvider;
        private DateTimeOffset _lastActivity;
        private DateTimeOffset _lastSendStatsLog;
        private DateTimeOffset _lastReceiveStatsLog;
        private long _upBytes;
        private long _downBytes;

        public UdpRelaySocket(Socket remoteSocket, UdpRelayKey key, DirectRelayTarget target, IPEndPoint clientEndPoint, Action<UdpRelayKey> remove, ConcurrentDictionary<UdpEndpointKey, byte> relayOutboundEndpoints, TrafficCounter trafficCounter, PacketWakeSignal? packetWakeSignal, Action<DirectRelayTarget, IPEndPoint, ReadOnlyMemory<byte>>? responseInjector, Action<string>? detailLog, Action<string> errorLog, TimeProvider timeProvider)
        {
            _remoteSocket = remoteSocket;
            _key = key;
            _target = target;
            _clientEndPoint = clientEndPoint;
            _remove = remove;
            _relayOutboundEndpoints = relayOutboundEndpoints;
            _trafficCounter = trafficCounter;
            _packetWakeSignal = packetWakeSignal;
            _responseInjector = responseInjector;
            _detailLog = detailLog;
            _errorLog = errorLog;
            _timeProvider = timeProvider;
            _lastActivity = _timeProvider.GetUtcNow();
        }

        public void Start(CancellationToken cancellationToken)
        {
            _ = Task.Run(() => ReceiveRemoteLoopAsync(cancellationToken), cancellationToken);
        }

        public void Refresh()
        {
            _lastActivity = _timeProvider.GetUtcNow();
        }

        public async Task SendToRemoteAsync(ReadOnlyMemory<byte> payload, IPAddress remoteAddress, ushort remotePort, CancellationToken cancellationToken)
        {
            Refresh();
            var remoteEndPoint = NetworkEndpointResolver.CreateRemoteEndPoint(_target, remoteAddress, remotePort);
            await _remoteSocket.SendToAsync(payload, SocketFlags.None, remoteEndPoint, cancellationToken).ConfigureAwait(false);
            _upBytes += payload.Length;
            _trafficCounter.AddUpload(payload.Length);
            _packetWakeSignal?.Pulse();
            LogStats("SEND");
        }

        private async Task ReceiveRemoteLoopAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[65535];

            while (!cancellationToken.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await _remoteSocket.ReceiveFromAsync(
                        buffer,
                        SocketFlags.None,
                    NetworkEndpointResolver.CreateAnyEndPoint(_remoteSocket.AddressFamily),
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
            catch (Exception ex)
            {
                    _errorLog($"UDP relay remote receive failed for {_key.ClientAddress}:{_key.ClientPort} -> {_key.RemoteAddress}:{_key.RemotePort}: {ex.Message}");
                    _remove(_key);
                    return;
                }

                if (received.RemoteEndPoint is not IPEndPoint remoteEndPoint)
                {
                    continue;
                }

                Refresh();
                _downBytes += received.ReceivedBytes;
                _trafficCounter.AddDownload(received.ReceivedBytes);
                if (_responseInjector is null)
                {
                    _errorLog($"UDP relay has no response injector for app={_target.AppLabel} appLocal={_target.ClientEndpoint} from={remoteEndPoint}.");
                    _remove(_key);
                    return;
                }

                var payload = buffer.AsMemory(0, received.ReceivedBytes).ToArray();
                _responseInjector(_target, remoteEndPoint, payload);
                _packetWakeSignal?.Pulse();
                LogStats("RECV");

                if (_timeProvider.GetUtcNow() - _lastActivity > TimeSpan.FromMinutes(5))
                {
                    _remove(_key);
                    return;
                }
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
            if (_remoteSocket.LocalEndPoint is IPEndPoint localEndPoint)
            {
                _relayOutboundEndpoints.TryRemove(new UdpEndpointKey(localEndPoint.Address, (ushort)localEndPoint.Port), out _);
            }

            _remoteSocket.Dispose();
        }
    }
}
