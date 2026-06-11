using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class TcpDirectRelay : IDisposable
{
    private const uint InitialRemoteSequence = 0x4A17C001;
    private const int MaxTcpPayload = 1400;
    private readonly ConcurrentDictionary<TcpClientKey, TcpRelayConnection> _connections = new();
    private readonly ConcurrentDictionary<TcpRelayKey, TcpClientKey> _clientsByFlow = new();
    private readonly ConcurrentDictionary<TcpRelayKey, byte> _relayOutboundFlows = new();
    private readonly TimeSpan _targetTtl = TimeSpan.FromMinutes(5);
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TrafficCounter _trafficCounter;
    private readonly PacketWakeSignal? _packetWakeSignal;
    private readonly TimeProvider _timeProvider;
    private Action<DirectRelayTarget, uint, uint, byte, ushort, ReadOnlyMemory<byte>>? _packetInjector;

    public TcpDirectRelay(Action<string>? log = null, bool detailedLogging = false, TrafficCounter? trafficCounter = null, PacketWakeSignal? packetWakeSignal = null, TimeProvider? timeProvider = null)
    {
        _log = log ?? Console.WriteLine;
        _detailedLogging = detailedLogging;
        _trafficCounter = trafficCounter ?? new TrafficCounter();
        _packetWakeSignal = packetWakeSignal;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public void SetPacketInjector(Action<DirectRelayTarget, uint, uint, byte, ushort, ReadOnlyMemory<byte>> packetInjector)
    {
        _packetInjector = packetInjector;
    }

    public void Start(CancellationToken cancellationToken)
    {
        LogDetail("Local direct TCP relay uses packet injection; no local TCP listener is opened.");
        _ = Task.Run(() => CleanupLoopAsync(cancellationToken), cancellationToken);
    }

    public TcpRelayConnection RegisterSyn(TcpRelayKey flowKey, TcpClientKey clientKey, DirectRelayTarget target, uint clientSequenceNumber, ushort clientWindow, CancellationToken cancellationToken)
    {
        var connection = new TcpRelayConnection(
            flowKey,
            clientKey,
            target,
            clientSequenceNumber + 1,
            InitialRemoteSequence,
            clientWindow,
            _trafficCounter,
            _packetWakeSignal,
            _packetInjector,
            TrackOutboundFlow,
            UntrackOutboundFlow,
            Remove,
            _detailedLogging ? LogDetail : null,
            _log,
            _timeProvider);

        _connections[clientKey] = connection;
        _clientsByFlow[flowKey] = clientKey;
        _ = connection.ConnectAsync(cancellationToken);
        return connection;
    }

    public bool TryGetConnection(TcpRelayKey flowKey, out TcpRelayConnection connection)
    {
        connection = default!;
        return _clientsByFlow.TryGetValue(flowKey, out var clientKey)
            && _connections.TryGetValue(clientKey, out connection!);
    }

    public bool TryGetConnection(TcpClientKey clientKey, out TcpRelayConnection connection)
    {
        return _connections.TryGetValue(clientKey, out connection!);
    }

    public bool IsRelayOutboundFlow(TcpRelayKey flowKey)
    {
        return _relayOutboundFlows.ContainsKey(flowKey);
    }

    public void TrackOutboundFlow(TcpRelayKey flowKey)
    {
        _relayOutboundFlows[flowKey] = 0;
    }

    public void UntrackOutboundFlow(TcpRelayKey flowKey)
    {
        _relayOutboundFlows.TryRemove(flowKey, out _);
    }

    public void Remove(TcpClientKey clientKey)
    {
        if (_connections.TryRemove(clientKey, out var connection))
        {
            _clientsByFlow.TryRemove(connection.FlowKey, out _);
            connection.Dispose();
        }
    }

    private void LogDetail(string message)
    {
        if (_detailedLogging)
        {
            _log(message);
        }
    }

    private async Task CleanupLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30), _timeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            CleanupExpiredConnections();
        }
    }

    private void CleanupExpiredConnections()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var pair in _connections)
        {
            if (now - pair.Value.LastActivity > _targetTtl)
            {
                Remove(pair.Key);
            }
        }
    }

    public void Dispose()
    {
        foreach (var connection in _connections.Values)
        {
            connection.Dispose();
        }

        _connections.Clear();
        _clientsByFlow.Clear();
        _relayOutboundFlows.Clear();
    }

    internal sealed class TcpRelayConnection : IDisposable
    {
        private readonly object _sync = new();
        private readonly TcpRelayKey _flowKey;
        private readonly TcpClientKey _clientKey;
        private readonly DirectRelayTarget _target;
        private readonly TrafficCounter _trafficCounter;
        private readonly PacketWakeSignal? _packetWakeSignal;
        private readonly Action<DirectRelayTarget, uint, uint, byte, ushort, ReadOnlyMemory<byte>>? _packetInjector;
        private readonly Action<TcpRelayKey> _trackOutboundFlow;
        private readonly Action<TcpRelayKey> _untrackOutboundFlow;
        private readonly Action<TcpClientKey> _remove;
        private readonly Action<string>? _detailLog;
        private readonly Action<string> _errorLog;
        private readonly TimeProvider _timeProvider;
        private readonly uint _remoteInitialSequence;
        private TcpClient? _client;
        private NetworkStream? _stream;
        private TcpRelayKey? _outboundFlowKey;
        private Task? _receiveTask;
        private Queue<byte[]>? _pendingPayloads;
        private bool _connected;
        private bool _closed;
        private uint _nextRemoteSequence;
        private uint _nextClientSequence;
        private ushort _clientWindow;
        private DateTimeOffset _lastUpLog;
        private DateTimeOffset _lastDownLog;
        private long _upBytes;
        private long _downBytes;

        public TcpRelayConnection(
            TcpRelayKey flowKey,
            TcpClientKey clientKey,
            DirectRelayTarget target,
            uint nextClientSequence,
            uint remoteInitialSequence,
            ushort clientWindow,
            TrafficCounter trafficCounter,
            PacketWakeSignal? packetWakeSignal,
            Action<DirectRelayTarget, uint, uint, byte, ushort, ReadOnlyMemory<byte>>? packetInjector,
            Action<TcpRelayKey> trackOutboundFlow,
            Action<TcpRelayKey> untrackOutboundFlow,
            Action<TcpClientKey> remove,
            Action<string>? detailLog,
            Action<string> errorLog,
            TimeProvider timeProvider)
        {
            _flowKey = flowKey;
            _clientKey = clientKey;
            _target = target;
            _trafficCounter = trafficCounter;
            _packetWakeSignal = packetWakeSignal;
            _packetInjector = packetInjector;
            _trackOutboundFlow = trackOutboundFlow;
            _untrackOutboundFlow = untrackOutboundFlow;
            _remove = remove;
            _detailLog = detailLog;
            _errorLog = errorLog;
            _timeProvider = timeProvider;
            _remoteInitialSequence = remoteInitialSequence;
            _nextRemoteSequence = remoteInitialSequence + 1;
            _nextClientSequence = nextClientSequence;
            _clientWindow = clientWindow;
            LastActivity = _timeProvider.GetUtcNow();
        }

        public TcpRelayKey FlowKey => _flowKey;

        public DateTimeOffset LastActivity { get; private set; }

        public bool IsConnected
        {
            get
            {
                lock (_sync)
                {
                    return _connected;
                }
            }
        }

        public void AcceptSyn()
        {
            Inject(_remoteInitialSequence, _nextClientSequence, PacketView.TcpFlagSyn | PacketView.TcpFlagAck, ReadOnlyMemory<byte>.Empty);
        }

        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            var remoteEndPoint = NetworkEndpointResolver.CreateRemoteEndPoint(_target);
            TcpClient? client = null;
            TcpRelayKey? outboundFlowKey = null;
            try
            {
                client = CreateRelayTcpClient(remoteEndPoint.AddressFamily);
                var bindEndPoint = NetworkEndpointResolver.CreateBindEndPoint(_target);
                try
                {
                    client.Client.Bind(bindEndPoint is not null && bindEndPoint.AddressFamily == remoteEndPoint.AddressFamily
                        ? bindEndPoint
                        : NetworkEndpointResolver.CreateAnyEndPoint(remoteEndPoint.AddressFamily));
                }
                catch (SocketException ex)
                {
                    _errorLog($"DIRECT TCP bind failed, retrying any app={_target.AppLabel} appLocal={_target.ClientEndpoint} target={_target.RemoteEndpoint} bind={bindEndPoint}: {ex.Message}");
                    client.Dispose();
                    client = CreateRelayTcpClient(remoteEndPoint.AddressFamily);
                    client.Client.Bind(NetworkEndpointResolver.CreateAnyEndPoint(remoteEndPoint.AddressFamily));
                }

                if (client.Client.LocalEndPoint is IPEndPoint localEndPoint)
                {
                    outboundFlowKey = new TcpRelayKey(remoteEndPoint.Address, (ushort)localEndPoint.Port, (ushort)remoteEndPoint.Port);
                    _trackOutboundFlow(outboundFlowKey.Value);
                    _outboundFlowKey = outboundFlowKey;
                }

                await client.ConnectAsync(remoteEndPoint, cancellationToken).ConfigureAwait(false);
                lock (_sync)
                {
                    if (_closed)
                    {
                        client.Dispose();
                        ClearOutboundFlow();
                        return;
                    }

                    _client = client;
                    _stream = client.GetStream();
                    _connected = true;
                    LastActivity = _timeProvider.GetUtcNow();
                }

                _detailLog?.Invoke($"DIRECT TCP CONNECT app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_clientKey.ClientAddress}:{_clientKey.ClientPort} target={_target.RemoteEndpoint} relayProcess={Environment.ProcessId} relayLocal={client.Client.LocalEndPoint}");
                AcceptSyn();
                var flushedPayloadBytes = await FlushPendingPayloadsAsync(_stream, cancellationToken).ConfigureAwait(false);
                if (flushedPayloadBytes > 0)
                {
                    Inject(_nextRemoteSequence, _nextClientSequence, PacketView.TcpFlagAck, ReadOnlyMemory<byte>.Empty);
                }

                _receiveTask = Task.Run(() => ReceiveRemoteLoopAsync(cancellationToken), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                if (outboundFlowKey is { } flowKey)
                {
                    _untrackOutboundFlow(flowKey);
                }

                client?.Dispose();
                _remove(_clientKey);
            }
            catch (Exception ex)
            {
                if (outboundFlowKey is { } flowKey)
                {
                    _untrackOutboundFlow(flowKey);
                }

                client?.Dispose();
                _errorLog($"DIRECT TCP connect failed app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_clientKey.ClientAddress}:{_clientKey.ClientPort} target={_target.RemoteEndpoint} relayProcess={Environment.ProcessId}: {ex.Message}");
                CloseNetwork();
            }
        }

        private static TcpClient CreateRelayTcpClient(AddressFamily addressFamily)
        {
            return new TcpClient(addressFamily)
            {
                NoDelay = true
            };
        }

        public async Task SendClientPayloadAsync(uint sequenceNumber, uint acknowledgmentNumber, ushort window, ReadOnlyMemory<byte> payload, bool fin, bool rst, CancellationToken cancellationToken)
        {
            NetworkStream? stream;
            bool connected;
            ReadOnlyMemory<byte> acceptedPayload = ReadOnlyMemory<byte>.Empty;
            lock (_sync)
            {
                if (_closed)
                {
                    return;
                }

                _clientWindow = window;
                LastActivity = _timeProvider.GetUtcNow();
                if (payload.Length > 0)
                {
                    var payloadEnd = sequenceNumber + (uint)payload.Length;
                    if (payloadEnd > _nextClientSequence)
                    {
                        if (sequenceNumber < _nextClientSequence)
                        {
                            acceptedPayload = payload[(int)(_nextClientSequence - sequenceNumber)..];
                        }
                        else
                        {
                            acceptedPayload = payload;
                        }

                        _nextClientSequence = payloadEnd;
                    }
                }

                if (fin)
                {
                    var finSequence = sequenceNumber + (uint)payload.Length + 1;
                    if (finSequence > _nextClientSequence)
                    {
                        _nextClientSequence = finSequence;
                    }
                }

                stream = _stream;
                connected = _connected;
            }

            if (rst)
            {
                Close();
                return;
            }

            if (stream is null || !connected)
            {
                if (acceptedPayload.Length > 0)
                {
                    lock (_sync)
                    {
                        _pendingPayloads ??= new Queue<byte[]>();
                        _pendingPayloads.Enqueue(acceptedPayload.ToArray());
                    }
                }

                return;
            }

            try
            {
                if (acceptedPayload.Length > 0)
                {
                    await stream.WriteAsync(acceptedPayload, cancellationToken).ConfigureAwait(false);
                    _upBytes += acceptedPayload.Length;
                    _trafficCounter.AddUpload(acceptedPayload.Length);
                    _packetWakeSignal?.Pulse();
                    LogStats("SEND");
                }

                if (acceptedPayload.Length > 0 || fin)
                {
                    Inject(_nextRemoteSequence, _nextClientSequence, PacketView.TcpFlagAck, ReadOnlyMemory<byte>.Empty);
                }

                if (fin)
                {
                    try
                    {
                        _client?.Client.Shutdown(SocketShutdown.Send);
                    }
                    catch
                    {
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _errorLog($"DIRECT TCP send failed app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_clientKey.ClientAddress}:{_clientKey.ClientPort} target={_target.RemoteEndpoint}: {ex.Message}");
                Close();
            }
        }

        private async Task ReceiveRemoteLoopAsync(CancellationToken cancellationToken)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(MaxTcpPayload);
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    NetworkStream? stream;
                    lock (_sync)
                    {
                        if (_closed)
                        {
                            return;
                        }

                        stream = _stream;
                    }

                    if (stream is null)
                    {
                        return;
                    }

                    var read = await stream.ReadAsync(buffer.AsMemory(0, MaxTcpPayload), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        uint seq;
                        uint ack;
                        lock (_sync)
                        {
                            if (_closed)
                            {
                                return;
                            }

                            seq = _nextRemoteSequence;
                            ack = _nextClientSequence;
                            _nextRemoteSequence++;
                            _closed = true;
                            LastActivity = _timeProvider.GetUtcNow();
                        }

                        Inject(seq, ack, PacketView.TcpFlagFin | PacketView.TcpFlagAck, ReadOnlyMemory<byte>.Empty);
                        CloseNetwork();
                        return;
                    }

                    byte[] payload = buffer.AsSpan(0, read).ToArray();
                    uint packetSequence;
                    uint packetAck;
                    lock (_sync)
                    {
                        if (_closed)
                        {
                            return;
                        }

                        packetSequence = _nextRemoteSequence;
                        packetAck = _nextClientSequence;
                        _nextRemoteSequence += (uint)read;
                        LastActivity = _timeProvider.GetUtcNow();
                    }

                    _downBytes += read;
                    _trafficCounter.AddDownload(read);
                    Inject(packetSequence, packetAck, PacketView.TcpFlagPsh | PacketView.TcpFlagAck, payload);
                    _packetWakeSignal?.Pulse();
                    LogStats("RECV");
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                _errorLog($"DIRECT TCP remote receive failed for {_clientKey.ClientAddress}:{_clientKey.ClientPort} -> {_target.RemoteAddress}:{_target.RemotePort}: {ex.Message}");
                Close();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private async Task<int> FlushPendingPayloadsAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var flushedBytes = 0;
            while (true)
            {
                byte[]? payload;
                lock (_sync)
                {
                    payload = _pendingPayloads is { Count: > 0 }
                        ? _pendingPayloads.Dequeue()
                        : null;
                }

                if (payload is null)
                {
                    return flushedBytes;
                }

                await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
                flushedBytes += payload.Length;
                _upBytes += payload.Length;
                _trafficCounter.AddUpload(payload.Length);
                _packetWakeSignal?.Pulse();
                LogStats("SEND");
            }
        }

        private void Inject(uint sequenceNumber, uint acknowledgmentNumber, byte flags, ReadOnlyMemory<byte> payload)
        {
            _packetInjector?.Invoke(_target, sequenceNumber, acknowledgmentNumber, flags, _clientWindow, payload);
        }

        private void Close()
        {
            lock (_sync)
            {
                _closed = true;
            }

            _remove(_clientKey);
        }

        private void ClearOutboundFlow()
        {
            if (_outboundFlowKey is { } outboundFlowKey)
            {
                _untrackOutboundFlow(outboundFlowKey);
                _outboundFlowKey = null;
            }
        }

        private void CloseNetwork()
        {
            ClearOutboundFlow();

            _stream?.Dispose();
            _client?.Dispose();
            _stream = null;
            _client = null;
            _connected = false;
        }

        private void LogStats(string direction)
        {
            var now = _timeProvider.GetUtcNow();
            if (_detailLog is null)
            {
                return;
            }

            ref var lastStatsLog = ref (direction == "RECV" ? ref _lastDownLog : ref _lastUpLog);
            if (lastStatsLog != default && now - lastStatsLog < TimeSpan.FromSeconds(5))
            {
                return;
            }

            lastStatsLog = now;
            _detailLog($"DIRECT TCP {direction} app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_clientKey.ClientAddress}:{_clientKey.ClientPort} target={_target.RemoteEndpoint} relayProcess={Environment.ProcessId} up={_upBytes} down={_downBytes}");
        }

        public void Dispose()
        {
            lock (_sync)
            {
                _closed = true;
            }

            CloseNetwork();
        }
    }
}
