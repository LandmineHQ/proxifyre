using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace ProxiFyre;

internal readonly record struct TcpSegment(
    uint SequenceNumber,
    uint AcknowledgmentNumber,
    byte Flags,
    ushort Window,
    ushort UrgentPointer,
    ReadOnlyMemory<byte> Payload,
    ReadOnlyMemory<byte> Options)
{
    public int SequenceLength => Payload.Length
        + (((Flags & PacketView.TcpFlagSyn) != 0) ? 1 : 0)
        + (((Flags & PacketView.TcpFlagFin) != 0) ? 1 : 0);
}

internal sealed class TcpDirectRelay : IDisposable
{
    private const int MaxTcpPayload = 1400;
    private const int MaxBufferedClientBytes = ushort.MaxValue;
    private const int MaxOutOfOrderBytes = ushort.MaxValue;
    private static readonly TimeSpan InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(600);
    private static readonly TimeSpan MaxRetransmissionTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan MaintenanceInterval = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan BypassFlowTtl = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<TcpRelayKey, TcpRelayConnection> _connections = new();
    private readonly ConcurrentDictionary<TcpRelayKey, byte> _relayOutboundFlows = new();
    private readonly ConcurrentDictionary<TcpRelayKey, DateTimeOffset> _bypassedFlows = new();
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TrafficCounter _trafficCounter;
    private readonly PacketWakeSignal? _packetWakeSignal;
    private readonly TimeProvider _timeProvider;
    private CancellationToken _cancellationToken;
    private Task? _maintenanceTask;
    private Func<DirectRelayTarget, TcpSegment, bool>? _packetInjector;
    private Action<RelayOutboundFlow>? _outboundBypassRegister;
    private Action<RelayOutboundFlow>? _outboundBypassUnregister;
    private Action<RelayOutboundFlow>? _targetRedirectUnregister;

    public TcpDirectRelay(
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

    public void SetPacketInjector(Func<DirectRelayTarget, TcpSegment, bool> packetInjector)
    {
        _packetInjector = packetInjector;
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
        _maintenanceTask = Task.Run(() => MaintenanceLoopAsync(cancellationToken), cancellationToken);
        LogDetail("Local direct TCP relay uses packet injection; no local TCP listener is opened.");
    }

    public TcpRelayConnection RegisterSyn(
        TcpRelayKey flowKey,
        TcpClientKey clientKey,
        DirectRelayTarget target,
        uint clientSequenceNumber,
        ushort clientWindow,
        CancellationToken cancellationToken,
        ushort clientMss = 536)
    {
        if (_connections.TryGetValue(flowKey, out var existingConnection))
        {
            existingConnection.MarkSynRetransmitted();
            return existingConnection;
        }

        var connection = new TcpRelayConnection(
            flowKey,
            clientKey,
            target,
            clientSequenceNumber,
            clientWindow,
            clientMss,
            CreateInitialSequence(),
            _trafficCounter,
            _packetWakeSignal,
            _packetInjector,
            RegisterOutboundFlow,
            UnregisterOutboundFlow,
            _remove: Remove,
            _detailedLogging ? LogDetail : null,
            _log,
            _timeProvider,
            cancellationToken);

        if (!_connections.TryAdd(flowKey, connection))
        {
            connection.DisposeWithoutRemoving();
            if (_connections.TryGetValue(flowKey, out var existing))
            {
                existing.MarkSynRetransmitted();
                return existing;
            }
        }

        _ = connection.StartAsync();
        return connection;
    }

    public bool TryGetConnection(TcpRelayKey flowKey, out TcpRelayConnection connection)
    {
        return _connections.TryGetValue(flowKey, out connection!);
    }

    public bool IsRelayOutboundFlow(TcpRelayKey flowKey)
    {
        if (_relayOutboundFlows.ContainsKey(flowKey))
        {
            return true;
        }

        var wildcardAddress = flowKey.ClientAddress.AddressFamily == AddressFamily.InterNetwork
            ? IPAddress.Any
            : IPAddress.IPv6Any;
        return _relayOutboundFlows.ContainsKey(new TcpRelayKey(
            flowKey.AdapterHandle,
            flowKey.Dot1q,
            wildcardAddress,
            flowKey.RemoteAddress,
            flowKey.ClientPort,
            flowKey.RemotePort));
    }

    public int ConnectionCount => _connections.Count;

    public void MarkBypassedFlow(TcpRelayKey flowKey)
    {
        _bypassedFlows[flowKey] = _timeProvider.GetUtcNow();
    }

    public bool IsBypassedFlow(TcpRelayKey flowKey)
    {
        if (!_bypassedFlows.TryGetValue(flowKey, out var markedAt))
        {
            return false;
        }

        if (_timeProvider.GetUtcNow() - markedAt <= BypassFlowTtl)
        {
            return true;
        }

        _bypassedFlows.TryRemove(flowKey, out _);
        return false;
    }

    public void Remove(TcpRelayConnection connection)
    {
        if (_connections.TryGetValue(connection.FlowKey, out var current)
            && ReferenceEquals(current, connection)
            && _connections.TryRemove(
                new KeyValuePair<TcpRelayKey, TcpRelayConnection>(connection.FlowKey, connection)))
        {
            _targetRedirectUnregister?.Invoke(new RelayOutboundFlow(
                connection.FlowKey.AdapterHandle,
                PacketView.ProtocolTcp,
                connection.FlowKey.ClientAddress,
                connection.FlowKey.RemoteAddress,
                connection.FlowKey.ClientPort,
                connection.FlowKey.RemotePort,
                connection.FlowKey.Dot1q));
            connection.Dispose();
        }
    }

    private void RegisterOutboundFlow(RelayOutboundFlow flow)
    {
        _relayOutboundFlows[new TcpRelayKey(
            flow.AdapterHandle,
            flow.Dot1q,
            flow.LocalAddress,
            flow.RemoteAddress,
            flow.LocalPort,
            flow.RemotePort)] = 0;
        _outboundBypassRegister?.Invoke(flow);
    }

    private void UnregisterOutboundFlow(RelayOutboundFlow flow)
    {
        _relayOutboundFlows.TryRemove(
            new TcpRelayKey(
                flow.AdapterHandle,
                flow.Dot1q,
                flow.LocalAddress,
                flow.RemoteAddress,
                flow.LocalPort,
                flow.RemotePort),
            out _);
        _outboundBypassUnregister?.Invoke(flow);
    }

    private static uint CreateInitialSequence()
    {
        Span<byte> bytes = stackalloc byte[4];
        RandomNumberGenerator.Fill(bytes);
        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    private void LogDetail(string message)
    {
        if (_detailedLogging)
        {
            _log(message);
        }
    }

    private async Task MaintenanceLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(MaintenanceInterval, _timeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            var now = _timeProvider.GetUtcNow();
            foreach (var connection in _connections.Values)
            {
                connection.Maintain(now);
                if (connection.CanBeRemoved)
                {
                    Remove(connection);
                }
            }

            foreach (var bypass in _bypassedFlows)
            {
                if (now - bypass.Value > BypassFlowTtl)
                {
                    _bypassedFlows.TryRemove(bypass.Key, out _);
                }
            }
        }
    }

    public void Dispose()
    {
        foreach (var connection in _connections.Values)
        {
            _targetRedirectUnregister?.Invoke(new RelayOutboundFlow(
                connection.FlowKey.AdapterHandle,
                PacketView.ProtocolTcp,
                connection.FlowKey.ClientAddress,
                connection.FlowKey.RemoteAddress,
                connection.FlowKey.ClientPort,
                connection.FlowKey.RemotePort,
                connection.FlowKey.Dot1q));
            connection.Dispose();
        }

        _connections.Clear();
        _relayOutboundFlows.Clear();
        _bypassedFlows.Clear();
    }

    internal sealed class TcpRelayConnection : IDisposable
    {
        private static readonly TimeSpan InitialRemoteFinLifetime = TimeSpan.FromMinutes(5);
        private const int MaxRetransmissionAttempts = 10;

        private readonly object _sync = new();
        private readonly object _outboundFlowSync = new();
        private readonly TcpRelayKey _flowKey;
        private readonly TcpClientKey _clientKey;
        private readonly DirectRelayTarget _target;
        private readonly TrafficCounter _trafficCounter;
        private readonly PacketWakeSignal? _packetWakeSignal;
        private readonly Func<DirectRelayTarget, TcpSegment, bool>? _packetInjector;
        private readonly Action<RelayOutboundFlow> _registerOutboundFlow;
        private readonly Action<RelayOutboundFlow> _unregisterOutboundFlow;
        private readonly Action<TcpRelayConnection> _remove;
        private readonly Action<string>? _detailLog;
        private readonly Action<string> _errorLog;
        private readonly TimeProvider _timeProvider;
        private readonly CancellationTokenSource _cts;
        private readonly TaskCompletionSource<bool> _connected =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _handshakeAcknowledged =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly SemaphoreSlim _writeSignal = new(0);
        private readonly SemaphoreSlim _windowChanged = new(0, 1);
        private readonly SortedDictionary<long, PendingClientData> _outOfOrder = [];
        private readonly SortedDictionary<long, OutboundSegment> _outboundToClient = [];
        private readonly Queue<PendingClientWrite> _writeQueue = new();
        private readonly List<RelayOutboundFlow> _outboundFlows = [];
        private Socket? _socket;
        private Task? _writerTask;
        private Task? _receiverTask;
        private long _clientReceiveNext;
        private readonly uint _clientInitialSequence;
        private readonly ushort _clientMss;
        private long _clientAcknowledged;
        private long _clientFinSequence = -1;
        private long? _pendingFinSequence;
        private long _remoteInitialSequence;
        private long _remoteSendNext;
        private long _remoteSentNext;
        private long _remoteSendUna;
        private long _clientAckSequence;
        private long _remoteFinSequence = -1;
        private DateTimeOffset _remoteFinQueuedAt;
        private long _outOfOrderBytes;
        private ushort _clientWindow;
        private int _duplicateAckCount;
        private bool _connectedFlag;
        private bool _handshakeAcknowledgedFlag;
        private bool _remoteFinQueued;
        private bool _remoteFinAcknowledged;
        private bool _clientFinReceived;
        private bool _closed;
        private bool _resourcesDisposed;
        private bool _failureScheduled;
        private DateTimeOffset _createdAt;
        private DateTimeOffset _lastActivity;
        private TimeSpan _retransmissionTimeout = InitialRetransmissionTimeout;

        public TcpRelayConnection(
            TcpRelayKey flowKey,
            TcpClientKey clientKey,
            DirectRelayTarget target,
            uint clientSequenceNumber,
            ushort clientWindow,
            ushort clientMss,
            uint remoteInitialSequence,
            TrafficCounter trafficCounter,
            PacketWakeSignal? packetWakeSignal,
            Func<DirectRelayTarget, TcpSegment, bool>? packetInjector,
            Action<RelayOutboundFlow> registerOutboundFlow,
            Action<RelayOutboundFlow> unregisterOutboundFlow,
            Action<TcpRelayConnection> _remove,
            Action<string>? detailLog,
            Action<string> errorLog,
            TimeProvider timeProvider,
            CancellationToken externalCancellationToken)
        {
            _flowKey = flowKey;
            _clientKey = clientKey;
            _target = target;
            _trafficCounter = trafficCounter;
            _packetWakeSignal = packetWakeSignal;
            _packetInjector = packetInjector;
            _registerOutboundFlow = registerOutboundFlow;
            _unregisterOutboundFlow = unregisterOutboundFlow;
            this._remove = _remove;
            _detailLog = detailLog;
            _errorLog = errorLog;
            _timeProvider = timeProvider;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCancellationToken);
            _createdAt = _timeProvider.GetUtcNow();
            _lastActivity = _createdAt;

            _clientReceiveNext = (long)clientSequenceNumber + 1;
            _clientInitialSequence = clientSequenceNumber;
            _clientMss = (ushort)Math.Clamp((int)clientMss, 536, 1460);
            _clientAcknowledged = _clientReceiveNext;
            _clientWindow = clientWindow;
            _remoteInitialSequence = remoteInitialSequence;
            _remoteSendNext = _remoteInitialSequence;
            _remoteSentNext = _remoteInitialSequence;
            _remoteSendUna = _remoteInitialSequence;
            _clientAckSequence = _remoteInitialSequence;
        }

        public TcpRelayKey FlowKey => _flowKey;

        public TcpClientKey ClientKey => _clientKey;

        public uint ClientInitialSequence => _clientInitialSequence;

        public bool IsClosed
        {
            get
            {
                lock (_sync)
                {
                    return _closed;
                }
            }
        }

        public bool CanBeRemoved
        {
            get
            {
                lock (_sync)
                {
                    return _closed && !_failureScheduled;
                }
            }
        }

        public async Task StartAsync()
        {
            Socket? socket = null;
            try
            {
                socket = CreateRelaySocket(_target.RemoteAddress.AddressFamily);
                var remoteEndPoint = NetworkEndpointResolver.CreateRemoteEndPoint(_target);
                if (_target.InterfaceIndex > 0)
                {
                    try
                    {
                        var optionValue = _target.RemoteAddress.AddressFamily == AddressFamily.InterNetwork
                            ? IPAddress.HostToNetworkOrder(_target.InterfaceIndex)
                            : _target.InterfaceIndex;
                        socket.SetSocketOption(
                            _target.RemoteAddress.AddressFamily == AddressFamily.InterNetwork
                                ? SocketOptionLevel.IP
                                : SocketOptionLevel.IPv6,
                            (SocketOptionName)31,
                            optionValue);
                    }
                    catch
                    {
                    }
                }

                var bindEndPoint = NetworkEndpointResolver.CreateBindEndPoint(_target)
                    ?? NetworkEndpointResolver.CreateAnyEndPoint(remoteEndPoint.AddressFamily);
                socket.Bind(bindEndPoint);
                RegisterOutboundFlow(remoteEndPoint, socket);

                await socket.ConnectAsync(remoteEndPoint, _cts.Token).ConfigureAwait(false);

                lock (_sync)
                {
                    if (_closed)
                    {
                        socket.Dispose();
                        ClearOutboundFlows();
                        return;
                    }

                    _socket = socket;
                    socket = null;
                    _connectedFlag = true;
                    RegisterOutboundFlow(remoteEndPoint, _socket);
                }

                if (!_connected.TrySetResult(true))
                {
                    CloseClient(injectReset: false);
                    return;
                }

                QueueSynAck();

                _writerTask = WriterLoopAsync();
                _receiverTask = ReceiveRemoteLoopAsync();
            }
            catch (OperationCanceledException)
            {
                CloseClient(injectReset: false);
            }
            catch (Exception ex)
            {
                FailClient($"DIRECT TCP connect failed app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_clientKey.ClientAddress}:{_clientKey.ClientPort} target={_target.RemoteEndpoint}: {ex.Message}");
            }
            finally
            {
                socket?.Dispose();
            }
        }

        public void MarkSynRetransmitted()
        {
            bool send;
            lock (_sync)
            {
                send = _connectedFlag && !_closed;
                if (send)
                {
                    RetransmitEarliestLocked(force: true);
                }
            }
        }

        public void SendClientSegment(TcpSegment segment)
        {
            bool closeWithoutReset = false;
            bool sendAck = false;
            bool signalWindow = false;
            bool closeAfterAck = false;

            lock (_sync)
            {
                if (_closed)
                {
                    return;
                }

                _lastActivity = _timeProvider.GetUtcNow();

                if ((segment.Flags & PacketView.TcpFlagRst) != 0)
                {
                    var resetSequence = UnwrapNear(segment.SequenceNumber, _clientReceiveNext);
                    var receiveWindow = GetClientFacingWindowLocked();
                    var windowEnd = _clientReceiveNext + Math.Max(1, (int)receiveWindow);
                    if (resetSequence >= _clientReceiveNext
                        && resetSequence < windowEnd)
                    {
                        closeWithoutReset = true;
                    }
                    else
                    {
                        return;
                    }
                }
                else
                {
                    if ((segment.Flags & PacketView.TcpFlagSyn) != 0
                        && (segment.Flags & PacketView.TcpFlagAck) == 0)
                    {
                        RetransmitEarliestLocked(force: true);
                        return;
                    }

                    if ((segment.Flags & PacketView.TcpFlagAck) != 0
                        && !IsClientSequenceRelevant(segment.SequenceNumber))
                    {
                        return;
                    }

                    if (!ProcessAckLocked(segment))
                    {
                        _detailLog?.Invoke(
                            $"DIRECT TCP relay ignored an unacceptable acknowledgement seq={segment.SequenceNumber} ack={segment.AcknowledgmentNumber} expected<= {_remoteSendNext}.");
                        sendAck = true;
                    }
                    else
                    {
                        _clientWindow = segment.Window;
                        signalWindow = true;

                        if (segment.Payload.Length > 0)
                        {
                            AcceptClientPayloadLocked(segment);
                        }

                        if ((segment.Flags & PacketView.TcpFlagFin) != 0)
                        {
                            HandleClientFinLocked(segment);
                        }

                        TryConsumePendingFinLocked();
                        TrySendQueuedToClientLocked();
                        closeAfterAck = TryCompleteCloseLocked();
                        sendAck = true;
                    }
                }
            }

            if (closeWithoutReset)
            {
                CloseClient(injectReset: false, abortRemote: true);
                return;
            }

            if (signalWindow)
            {
                Pulse(_windowChanged);
            }

            if (sendAck)
            {
                InjectClientAcknowledgement();
            }

            if (closeAfterAck)
            {
                CloseClient(injectReset: false);
            }
        }

        private bool ProcessAckLocked(TcpSegment segment)
        {
            if ((segment.Flags & PacketView.TcpFlagAck) == 0)
            {
                return true;
            }

            var ack = UnwrapNear(segment.AcknowledgmentNumber, _remoteSendNext);
            if (ack > _remoteSendNext)
            {
                return false;
            }

            if (ack < _remoteSendUna)
            {
                return true;
            }

            if (ack >= _remoteInitialSequence + 1 && !_handshakeAcknowledgedFlag)
            {
                _handshakeAcknowledgedFlag = true;
                _handshakeAcknowledged.TrySetResult(true);
            }

            if (ack > _clientAckSequence)
            {
                _clientAckSequence = ack;
                _remoteSendUna = ack;
                _duplicateAckCount = 0;
                _retransmissionTimeout = InitialRetransmissionTimeout;
                RemoveAcknowledgedSegmentsLocked(ack);
            }
            else if (ack == _clientAckSequence && _outboundToClient.Count > 0)
            {
                _duplicateAckCount++;
                if (_duplicateAckCount >= 3)
                {
                    _duplicateAckCount = 0;
                    RetransmitEarliestLocked(force: true);
                }
            }

            if (_remoteFinQueued && ack >= _remoteFinSequence + 1)
            {
                _remoteFinAcknowledged = true;
            }

            return true;
        }

        private void RemoveAcknowledgedSegmentsLocked(long ack)
        {
            while (_outboundToClient.Count > 0)
            {
                using var enumerator = _outboundToClient.GetEnumerator();
                if (!enumerator.MoveNext())
                {
                    return;
                }

                var pair = enumerator.Current;
                if (pair.Value.End <= ack)
                {
                    _outboundToClient.Remove(pair.Key);
                    continue;
                }

                if (pair.Value.Start < ack && pair.Value.End > ack)
                {
                    var trim = (int)(ack - pair.Value.Start);
                    var trimmedPayload = pair.Value.Segment.Payload[trim..];
                    var flags = (byte)(pair.Value.Segment.Flags & ~PacketView.TcpFlagSyn);
                    var trimmed = new TcpSegment(
                        (uint)ack,
                        pair.Value.Segment.AcknowledgmentNumber,
                        flags,
                        pair.Value.Segment.Window,
                        pair.Value.Segment.UrgentPointer,
                        trimmedPayload,
                        pair.Value.Segment.Options);

                    _outboundToClient.Remove(pair.Key);
                    _outboundToClient[ack] = OutboundSegment.Create(trimmed);
                }

                return;
            }
        }

        private void AcceptClientPayloadLocked(TcpSegment segment)
        {
            var sequence = UnwrapNear(segment.SequenceNumber, _clientReceiveNext);
            var payload = segment.Payload;
            if (payload.Length == 0)
            {
                return;
            }

            var end = sequence + payload.Length;
            if (end <= _clientAcknowledged)
            {
                return;
            }

            var bufferedEnd = Math.Max(_clientReceiveNext, end);
            if (bufferedEnd - _clientAcknowledged > MaxBufferedClientBytes)
            {
                return;
            }

            if (sequence > _clientReceiveNext)
            {
                StoreOutOfOrder(sequence, payload, segment.UrgentPointer, (segment.Flags & PacketView.TcpFlagUrg) != 0);
                return;
            }

            var start = Math.Max(sequence, _clientReceiveNext);
            var offset = checked((int)(start - sequence));
            if (offset >= payload.Length)
            {
                return;
            }

            var accepted = payload[offset..].ToArray();
            var urgent = (segment.Flags & PacketView.TcpFlagUrg) != 0
                && segment.UrgentPointer > offset;
            var urgentPointer = urgent
                ? (ushort)(segment.UrgentPointer - offset)
                : (ushort)0;
            EnqueueClientWrite(start, accepted, urgentPointer, urgent);
            _clientReceiveNext = start + accepted.Length;
            FlushOutOfOrderLocked();
        }

        private void StoreOutOfOrder(
            long sequence,
            ReadOnlyMemory<byte> payload,
            ushort urgentPointer,
            bool urgent)
        {
            _outOfOrder.TryGetValue(sequence, out var existing);
            if (existing is not null && existing.Payload.Length >= payload.Length)
            {
                return;
            }

            var existingLength = existing?.Payload.Length ?? 0;
            if (_outOfOrderBytes - existingLength + payload.Length > MaxOutOfOrderBytes)
            {
                return;
            }

            var copy = payload.ToArray();
            if (existing is not null)
            {
                _outOfOrderBytes -= existingLength;
            }

            _outOfOrder[sequence] = new PendingClientData(sequence, copy, urgentPointer, urgent);
            _outOfOrderBytes += copy.Length;
        }

        private void FlushOutOfOrderLocked()
        {
            while (_outOfOrder.Count > 0)
            {
                using var enumerator = _outOfOrder.GetEnumerator();
                if (!enumerator.MoveNext())
                {
                    return;
                }

                var pair = enumerator.Current;
                if (pair.Key > _clientReceiveNext)
                {
                    return;
                }

                _outOfOrder.Remove(pair.Key);
                _outOfOrderBytes -= pair.Value.Payload.Length;

                var end = pair.Key + pair.Value.Payload.Length;
                if (end <= _clientReceiveNext)
                {
                    continue;
                }

                var offset = checked((int)Math.Max(0, _clientReceiveNext - pair.Key));
                var payload = pair.Value.Payload[offset..];
                if (payload.Length == 0)
                {
                    continue;
                }

                EnqueueClientWrite(
                    _clientReceiveNext,
                    payload,
                    0,
                    urgent: false);
                _clientReceiveNext += payload.Length;
            }
        }

        private void HandleClientFinLocked(TcpSegment segment)
        {
            var finSequence = UnwrapNear(segment.SequenceNumber, _clientReceiveNext) + segment.Payload.Length;
            if (finSequence < _clientAcknowledged)
            {
                return;
            }

            if (finSequence == _clientReceiveNext)
            {
                ConsumePendingFinLocked(finSequence);
            }
            else if (finSequence > _clientReceiveNext)
            {
                _pendingFinSequence = finSequence;
            }
        }

        private void TryConsumePendingFinLocked()
        {
            if (_pendingFinSequence is not { } pending || pending != _clientReceiveNext)
            {
                return;
            }

            ConsumePendingFinLocked(pending);
        }

        private void ConsumePendingFinLocked(long finSequence)
        {
            if (_clientFinReceived && _clientFinSequence == finSequence)
            {
                return;
            }

            _pendingFinSequence = null;
            _clientFinReceived = true;
            _clientFinSequence = finSequence;
            _clientReceiveNext = finSequence + 1;
            _writeQueue.Enqueue(new PendingClientWrite(finSequence, [], Fin: true, Urgent: false, UrgentPointer: 0));
            _writeSignal.Release();
        }

        private void EnqueueClientWrite(
            long sequence,
            byte[] payload,
            ushort urgentPointer,
            bool urgent)
        {
            _writeQueue.Enqueue(new PendingClientWrite(sequence, payload, Fin: false, Urgent: urgent, UrgentPointer: urgentPointer));
            _writeSignal.Release();
        }

        private async Task WriterLoopAsync()
        {
            try
            {
                await _connected.Task.WaitAsync(_cts.Token).ConfigureAwait(false);

                while (!_cts.IsCancellationRequested)
                {
                    await _writeSignal.WaitAsync(_cts.Token).ConfigureAwait(false);

                    PendingClientWrite? item;
                    lock (_sync)
                    {
                        if (_closed)
                        {
                            return;
                        }

                        item = _writeQueue.Count > 0 ? _writeQueue.Dequeue() : null;
                    }

                    if (item is null)
                    {
                        continue;
                    }

                    Socket? socket;
                    lock (_sync)
                    {
                        socket = _socket;
                    }

                    if (socket is null)
                    {
                        return;
                    }

                    if (item.Payload.Length > 0)
                    {
                        await SendClientPayloadAsync(socket, item).ConfigureAwait(false);
                        _trafficCounter.AddUpload(item.Payload.Length);
                        _packetWakeSignal?.Pulse();
                    }

                    if (item.Fin)
                    {
                        try
                        {
                            socket.Shutdown(SocketShutdown.Send);
                        }
                        catch (SocketException ex)
                        {
                            FailClient($"DIRECT TCP shutdown failed app={_target.AppLabel}: {ex.Message}");
                            return;
                        }
                    }

                    bool closeAfter;
                    lock (_sync)
                    {
                        _clientAcknowledged = Math.Max(
                            _clientAcknowledged,
                            item.Sequence + item.Payload.Length + (item.Fin ? 1 : 0));
                        closeAfter = TryCompleteCloseLocked();
                    }

                    InjectClientAcknowledgement();
                    if (closeAfter)
                    {
                        CloseClient(injectReset: false);
                        return;
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                FailClient($"DIRECT TCP send failed app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_clientKey.ClientAddress}:{_clientKey.ClientPort} target={_target.RemoteEndpoint}: {ex.Message}");
            }
        }

        private async Task SendClientPayloadAsync(Socket socket, PendingClientWrite item)
        {
            if (!item.Urgent || item.Payload.Length == 0)
            {
                await SendAllAsync(socket, item.Payload, SocketFlags.None, _cts.Token).ConfigureAwait(false);
                return;
            }

            var urgentIndex = Math.Clamp(item.UrgentPointer, 1, item.Payload.Length);
            if (urgentIndex > 1)
            {
                await SendAllAsync(socket, item.Payload.AsMemory(0, urgentIndex - 1), SocketFlags.None, _cts.Token).ConfigureAwait(false);
            }

            try
            {
                await SendAllAsync(socket, item.Payload.AsMemory(urgentIndex - 1, 1), SocketFlags.OutOfBand, _cts.Token).ConfigureAwait(false);
            }
            catch (SocketException)
            {
                await SendAllAsync(socket, item.Payload.AsMemory(urgentIndex - 1, 1), SocketFlags.None, _cts.Token).ConfigureAwait(false);
            }

            if (urgentIndex < item.Payload.Length)
            {
                await SendAllAsync(socket, item.Payload.AsMemory(urgentIndex), SocketFlags.None, _cts.Token).ConfigureAwait(false);
            }
        }

        private async Task ReceiveRemoteLoopAsync()
        {
            var maxPayload = GetMaxTcpPayload();
            var buffer = new byte[maxPayload];
            try
            {
                await _connected.Task.WaitAsync(_cts.Token).ConfigureAwait(false);
                await _handshakeAcknowledged.Task.WaitAsync(_cts.Token).ConfigureAwait(false);

                while (!_cts.IsCancellationRequested)
                {
                    int readSize;
                    var waitForWindow = false;
                    lock (_sync)
                    {
                        if (_closed || _remoteFinQueued)
                        {
                            return;
                        }

                        var windowEnd = _clientAckSequence + _clientWindow;
                        var available = windowEnd - _remoteSendNext;
                        if (available <= 0)
                        {
                            waitForWindow = true;
                            readSize = 0;
                        }
                        else
                        {
                            readSize = (int)Math.Min(maxPayload, available);
                        }
                    }

                    if (waitForWindow)
                    {
                        await _windowChanged.WaitAsync(_cts.Token).ConfigureAwait(false);
                        continue;
                    }

                    Socket? socket;
                    lock (_sync)
                    {
                        socket = _socket;
                    }

                    if (socket is null)
                    {
                        return;
                    }

                    var read = await socket.ReceiveAsync(
                        buffer.AsMemory(0, readSize),
                        SocketFlags.None,
                        _cts.Token).ConfigureAwait(false);

                    if (read == 0)
                    {
                        _detailLog?.Invoke($"DIRECT TCP remote EOF app={_target.AppLabel} client={_clientKey.ClientAddress}:{_clientKey.ClientPort} target={_target.RemoteEndpoint}");
                        QueueRemoteFin();
                        return;
                    }

                    var payload = buffer.AsMemory(0, read).ToArray();
                    lock (_sync)
                    {
                        if (_closed)
                        {
                            return;
                        }

                        var sequence = _remoteSendNext;
                        var segment = new TcpSegment(
                            (uint)sequence,
                            (uint)_clientAcknowledged,
                            PacketView.TcpFlagPsh | PacketView.TcpFlagAck,
                            GetClientFacingWindowLocked(),
                            0,
                            payload,
                            ReadOnlyMemory<byte>.Empty);
                        AddOutboundSegmentLocked(segment);
                        TrySendQueuedToClientLocked();
                    }

                    _trafficCounter.AddDownload(read);
                    _packetWakeSignal?.Pulse();
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                FailClient($"DIRECT TCP remote receive failed for {_clientKey.ClientAddress}:{_clientKey.ClientPort} -> {_target.RemoteAddress}:{_target.RemotePort}: {ex.Message}");
            }
        }

        private void QueueRemoteFin()
        {
            bool signalConnection = false;
            lock (_sync)
            {
                if (_closed || _remoteFinQueued)
                {
                    return;
                }

                _remoteFinQueued = true;
                _remoteFinSequence = _remoteSendNext;
                _remoteFinQueuedAt = _timeProvider.GetUtcNow();
                var segment = new TcpSegment(
                    (uint)_remoteFinSequence,
                    (uint)_clientAcknowledged,
                    PacketView.TcpFlagFin | PacketView.TcpFlagAck,
                    GetClientFacingWindowLocked(),
                    0,
                    ReadOnlyMemory<byte>.Empty,
                    ReadOnlyMemory<byte>.Empty);
                AddOutboundSegmentLocked(segment);
                TrySendQueuedToClientLocked();
                signalConnection = TryCompleteCloseLocked();
            }

            if (signalConnection)
            {
                CloseClient(injectReset: false);
            }
        }

        private void AddOutboundSegmentLocked(TcpSegment segment)
        {
            var start = (long)segment.SequenceNumber;
            if (_remoteSendNext != _remoteInitialSequence && start != _remoteSendNext)
            {
                start = _remoteSendNext;
                segment = segment with { SequenceNumber = (uint)start };
            }

            var outbound = OutboundSegment.Create(segment);
            _outboundToClient[start] = outbound;
            _remoteSendNext = outbound.End;
        }

        private void TrySendQueuedToClientLocked()
        {
            var windowEnd = _clientAckSequence + _clientWindow;
            foreach (var outbound in _outboundToClient.Values)
            {
                if (outbound.Sent)
                {
                    continue;
                }

                if ((outbound.Segment.Flags & PacketView.TcpFlagSyn) == 0
                    && outbound.End > windowEnd)
                {
                    return;
                }

                SendOutboundSegmentLocked(outbound, force: false);
            }
        }

        private void RetransmitEarliestLocked(bool force)
        {
            foreach (var outbound in _outboundToClient.Values)
            {
                if (!outbound.Sent || force)
                {
                    if ((outbound.Segment.Flags & PacketView.TcpFlagSyn) == 0
                        && outbound.End > _clientAckSequence + _clientWindow)
                    {
                        return;
                    }

                    SendOutboundSegmentLocked(outbound, force);
                    return;
                }
            }
        }

        private void SendOutboundSegmentLocked(OutboundSegment outbound, bool force)
        {
            if (_packetInjector is null)
            {
                FailLocked("DIRECT TCP relay has no packet injector.");
                return;
            }

            try
            {
                var injected = _packetInjector(
                    _target,
                    outbound.Segment with
                    {
                        SequenceNumber = (uint)outbound.Start,
                        AcknowledgmentNumber = (uint)_clientAcknowledged,
                        Window = GetClientFacingWindowLocked()
                    });
                if (!injected)
                {
                    FailLocked("DIRECT TCP packet injection was rejected.");
                    return;
                }

                outbound.Sent = true;
                _remoteSentNext = Math.Max(_remoteSentNext, outbound.End);
                outbound.Attempts++;
                outbound.LastSent = _timeProvider.GetUtcNow();
                if (outbound.Attempts > MaxRetransmissionAttempts)
                {
                    FailLocked("DIRECT TCP relay exceeded the retransmission limit.");
                }
            }
            catch (Exception ex)
            {
                _errorLog($"DIRECT TCP inject failed app={_target.AppLabel} client={_clientKey.ClientAddress}:{_clientKey.ClientPort} target={_target.RemoteEndpoint}: {ex.Message}");
                FailLocked($"DIRECT TCP inject failed: {ex.Message}");
            }
        }

        private void InjectClientAcknowledgement()
        {
            lock (_sync)
            {
                if (_closed || _packetInjector is null)
                {
                    return;
                }

                var segment = new TcpSegment(
                    (uint)_remoteSentNext,
                    (uint)_clientAcknowledged,
                    PacketView.TcpFlagAck,
                    GetClientFacingWindowLocked(),
                    0,
                    ReadOnlyMemory<byte>.Empty,
                    ReadOnlyMemory<byte>.Empty);
                try
                {
                    if (!_packetInjector(_target, segment))
                    {
                        FailLocked("DIRECT TCP acknowledgement injection was rejected.");
                    }
                }
                catch (Exception ex)
                {
                    _errorLog($"DIRECT TCP acknowledgement inject failed app={_target.AppLabel}: {ex.Message}");
                    FailLocked($"DIRECT TCP acknowledgement inject failed: {ex.Message}");
                }
            }
        }

        private ushort GetClientFacingWindowLocked()
        {
            var buffered = Math.Max(0, _clientReceiveNext - _clientAcknowledged);
            return (ushort)Math.Clamp(MaxBufferedClientBytes - buffered, 0, ushort.MaxValue);
        }

        private bool IsClientSequenceRelevant(uint sequenceNumber)
        {
            var sequence = UnwrapNear(sequenceNumber, _clientReceiveNext);
            return sequence >= _clientAcknowledged - MaxBufferedClientBytes
                && sequence <= _clientReceiveNext + MaxBufferedClientBytes;
        }

        private bool TryCompleteCloseLocked()
        {
            if (!_clientFinReceived || !_remoteFinAcknowledged)
            {
                return false;
            }

            if (_writeQueue.Count > 0 || _outboundToClient.Count > 0)
            {
                return false;
            }

            return _clientAcknowledged >= _clientFinSequence + 1;
        }

        private void QueueSynAck()
        {
            lock (_sync)
            {
                if (_closed || _remoteSendNext != _remoteInitialSequence)
                {
                    return;
                }

                var mss = (ushort)Math.Clamp(GetMaxTcpPayload(), 536, ushort.MaxValue);
                var options = new byte[]
                {
                    2,
                    4,
                    (byte)(mss >> 8),
                    (byte)mss
                };
                var segment = new TcpSegment(
                    (uint)_remoteInitialSequence,
                    (uint)_clientReceiveNext,
                    PacketView.TcpFlagSyn | PacketView.TcpFlagAck,
                    GetClientFacingWindowLocked(),
                    0,
                    ReadOnlyMemory<byte>.Empty,
                    options);
                AddOutboundSegmentLocked(segment);
                TrySendQueuedToClientLocked();
            }

            _detailLog?.Invoke($"DIRECT TCP CONNECT app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_clientKey.ClientAddress}:{_clientKey.ClientPort} target={_target.RemoteEndpoint} relayProcess={Environment.ProcessId}");
        }

        private void RegisterOutboundFlow(IPEndPoint remoteEndPoint, Socket socket)
        {
            if (socket.LocalEndPoint is not IPEndPoint localEndPoint || localEndPoint.Port == 0)
            {
                return;
            }

            var localAddress = localEndPoint.Address.AddressFamily == AddressFamily.InterNetwork
                ? (localEndPoint.Address.Equals(IPAddress.Any) ? IPAddress.Any : localEndPoint.Address)
                : (localEndPoint.Address.Equals(IPAddress.IPv6Any) ? IPAddress.IPv6Any : localEndPoint.Address);
            var flow = new RelayOutboundFlow(
                _target.AdapterHandle,
                PacketView.ProtocolTcp,
                localAddress,
                remoteEndPoint.Address,
                (ushort)localEndPoint.Port,
                (ushort)remoteEndPoint.Port,
                _target.Dot1q);

            lock (_outboundFlowSync)
            {
                if (_resourcesDisposed)
                {
                    return;
                }

                if (_outboundFlows.Contains(flow))
                {
                    return;
                }

                _outboundFlows.Add(flow);
                _registerOutboundFlow(flow);
            }

            if (localAddress.Equals(IPAddress.Any) || localAddress.Equals(IPAddress.IPv6Any))
            {
                return;
            }

            var wildcardAddress = localAddress.AddressFamily == AddressFamily.InterNetwork
                ? IPAddress.Any
                : IPAddress.IPv6Any;
            RelayOutboundFlow wildcardFlow;
            lock (_outboundFlowSync)
            {
                wildcardFlow = _outboundFlows.FirstOrDefault(candidate =>
                    candidate.AdapterHandle == flow.AdapterHandle
                    && candidate.LocalAddress.Equals(wildcardAddress)
                    && candidate.LocalPort == flow.LocalPort
                    && candidate.RemoteAddress.Equals(flow.RemoteAddress)
                    && candidate.RemotePort == flow.RemotePort);
                if (wildcardFlow != default)
                {
                    _outboundFlows.Remove(wildcardFlow);
                }
            }

            if (wildcardFlow != default)
            {
                _unregisterOutboundFlow(wildcardFlow);
            }
        }

        private void ClearOutboundFlows()
        {
            lock (_outboundFlowSync)
            {
                foreach (var flow in _outboundFlows)
                {
                    _unregisterOutboundFlow(flow);
                }

                _outboundFlows.Clear();
            }
        }

        internal void Maintain(DateTimeOffset now)
        {
            string? failureMessage = null;
            lock (_sync)
            {
                if (_closed)
                {
                    return;
                }

                if (!_connectedFlag && now - _createdAt > ConnectTimeout)
                {
                    failureMessage = "DIRECT TCP relay timed out while connecting.";
                }
                else if (_outboundToClient.Count > 0)
                {
                    using var enumerator = _outboundToClient.GetEnumerator();
                    if (enumerator.MoveNext())
                    {
                        var outbound = enumerator.Current.Value;
                        if (outbound.Sent
                            && now - outbound.LastSent >= _retransmissionTimeout
                            && outbound.End <= _clientAckSequence + _clientWindow)
                        {
                            SendOutboundSegmentLocked(outbound, force: true);
                            _retransmissionTimeout = TimeSpan.FromMilliseconds(
                                Math.Min(
                                    MaxRetransmissionTimeout.TotalMilliseconds,
                                    _retransmissionTimeout.TotalMilliseconds * 2));
                        }
                    }
                }

                if (_remoteFinQueued
                    && !_remoteFinAcknowledged
                    && now - _remoteFinQueuedAt > InitialRemoteFinLifetime)
                {
                    failureMessage = "DIRECT TCP relay timed out waiting for the remote FIN acknowledgement.";
                }
            }

            if (failureMessage is not null)
            {
                FailClient(failureMessage);
            }
        }

        private void FailClient(string message)
        {
            _errorLog(message);
            bool injectReset;
            TcpSegment segment = default;
            lock (_sync)
            {
                if (_resourcesDisposed)
                {
                    return;
                }

                _closed = true;
                injectReset = true;
                segment = new TcpSegment(
                    (uint)_remoteSentNext,
                    (uint)_clientReceiveNext,
                    PacketView.TcpFlagRst | PacketView.TcpFlagAck,
                    0,
                    0,
                    ReadOnlyMemory<byte>.Empty,
                    ReadOnlyMemory<byte>.Empty);
            }

            if (injectReset && _packetInjector is not null)
            {
                try
                {
                    if (!_packetInjector(_target, segment))
                    {
                        _errorLog($"DIRECT TCP reset injection was rejected app={_target.AppLabel} client={_clientKey.ClientAddress}:{_clientKey.ClientPort}");
                    }
                }
                catch
                {
                }
            }

            AbortRemoteSocket();
            DisposeResources();
        }

        private void AbortRemoteSocket()
        {
            lock (_sync)
            {
                if (_socket is null)
                {
                    return;
                }

                try
                {
                    _socket.LingerState = new LingerOption(true, 0);
                }
                catch
                {
                }
            }
        }

        private void FailLocked(string message)
        {
            _closed = true;
            if (_failureScheduled)
            {
                return;
            }

            _failureScheduled = true;
            _ = Task.Run(() => FailClient(message));
        }

        private void CloseClient(bool injectReset, bool abortRemote = false)
        {
            TcpSegment reset = default;
            lock (_sync)
            {
                if (_resourcesDisposed)
                {
                    return;
                }

                _closed = true;
                if (abortRemote && _socket is not null)
                {
                    try
                    {
                        _socket.LingerState = new LingerOption(true, 0);
                    }
                    catch
                    {
                    }
                }

                if (injectReset)
                {
                    reset = new TcpSegment(
                        (uint)_remoteSendNext,
                        (uint)_clientReceiveNext,
                        PacketView.TcpFlagRst | PacketView.TcpFlagAck,
                        0,
                        0,
                        ReadOnlyMemory<byte>.Empty,
                        ReadOnlyMemory<byte>.Empty);
                }
            }

            if (injectReset && _packetInjector is not null)
            {
                try
                {
                    _ = _packetInjector(_target, reset);
                }
                catch
                {
                }
            }

            DisposeResources();
        }

        private void DisposeResources(bool removeConnection = true)
        {
            lock (_sync)
            {
                if (_resourcesDisposed)
                {
                    return;
                }

                _resourcesDisposed = true;
            }

            ClearOutboundFlows();
            _connected.TrySetCanceled();
            _handshakeAcknowledged.TrySetCanceled();
            _cts.Cancel();
            _socket?.Dispose();
            _socket = null;
            Pulse(_writeSignal);
            Pulse(_windowChanged);
            if (removeConnection)
            {
                _remove(this);
            }
        }

        public void Dispose()
        {
            CloseClient(injectReset: false);
            _cts.Dispose();
            _writeSignal.Dispose();
            _windowChanged.Dispose();
        }

        internal void DisposeWithoutRemoving()
        {
            lock (_sync)
            {
                if (_resourcesDisposed)
                {
                    return;
                }

                _closed = true;
            }

            DisposeResources(removeConnection: false);
            _cts.Dispose();
            _writeSignal.Dispose();
            _windowChanged.Dispose();
        }

        private static Socket CreateRelaySocket(AddressFamily addressFamily)
        {
            return new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true
            };
        }

        private static async Task SendAllAsync(
            Socket socket,
            ReadOnlyMemory<byte> payload,
            SocketFlags flags,
            CancellationToken cancellationToken)
        {
            var offset = 0;
            while (offset < payload.Length)
            {
                var sent = await socket.SendAsync(payload[offset..], flags, cancellationToken).ConfigureAwait(false);
                if (sent <= 0)
                {
                    throw new IOException("The relay socket sent zero bytes.");
                }

                offset += sent;
            }
        }

        private static long UnwrapNear(uint sequence, long reference)
        {
            var delta = (int)(sequence - (uint)reference);
            return reference + delta;
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

        private int GetMaxTcpPayload()
        {
            var ipHeaderLength = _target.RemoteAddress.AddressFamily == AddressFamily.InterNetwork ? 20 : 40;
            return Math.Clamp(
                Math.Min(_target.AdapterMtu - ipHeaderLength - 20, _clientMss),
                536,
                MaxTcpPayload);
        }

        private sealed class PendingClientData(
            long sequence,
            byte[] payload,
            ushort urgentPointer,
            bool urgent)
        {
            public long Sequence { get; } = sequence;
            public byte[] Payload { get; } = payload;
            public ushort UrgentPointer { get; } = urgentPointer;
            public bool Urgent { get; } = urgent;
        }

        private sealed record PendingClientWrite(
            long Sequence,
            byte[] Payload,
            bool Fin,
            bool Urgent,
            ushort UrgentPointer);

        private sealed class OutboundSegment
        {
            private OutboundSegment(long start, TcpSegment segment)
            {
                Start = start;
                Segment = segment;
            }

            public long Start { get; }
            public long End => Start + Segment.SequenceLength;
            public TcpSegment Segment { get; }
            public bool Sent { get; set; }
            public int Attempts { get; set; }
            public DateTimeOffset LastSent { get; set; }

            public static OutboundSegment Create(TcpSegment segment)
            {
                return new OutboundSegment((long)segment.SequenceNumber, segment);
            }
        }
    }
}
