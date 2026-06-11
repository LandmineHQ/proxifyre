using System.Collections.Concurrent;
using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class TcpDirectRelay : IDisposable
{
    private readonly ConcurrentDictionary<TcpClientKey, DirectRelayTarget> _targetsByClient = new();
    private readonly ConcurrentDictionary<TcpRelayKey, TcpClientKey> _clientsByFlow = new();
    private readonly ConcurrentDictionary<TcpRelayKey, byte> _relayOutboundFlows = new();
    private readonly TimeSpan _targetTtl = TimeSpan.FromMinutes(5);
    private readonly Action<string> _log;
    private readonly bool _detailedLogging;
    private readonly TrafficCounter _trafficCounter;
    private readonly PacketWakeSignal? _packetWakeSignal;
    private readonly TimeProvider _timeProvider;
    private TcpListener? _listener;

    public TcpDirectRelay(Action<string>? log = null, bool detailedLogging = false, TrafficCounter? trafficCounter = null, PacketWakeSignal? packetWakeSignal = null, TimeProvider? timeProvider = null)
    {
        _log = log ?? Console.WriteLine;
        _detailedLogging = detailedLogging;
        _trafficCounter = trafficCounter ?? new TrafficCounter();
        _packetWakeSignal = packetWakeSignal;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public ushort Port { get; private set; }

    public void Start(CancellationToken cancellationToken)
    {
        if (_listener is not null)
        {
            return;
        }

        _listener = new TcpListener(IPAddress.IPv6Any, 0);
        _listener.Server.DualMode = true;
        _listener.Start(512);
        Port = (ushort)((IPEndPoint)_listener.LocalEndpoint).Port;

        LogDetail($"Local direct TCP relay listening on [::]:{Port}");
        _ = Task.Run(() => AcceptLoopAsync(_listener, cancellationToken), cancellationToken);
        _ = Task.Run(() => CleanupLoopAsync(cancellationToken), cancellationToken);
    }

    public void Register(TcpRelayKey flowKey, TcpClientKey clientKey, DirectRelayTarget target)
    {
        _targetsByClient[clientKey] = target;
        _clientsByFlow[flowKey] = clientKey;
    }

    public bool Refresh(TcpRelayKey flowKey)
    {
        return _clientsByFlow.TryGetValue(flowKey, out var clientKey) && Refresh(clientKey);
    }

    public bool Refresh(TcpClientKey clientKey)
    {
        if (!_targetsByClient.TryGetValue(clientKey, out var target))
        {
            return false;
        }

        _targetsByClient[clientKey] = target with { CreatedAt = _timeProvider.GetUtcNow() };
        return true;
    }

    public bool TryGetTarget(TcpRelayKey flowKey, out DirectRelayTarget target)
    {
        target = default!;
        return _clientsByFlow.TryGetValue(flowKey, out var clientKey)
            && _targetsByClient.TryGetValue(clientKey, out target!);
    }

    public bool TryGetTarget(TcpClientKey clientKey, out DirectRelayTarget target)
    {
        return _targetsByClient.TryGetValue(clientKey, out target!);
    }

    public bool IsRelayOutboundFlow(TcpRelayKey flowKey)
    {
        return _relayOutboundFlows.ContainsKey(flowKey);
    }

    public void Remove(TcpClientKey clientKey)
    {
        if (_targetsByClient.TryRemove(clientKey, out var target))
        {
            _clientsByFlow.TryRemove(new TcpRelayKey(target.RemoteAddress, clientKey.ClientPort, target.RemotePort), out _);
        }
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
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
                _log($"TCP relay accept failed: {ex.Message}");
                continue;
            }

            _ = Task.Run(() => HandleClientAsync(client, cancellationToken), cancellationToken);
        }
    }

    private async Task HandleClientAsync(TcpClient inbound, CancellationToken cancellationToken)
    {
        using var inboundClient = inbound;

        if (inbound.Client.RemoteEndPoint is not IPEndPoint remoteClientEndPoint)
        {
            return;
        }

        var key = new TcpClientKey(remoteClientEndPoint.Address, (ushort)remoteClientEndPoint.Port);
        if (!_targetsByClient.TryGetValue(key, out var target))
        {
            _log($"No direct target found for redirected TCP client {key.ClientAddress}:{key.ClientPort}");
            return;
        }

        var remoteEndPoint = NetworkEndpointResolver.CreateRemoteEndPoint(target);
        TcpRelayKey? outboundFlowKey = null;
        try
        {
            LogDetail($"DIRECT TCP ACCEPT app={target.AppLabel} appLocal={target.ClientEndpoint} client={key.ClientAddress}:{key.ClientPort} target={target.RemoteEndpoint} relayProcess={Environment.ProcessId} inboundLocal={inbound.Client.LocalEndPoint}");
            var connectResult = await ConnectOutboundAsync(remoteEndPoint, target, cancellationToken).ConfigureAwait(false);
            using var outbound = connectResult.Client;
            outboundFlowKey = connectResult.FlowKey;
            LogDetail($"DIRECT TCP CONNECT app={target.AppLabel} appLocal={target.ClientEndpoint} client={key.ClientAddress}:{key.ClientPort} target={target.RemoteEndpoint} relayProcess={Environment.ProcessId} relayLocal={outbound.Client.LocalEndPoint}");

            await using var inboundStream = inbound.GetStream();
            await using var outboundStream = outbound.GetStream();
            var stats = new TcpRelayStats(key, target, _detailedLogging ? LogDetail : null, _timeProvider);
            var upstream = CopyAndCountAsync(
                "upstream",
                inboundStream,
                outboundStream,
                bytes =>
                {
                    stats.AddUp(bytes);
                    _trafficCounter.AddUpload(bytes);
                },
                key,
                target,
                cancellationToken);
            var downstream = CopyAndCountAsync(
                "downstream",
                outboundStream,
                inboundStream,
                bytes =>
                {
                    stats.AddDown(bytes);
                    _trafficCounter.AddDownload(bytes);
                },
                key,
                target,
                cancellationToken);

            await WaitForRelayCompletionAsync(upstream, downstream, inbound.Client, outbound.Client, cancellationToken).ConfigureAwait(false);
            stats.Log("END", force: true);
            LogCopyFailure("upstream", upstream, key, target);
            LogCopyFailure("downstream", downstream, key, target);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _log($"DIRECT TCP failed app={target.AppLabel} appLocal={target.ClientEndpoint} client={key.ClientAddress}:{key.ClientPort} target={target.RemoteEndpoint} relayProcess={Environment.ProcessId}: {ex.Message}");
        }
        finally
        {
            if (outboundFlowKey is { } flowKey)
            {
                _relayOutboundFlows.TryRemove(flowKey, out _);
            }
        }
    }

    private async Task<TcpConnectResult> ConnectOutboundAsync(IPEndPoint remoteEndPoint, DirectRelayTarget target, CancellationToken cancellationToken)
    {
        var bindEndPoint = NetworkEndpointResolver.CreateBindEndPoint(target);
        if (bindEndPoint is not null && bindEndPoint.AddressFamily == remoteEndPoint.AddressFamily)
        {
            try
            {
                return await ConnectFromBoundSocketAsync(remoteEndPoint, bindEndPoint, cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException ex) when (IsAddressContextFailure(ex))
            {
                _log($"DIRECT TCP bind/connect failed, retrying unbound app={target.AppLabel} appLocal={target.ClientEndpoint} target={target.RemoteEndpoint} bind={bindEndPoint}: {ex.Message}");
            }
        }

        return await ConnectFromBoundSocketAsync(
            remoteEndPoint,
            NetworkEndpointResolver.CreateAnyEndPoint(remoteEndPoint.AddressFamily),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<TcpConnectResult> ConnectFromBoundSocketAsync(IPEndPoint remoteEndPoint, IPEndPoint bindEndPoint, CancellationToken cancellationToken)
    {
        var client = new TcpClient(remoteEndPoint.AddressFamily);
        TcpRelayKey? flowKey = null;
        try
        {
            client.Client.Bind(bindEndPoint);
            flowKey = RegisterRelayOutboundFlow(client, remoteEndPoint);
            await client.ConnectAsync(remoteEndPoint, cancellationToken).ConfigureAwait(false);
            return new TcpConnectResult(client, flowKey);
        }
        catch
        {
            if (flowKey is { } key)
            {
                _relayOutboundFlows.TryRemove(key, out _);
            }

            client.Dispose();
            throw;
        }
    }

    private TcpRelayKey? RegisterRelayOutboundFlow(TcpClient outbound, IPEndPoint remoteEndPoint)
    {
        if (outbound.Client.LocalEndPoint is not IPEndPoint localEndPoint)
        {
            return null;
        }

        var key = new TcpRelayKey(remoteEndPoint.Address, (ushort)localEndPoint.Port, (ushort)remoteEndPoint.Port);
        _relayOutboundFlows[key] = 0;
        return key;
    }

    private static bool IsAddressContextFailure(SocketException ex)
    {
        return ex.SocketErrorCode is SocketError.AddressNotAvailable or SocketError.InvalidArgument;
    }

    private void LogCopyFailure(string direction, Task<long> task, TcpClientKey key, DirectRelayTarget target)
    {
        if (!task.IsFaulted)
        {
            return;
        }

        var message = task.Exception?.GetBaseException().Message ?? "unknown copy failure";
        LogDetail($"DIRECT TCP {direction} copy failed app={target.AppLabel} appLocal={target.ClientEndpoint} client={key.ClientAddress}:{key.ClientPort} target={target.RemoteEndpoint} relayProcess={Environment.ProcessId}: {message}");
    }

    private static async Task WaitForRelayCompletionAsync(Task<long> upstream, Task<long> downstream, Socket inbound, Socket outbound, CancellationToken cancellationToken)
    {
        var first = await Task.WhenAny(upstream, downstream).ConfigureAwait(false);
        if (first == upstream)
        {
            if (!await WaitForSecondDirectionAsync(downstream, cancellationToken, TimeSpan.FromSeconds(30)).ConfigureAwait(false))
            {
                TryShutdown(outbound, SocketShutdown.Send);
                await WaitForSecondDirectionAsync(downstream, cancellationToken, TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            }
        }
        else
        {
            TryShutdown(inbound, SocketShutdown.Send);
            await WaitForSecondDirectionAsync(upstream, cancellationToken, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        }

        ObserveCopyTask(upstream);
        ObserveCopyTask(downstream);
    }

    private static async Task<bool> WaitForSecondDirectionAsync(Task<long> task, CancellationToken cancellationToken, TimeSpan timeout)
    {
        if (task.IsCompleted)
        {
            return true;
        }

        try
        {
            await Task.WhenAny(task, Task.Delay(timeout, cancellationToken)).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        return task.IsCompleted;
    }

    private static void ObserveCopyTask(Task<long> task)
    {
        if (task.IsFaulted)
        {
            _ = task.Exception;
        }
    }

    private static void TryShutdown(Socket socket, SocketShutdown shutdown)
    {
        try
        {
            socket.Shutdown(shutdown);
        }
        catch
        {
        }
    }

    private async Task<long> CopyAndCountAsync(string direction, Stream source, Stream destination, Action<int> addBytes, TcpClientKey key, DirectRelayTarget target, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(81920);
        long total = 0;
        var loggedFirstChunk = false;
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return total;
                }

                if (!loggedFirstChunk)
                {
                    loggedFirstChunk = true;
                    LogDetail($"DIRECT TCP {direction} first-chunk app={target.AppLabel} appLocal={target.ClientEndpoint} client={key.ClientAddress}:{key.ClientPort} target={target.RemoteEndpoint} bytes={read} hex={FormatPreview(buffer.AsSpan(0, read))}");
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                addBytes(read);
                _packetWakeSignal?.Pulse();
                total += read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static string FormatPreview(ReadOnlySpan<byte> bytes)
    {
        var previewLength = Math.Min(bytes.Length, 24);
        return Convert.ToHexString(bytes[..previewLength]);
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
            CleanupExpiredTargets();
        }
    }

    private void CleanupExpiredTargets()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var pair in _targetsByClient)
        {
            if (now - pair.Value.CreatedAt > _targetTtl)
            {
                Remove(pair.Key);
            }
        }
    }

    public void Dispose()
    {
        _listener?.Stop();
        _targetsByClient.Clear();
        _clientsByFlow.Clear();
        _relayOutboundFlows.Clear();
    }

    private sealed class TcpRelayStats
    {
        private readonly object _sync = new();
        private readonly TcpClientKey _key;
        private readonly DirectRelayTarget _target;
        private readonly Action<string>? _log;
        private readonly TimeProvider _timeProvider;
        private DateTimeOffset _lastUpLog;
        private DateTimeOffset _lastDownLog;
        private DateTimeOffset _lastEndLog;
        private long _upBytes;
        private long _downBytes;

        public TcpRelayStats(TcpClientKey key, DirectRelayTarget target, Action<string>? log, TimeProvider timeProvider)
        {
            _key = key;
            _target = target;
            _log = log;
            _timeProvider = timeProvider;
        }

        public void AddUp(int bytes)
        {
            lock (_sync)
            {
                _upBytes += bytes;
                LogLocked("SEND", ref _lastUpLog, force: false);
            }
        }

        public void AddDown(int bytes)
        {
            lock (_sync)
            {
                _downBytes += bytes;
                LogLocked("RECV", ref _lastDownLog, force: false);
            }
        }

        public void Log(string direction, bool force)
        {
            lock (_sync)
            {
                LogLocked(direction, ref _lastEndLog, force);
            }
        }

        private void LogLocked(string direction, ref DateTimeOffset lastLog, bool force)
        {
            if (_log is null)
            {
                return;
            }

            var now = _timeProvider.GetUtcNow();
            if (!force && lastLog != default && now - lastLog < TimeSpan.FromSeconds(5))
            {
                return;
            }

            lastLog = now;
            _log($"DIRECT TCP {direction} app={_target.AppLabel} appLocal={_target.ClientEndpoint} client={_key.ClientAddress}:{_key.ClientPort} target={_target.RemoteEndpoint} relayProcess={Environment.ProcessId} up={_upBytes} down={_downBytes}");
        }
    }

    private readonly record struct TcpConnectResult(TcpClient Client, TcpRelayKey? FlowKey);
}
