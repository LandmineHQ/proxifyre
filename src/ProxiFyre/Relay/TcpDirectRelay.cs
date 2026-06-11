using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace ProxiFyre;

internal sealed class TcpDirectRelay : IDisposable
{
    private readonly ConcurrentDictionary<TcpClientKey, DirectRelayTarget> _targets = new();
    private readonly TimeSpan _targetTtl = TimeSpan.FromMinutes(5);
    private readonly Action<string> _log;
    private readonly TimeProvider _timeProvider;
    private TcpListener? _listener;

    public TcpDirectRelay(Action<string>? log = null, TimeProvider? timeProvider = null)
    {
        _log = log ?? Console.WriteLine;
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

        _log($"Local direct TCP relay listening on [::]:{Port}");
        _ = Task.Run(() => AcceptLoopAsync(_listener, cancellationToken), cancellationToken);
        _ = Task.Run(() => CleanupLoopAsync(cancellationToken), cancellationToken);
    }

    public void Register(TcpClientKey key, IPAddress remoteAddress, ushort remotePort)
    {
        _targets[key] = new DirectRelayTarget(remoteAddress, remotePort, _timeProvider.GetUtcNow());
    }

    public bool Refresh(TcpClientKey key)
    {
        if (!_targets.TryGetValue(key, out var target))
        {
            return false;
        }

        _targets[key] = target with { CreatedAt = _timeProvider.GetUtcNow() };
        return true;
    }

    public bool HasTarget(TcpClientKey key)
    {
        return _targets.ContainsKey(key);
    }

    public bool TryGetTarget(TcpClientKey key, out DirectRelayTarget target)
    {
        return _targets.TryGetValue(key, out target!);
    }

    public void Remove(TcpClientKey key)
    {
        _targets.TryRemove(key, out _);
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
        if (!_targets.TryGetValue(key, out var target))
        {
            _log($"No direct target found for redirected client {key.ClientAddress}:{key.ClientPort}");
            return;
        }

        using var outbound = new TcpClient(target.RemoteAddress.AddressFamily);
        try
        {
            await outbound.ConnectAsync(target.RemoteAddress, target.RemotePort, cancellationToken).ConfigureAwait(false);
            _log($"DIRECT TCP {key.ClientAddress}:{key.ClientPort} -> {target}");

            await using var inboundStream = inbound.GetStream();
            await using var outboundStream = outbound.GetStream();
            var upstream = inboundStream.CopyToAsync(outboundStream, cancellationToken);
            var downstream = outboundStream.CopyToAsync(inboundStream, cancellationToken);

            await Task.WhenAny(upstream, downstream).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _log($"DIRECT TCP {key.ClientAddress}:{key.ClientPort} -> {target} failed: {ex.Message}");
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
        foreach (var pair in _targets)
        {
            if (now - pair.Value.CreatedAt > _targetTtl)
            {
                _targets.TryRemove(pair.Key, out _);
            }
        }
    }

    public void Dispose()
    {
        _listener?.Stop();
        _targets.Clear();
    }
}
