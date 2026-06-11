namespace ProxiFyre;

internal sealed class RelayService : IDisposable, IAsyncDisposable
{
    private readonly Action<string> _log;
    private readonly TimeProvider _timeProvider;
    private CancellationTokenSource? _cts;
    private TcpDirectRelay? _tcpRelay;
    private UdpDirectRelay? _udpRelay;
    private PacketFilterLoop? _filter;
    private Task? _filterTask;

    public RelayService(Action<string> log, TimeProvider? timeProvider = null)
    {
        _log = log;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public bool IsRunning => _filterTask is { IsCompleted: false };

    public Task Completion => _filterTask ?? Task.CompletedTask;

    public void Start(AppConfiguration configuration, CancellationToken externalCancellationToken = default)
    {
        if (IsRunning)
        {
            return;
        }

        if (configuration.Apps.Count == 0)
        {
            throw new InvalidOperationException("No applications are configured.");
        }

        _log($"Configured core process name: {configuration.CoreProcessName}");
        _log($"Configured apps: {string.Join(", ", configuration.Apps)}");
        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCancellationToken);
        _tcpRelay = new TcpDirectRelay(_log, _timeProvider);
        _udpRelay = new UdpDirectRelay(_log, _timeProvider);
        _tcpRelay.Start(_cts.Token);
        _udpRelay.Start(_cts.Token);
        _filter = new PacketFilterLoop(configuration, _tcpRelay, _udpRelay, _log, _timeProvider);
        _filterTask = _filter.RunAsync(_cts.Token);
        _ = WatchFilterTaskAsync(_filterTask, _cts);
    }

    private async Task WatchFilterTaskAsync(Task filterTask, CancellationTokenSource cts)
    {
        try
        {
            await filterTask.ConfigureAwait(false);
            if (!cts.IsCancellationRequested)
            {
                _log("Packet filter stopped unexpectedly.");
                cts.Cancel();
            }
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _log($"Packet filter failed: {ex}");
            cts.Cancel();
        }
    }

    public async Task StopAsync()
    {
        _cts?.Cancel();
        if (_filterTask is not null)
        {
            try
            {
                await _filterTask.WaitAsync(TimeSpan.FromSeconds(3));
            }
            catch
            {
            }
        }

        _filter?.Dispose();
        _udpRelay?.Dispose();
        _tcpRelay?.Dispose();
        _cts?.Dispose();
        _filter = null;
        _udpRelay = null;
        _tcpRelay = null;
        _cts = null;
        _filterTask = null;
        _log("Stopped.");
    }

    public void Stop()
    {
        StopAsync().GetAwaiter().GetResult();
    }

    public void Dispose() => Stop();

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
    }
}
