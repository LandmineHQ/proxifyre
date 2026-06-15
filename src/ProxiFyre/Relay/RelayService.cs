using System.Diagnostics;
using System.IO;

namespace ProxiFyre;

internal sealed class RelayService : IDisposable, IAsyncDisposable
{
    private readonly Action<string> _log;
    private readonly Action<string> _trafficOutput;
    private readonly bool _detailedLogging;
    private readonly TimeProvider _timeProvider;
    private readonly TrafficCounter _trafficCounter = new();
    private readonly PacketWakeSignal _packetWakeSignal = new();
    private CancellationTokenSource? _cts;
    private DynamicAppConfiguration? _configuration;
    private TcpDirectRelay? _tcpRelay;
    private UdpDirectRelay? _udpRelay;
    private PacketFilterLoop? _filter;
    private Task? _filterTask;
    private Task? _trafficStatsTask;
    private Task? _configurationWatchTask;

    public RelayService(Action<string> log, bool detailedLogging = false, Action<string>? trafficOutput = null, TimeProvider? timeProvider = null)
    {
        _log = log;
        _trafficOutput = trafficOutput ?? log;
        _detailedLogging = detailedLogging;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public bool IsRunning => _filterTask is { IsCompleted: false };

    public Task Completion => _filterTask ?? Task.CompletedTask;

    public bool Reload(AppConfiguration configuration)
    {
        if (_configuration is null)
        {
            return false;
        }

        _configuration.Update(configuration);
        _log($"Configuration reloaded: coreProcessName={configuration.CoreProcessName}, apps={configuration.Apps.Count}");
        return true;
    }

    public void Start(AppConfiguration configuration, string? configurationPath = null, CancellationToken externalCancellationToken = default)
    {
        if (IsRunning)
        {
            return;
        }

        _log($"Configured core process name: {configuration.CoreProcessName}");
        _log($"Configured apps: {string.Join(", ", configuration.Apps)}");
        _log($"Relay socket owner process: {Process.GetCurrentProcess().ProcessName}.exe pid={Environment.ProcessId}");
        _log($"Detailed packet logging: {(_detailedLogging ? "enabled" : "disabled")}");
        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCancellationToken);
        _configuration = new DynamicAppConfiguration(configuration);
        _tcpRelay = new TcpDirectRelay(_log, _detailedLogging, _trafficCounter, _packetWakeSignal, _timeProvider);
        _udpRelay = new UdpDirectRelay(_log, _detailedLogging, _trafficCounter, _packetWakeSignal, _timeProvider);
        _tcpRelay.Start(_cts.Token);
        _udpRelay.Start(_cts.Token);
        _filter = new PacketFilterLoop(_configuration, _tcpRelay, _udpRelay, _packetWakeSignal, _log, _detailedLogging, _timeProvider);
        _filterTask = _filter.RunAsync(_cts.Token);
        _trafficStatsTask = Task.Run(() => ReportTrafficStatsAsync(_cts.Token), _cts.Token);
        if (!string.IsNullOrWhiteSpace(configurationPath))
        {
            _configurationWatchTask = Task.Run(() => WatchConfigurationAsync(Path.GetFullPath(configurationPath), _cts.Token), _cts.Token);
        }

        _ = WatchFilterTaskAsync(_filterTask, _cts);
    }

    private async Task WatchConfigurationAsync(string configurationPath, CancellationToken cancellationToken)
    {
        var lastKey = BuildConfigurationKey(_configuration?.Current);
        var lastWrite = GetLastWriteTime(configurationPath);
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500), _timeProvider);

        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            var currentWrite = GetLastWriteTime(configurationPath);
            if (currentWrite == lastWrite)
            {
                continue;
            }

            lastWrite = currentWrite;
            await Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken).ConfigureAwait(false);
            try
            {
                var configuration = AppConfiguration.Load(configurationPath);
                var key = BuildConfigurationKey(configuration);
                if (string.Equals(key, lastKey, StringComparison.Ordinal))
                {
                    continue;
                }

                _configuration?.Update(configuration);
                lastKey = key;
                _log($"Configuration hot reloaded: coreProcessName={configuration.CoreProcessName}, apps={configuration.Apps.Count}");
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                _log($"Configuration hot reload failed: {ex.Message}");
            }
        }
    }

    private static DateTimeOffset GetLastWriteTime(string path)
    {
        return File.Exists(path)
            ? File.GetLastWriteTimeUtc(path)
            : DateTimeOffset.MinValue;
    }

    private static string BuildConfigurationKey(AppConfiguration? configuration)
    {
        if (configuration is null)
        {
            return string.Empty;
        }

        return AppConfiguration.NormalizeCoreProcessName(configuration.CoreProcessName)
            + "\n"
            + string.Join("\n", configuration.Apps.Order(StringComparer.OrdinalIgnoreCase));
    }

    private async Task ReportTrafficStatsAsync(CancellationToken cancellationToken)
    {
        var previous = TrafficSnapshot.Empty;
        var previousTime = _timeProvider.GetUtcNow();
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1), _timeProvider);

        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            var now = _timeProvider.GetUtcNow();
            var elapsed = Math.Max(0.001, (now - previousTime).TotalSeconds);
            var snapshot = _trafficCounter.Snapshot(previous.UploadBytes, previous.DownloadBytes, elapsed);
            previous = snapshot;
            previousTime = now;
            _trafficOutput($"TRAFFIC up={snapshot.UploadBytes} down={snapshot.DownloadBytes} upRate={snapshot.UploadBytesPerSecond} downRate={snapshot.DownloadBytesPerSecond}");
        }
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
        if (_trafficStatsTask is not null)
        {
            try
            {
                await _trafficStatsTask.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch
            {
            }
        }

        if (_configurationWatchTask is not null)
        {
            try
            {
                await _configurationWatchTask.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch
            {
            }
        }

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
        _configuration = null;
        _cts = null;
        _filterTask = null;
        _trafficStatsTask = null;
        _configurationWatchTask = null;
        _log("Stopped.");
    }

    public void Stop()
    {
        StopAsync().GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        Stop();
        _packetWakeSignal.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _packetWakeSignal.Dispose();
    }
}
