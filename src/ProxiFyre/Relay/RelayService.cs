using System.IO;

namespace ProxiFyre;

internal sealed class RelayService : IDisposable, IAsyncDisposable
{
    private readonly Action<string> _log;
    private readonly Action<string> _warningLog;
    private readonly Action<TrafficSnapshot>? _trafficSink;
    private readonly DetailedLoggingState _detailedLogging;
    private readonly TimeProvider _timeProvider;
    private readonly ProcessLookup _processLookup;
    private readonly TrafficCounter _trafficCounter = new();
    private readonly PacketWakeSignal _packetWakeSignal = new();
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private CancellationTokenSource? _cts;
    private DynamicAppConfiguration? _configuration;
    private WinDivertPacketRouter? _router;
    private Task? _routerTask;
    private Task? _trafficStatsTask;
    private Task? _configurationWatchTask;

    public RelayService(
        Action<string> log,
        bool detailedLogging = false,
        Action<TrafficSnapshot>? trafficSink = null,
        TimeProvider? timeProvider = null,
        Action<string>? warningLog = null)
    {
        _log = log;
        _warningLog = warningLog ?? log;
        _trafficSink = trafficSink;
        _detailedLogging = new DetailedLoggingState(detailedLogging);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _processLookup = new ProcessLookup(log, _timeProvider, warningLog: _warningLog);
    }

    public bool IsRunning => _routerTask is { IsCompleted: false };

    public Task Completion => _routerTask ?? Task.CompletedTask;

    public bool Reload(AppConfiguration configuration)
    {
        if (_configuration is null)
        {
            return false;
        }

        _detailedLogging.Update(configuration.Detailed);
        _configuration.Update(configuration);
        _router?.ApplyConfiguration();
        _log(
            $"Configuration reloaded: coreProcessName={configuration.CoreProcessName}, apps={configuration.Apps.Count}, detailed={configuration.Detailed}");
        return true;
    }

    public void Start(
        AppConfiguration configuration,
        string? configurationPath = null,
        CancellationToken externalCancellationToken = default,
        string? nativeDirectory = null,
        nint networkHandle = 0,
        nint flowHandle = 0)
    {
        _lifecycleGate.Wait();
        try
        {
            StartCore(
                configuration,
                configurationPath,
                externalCancellationToken,
                nativeDirectory,
                networkHandle,
                flowHandle);
        }
        catch
        {
            StopCoreAsync().GetAwaiter().GetResult();
            throw;
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    private void StartCore(
        AppConfiguration configuration,
        string? configurationPath,
        CancellationToken externalCancellationToken,
        string? nativeDirectory,
        nint networkHandle,
        nint flowHandle)
    {
        if (IsRunning || _router is not null || _cts is not null)
        {
            return;
        }

        _log($"Configured core process name: {configuration.CoreProcessName}");
        _log($"Configured apps: {string.Join(", ", configuration.Apps)}");
        _log($"WinDivert relay process: {Environment.ProcessPath} pid={Environment.ProcessId}");
        _log($"Detailed packet logging: {(_detailedLogging.Enabled ? "enabled" : "disabled")}");

        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCancellationToken);
        _configuration = new DynamicAppConfiguration(configuration);
        _router = new WinDivertPacketRouter(
            configuration: _configuration,
            processLookup: _processLookup,
            log: _log,
            trafficCounter: _trafficCounter,
            packetWakeSignal: _packetWakeSignal,
            timeProvider: _timeProvider,
            detailedLogging: _detailedLogging.Enabled,
            detailedLoggingState: _detailedLogging,
            warningLog: _warningLog);
        _router.Start(
            nativeDirectory,
            _cts.Token,
            networkHandle != 0 ? new WinDivertHandle(networkHandle) : null,
            flowHandle != 0 ? new WinDivertHandle(flowHandle) : null);
        _routerTask = _router.Completion;

        _trafficStatsTask = Task.Run(
            () => ReportTrafficStatsAsync(_cts.Token),
            CancellationToken.None);
        if (!string.IsNullOrWhiteSpace(configurationPath))
        {
            _configurationWatchTask = Task.Run(
                () => WatchConfigurationAsync(Path.GetFullPath(configurationPath), _cts.Token),
                CancellationToken.None);
        }

        _ = WatchRouterTaskAsync(_routerTask, _cts);
    }

    private async Task WatchRouterTaskAsync(Task routerTask, CancellationTokenSource cts)
    {
        var unexpectedStop = false;
        try
        {
            await routerTask.ConfigureAwait(false);
            if (!cts.IsCancellationRequested)
            {
                _log("WinDivert packet router stopped unexpectedly.");
                unexpectedStop = true;
            }
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _log($"WinDivert relay failed: {ex}");
            unexpectedStop = true;
        }
        finally
        {
            if (unexpectedStop)
            {
                try
                {
                    await StopAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _warningLog(
                        $"WinDivert relay cleanup after data-plane failure failed: {ex.Message}");
                }
            }
        }
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

                Reload(configuration);
                lastKey = key;
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                _warningLog(
                    $"Configuration hot reload failed; keeping the active configuration: {ex.Message}");
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
            + string.Join("\n", configuration.Apps.Order(StringComparer.OrdinalIgnoreCase))
            + "\n--detailed--\n"
            + configuration.Detailed;
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
            var snapshot = _trafficCounter.Snapshot(previous, elapsed);
            previous = snapshot;
            previousTime = now;
            _trafficSink?.Invoke(snapshot);
        }
    }

    public async Task StopAsync()
    {
        await _lifecycleGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await StopCoreAsync().ConfigureAwait(false);
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    private async Task StopCoreAsync()
    {
        if (_cts is null && _router is null)
        {
            return;
        }

        _cts?.Cancel();
        var stopped =
            await WaitForTaskAsync(_trafficStatsTask, "traffic stats").ConfigureAwait(false)
            && await WaitForTaskAsync(_configurationWatchTask, "configuration watcher").ConfigureAwait(false)
            && await WaitForTaskAsync(_routerTask, "WinDivert router").ConfigureAwait(false);
        if (!stopped)
        {
            throw new TimeoutException("WinDivert relay tasks did not stop before the shutdown deadline.");
        }

        if (_router is not null)
        {
            await _router.DisposeAsync().ConfigureAwait(false);
        }

        _cts?.Dispose();
        _routerTask = null;
        _trafficStatsTask = null;
        _configurationWatchTask = null;
        _router = null;
        _configuration = null;
        _cts = null;
        _log("Stopped.");
    }

    private async Task<bool> WaitForTaskAsync(Task? task, string name)
    {
        if (task is null)
        {
            return true;
        }

        try
        {
            await task.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
            return true;
        }
        catch (TimeoutException)
        {
            _warningLog($"WinDivert relay shutdown timed out waiting for the {name}.");
            return false;
        }
        catch
        {
            return true;
        }
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
        await StopAsync().ConfigureAwait(false);
        _packetWakeSignal.Dispose();
    }
}
