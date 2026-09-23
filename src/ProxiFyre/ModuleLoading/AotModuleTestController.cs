namespace ProxiFyre;

public sealed class AotModuleTestController : IDisposable
{
    private readonly TaskCompletionSource<bool> _running = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly AotModuleController _controller;
    private readonly Action<string> _log;

    public AotModuleTestController(
        string configPath,
        string moduleLogPath,
        Action<string> log,
        bool detailedLogging = false)
    {
        _log = log;
        var configurationStore = new ConfigurationStore(configPath);
        _controller = new AotModuleController(
            configurationStore,
            log,
            ApplyModuleEvent,
            moduleLogPath,
            detailedLogging: detailedLogging);
    }

    public async Task LoadAndRunAsync(
        int targetProcessId,
        string targetProcessName,
        string? targetProcessPath,
        IEnumerable<string> apps,
        string licenseKey,
        CancellationToken cancellationToken)
    {
        var target = new ModuleTargetProcess(targetProcessId, targetProcessName, targetProcessPath);
        var result = await _controller.LoadAndRunAsync(
            target,
            targetProcessName,
            apps,
            (_, _) => licenseKey).ConfigureAwait(false);

        if (result != ModuleStartResult.Started)
        {
            throw new InvalidOperationException("AOT module load was canceled.");
        }

        using var registration = cancellationToken.Register(() => _running.TrySetCanceled(cancellationToken));
        await _running.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        _controller.Dispose();
    }

    private void ApplyModuleEvent(ModuleEvent moduleEvent)
    {
        if (!string.IsNullOrWhiteSpace(moduleEvent.Text))
        {
            _log($"module {moduleEvent.EventName}: {moduleEvent.Text}");
        }

        if (moduleEvent.Running == true)
        {
            _running.TrySetResult(true);
        }
    }
}
