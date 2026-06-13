namespace ProxiFyre;

internal sealed class WinpkFilterManager
{
    private readonly Action<string> _log;
    private WinpkFilterStatus _status = new(false, "检查中", "正在检查安装状态...", null);

    public WinpkFilterManager(Action<string> log)
    {
        _log = log;
    }

    public event EventHandler<WinpkFilterStatus>? StatusChanged;

    public WinpkFilterStatus Status => _status;

    public WinpkFilterStatus RefreshStatus()
    {
        return SetStatus(WinpkFilterDependency.GetStatus());
    }

    public async Task EnsureInstalledAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await WinpkFilterDependency.EnsureInstalledAsync(_log, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            RefreshStatus();
        }
    }

    public async Task UninstallAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await WinpkFilterDependency.UninstallAsync(_log, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            RefreshStatus();
        }
    }

    private WinpkFilterStatus SetStatus(WinpkFilterStatus status)
    {
        _status = status;
        StatusChanged?.Invoke(this, status);
        return status;
    }
}
