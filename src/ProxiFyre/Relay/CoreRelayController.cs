namespace ProxiFyre;

internal sealed class CoreRelayController : IDisposable
{
    private readonly CoreProcessHost _coreProcessHost;
    private readonly ConfigurationStore _configurationStore;
    private readonly WinpkFilterManager _winpkFilterManager;
    private readonly Action<string> _log;

    public CoreRelayController(ConfigurationStore configurationStore, WinpkFilterManager winpkFilterManager, Action<string> log, Action stopped)
    {
        _configurationStore = configurationStore;
        _winpkFilterManager = winpkFilterManager;
        _log = log;
        _coreProcessHost = new CoreProcessHost(log, stopped);
    }

    public bool IsRunning => _coreProcessHost.IsRunning;

    public string? ProcessName => _coreProcessHost.ProcessName;

    public int? ProcessId => _coreProcessHost.ProcessId;

    public async Task StopAsync()
    {
        await _coreProcessHost.StopAsync().ConfigureAwait(false);
    }

    public async Task<CoreRelayStartResult> StartAsync(
        string coreProcessName,
        IEnumerable<string> apps,
        Func<string, string?, string?> requestLicenseKey)
    {
        _configurationStore.Save(coreProcessName, apps);
        var configuration = _configurationStore.Load();
        var deviceId = LicenseKey.GetCurrentDeviceId();
        if (!LicenseKey.IsValid(deviceId, configuration.LicenseKey))
        {
            var licenseKey = requestLicenseKey(deviceId, configuration.LicenseKey);
            if (licenseKey is null)
            {
                _log("Start canceled: license key is missing or invalid.");
                return CoreRelayStartResult.Canceled;
            }

            _configurationStore.SaveLicenseKey(coreProcessName, apps, licenseKey);
            configuration = _configurationStore.Load();
            _log("License key saved.");
        }

        await _winpkFilterManager.EnsureInstalledAsync().ConfigureAwait(false);
        _coreProcessHost.Start(_configurationStore.Path, configuration.CoreProcessName);
        _log("Started direct relay core.");
        return CoreRelayStartResult.Started;
    }

    public CoreProcessDisplayInfo GetDisplayInfo(string configuredCoreProcessName)
    {
        if (IsRunning)
        {
            var processName = ProcessName ?? AppConfiguration.NormalizeCoreProcessName(configuredCoreProcessName);
            var text = ProcessId is null
                ? processName
                : $"{processName}  pid={ProcessId}";
            return new CoreProcessDisplayInfo(
                text,
                $"任务管理器中请观察 {processName}，relay 出站 socket 归属于该进程。");
        }

        var configuredName = AppConfiguration.NormalizeCoreProcessName(configuredCoreProcessName);
        return new CoreProcessDisplayInfo(
            $"未运行，启动后为 {configuredName}",
            "启动后查看核心进程，而不是 UI 的 ProxiFyre 进程。");
    }

    public void Dispose()
    {
        _coreProcessHost.Dispose();
    }
}

internal enum CoreRelayStartResult
{
    Canceled,
    Started
}

internal sealed record CoreProcessDisplayInfo(string Text, string NetworkOwnerHint);
