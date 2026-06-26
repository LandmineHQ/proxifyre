using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ProxiFyre;

internal sealed class AotModuleController : IDisposable
{
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan HeartbeatSendTimeout = TimeSpan.FromSeconds(1);

    private readonly ConfigurationStore _configurationStore;
    private readonly WinpkFilterManager _winpkFilterManager;
    private readonly Action<string> _log;
    private readonly Action<ModuleEvent> _moduleEvent;
    private readonly object _heartbeatLock = new();
    private ModuleMessageClient? _messageClient;
    private Timer? _heartbeatTimer;
    private readonly List<nint> _hookHandles = [];
    private nint _moduleWindow;
    private ModuleTargetProcess? _targetProcess;
    private string? _runtimeDllPath;
    private readonly string? _moduleLogPath;
    private bool _relayRunning;
    private bool _disposed;
    private bool _heartbeatInProgress;
    private bool _heartbeatLossReported;
    private int _missedHeartbeats;

    public AotModuleController(
        ConfigurationStore configurationStore,
        WinpkFilterManager winpkFilterManager,
        Action<string> log,
        Action<ModuleEvent> moduleEvent,
        string? moduleLogPath = null)
    {
        _configurationStore = configurationStore;
        _winpkFilterManager = winpkFilterManager;
        _log = log;
        _moduleEvent = moduleEvent;
        _moduleLogPath = moduleLogPath;
    }

    public bool IsRunning => _relayRunning;

    public string? ProcessName => _targetProcess?.ProcessName;

    public int? ProcessId => _targetProcess?.ProcessId;

    public void ApplyModuleEvent(ModuleEvent moduleEvent)
    {
        _missedHeartbeats = 0;
        _heartbeatLossReported = false;

        if (moduleEvent.Running is not null)
        {
            _relayRunning = moduleEvent.Running.Value;
        }

        if (moduleEvent.ProcessId is not null && _targetProcess is { } target)
        {
            _targetProcess = target with { ProcessId = moduleEvent.ProcessId.Value };
        }

        _moduleEvent(moduleEvent);
    }

    public Task<ModuleAttachResult> TryAttachExistingAsync(string targetProcessName, CancellationToken cancellationToken = default)
    {
        return Task.Run(() => TryAttachExisting(targetProcessName), cancellationToken);
    }

    public async Task<ModuleStartResult> LoadAndRunAsync(
        string targetProcessName,
        IEnumerable<string> apps,
        Func<string, string?, string?> requestLicenseKey)
    {
        return await LoadAndRunCoreAsync(null, targetProcessName, apps, requestLicenseKey).ConfigureAwait(false);
    }

    internal async Task<ModuleStartResult> LoadAndRunAsync(
        ModuleTargetProcess targetProcess,
        string targetProcessName,
        IEnumerable<string> apps,
        Func<string, string?, string?> requestLicenseKey)
    {
        return await LoadAndRunCoreAsync(targetProcess, targetProcessName, apps, requestLicenseKey).ConfigureAwait(false);
    }

    private async Task<ModuleStartResult> LoadAndRunCoreAsync(
        ModuleTargetProcess? explicitTargetProcess,
        string targetProcessName,
        IEnumerable<string> apps,
        Func<string, string?, string?> requestLicenseKey)
    {
        _configurationStore.Save(targetProcessName, apps);
        var configuration = _configurationStore.Load();
        var target = ResolveModuleTarget(explicitTargetProcess, configuration.CoreProcessName);

        var deviceId = LicenseKey.GetCurrentDeviceId();
        if (!LicenseKey.IsValid(deviceId, configuration.LicenseKey))
        {
            var licenseKey = requestLicenseKey(deviceId, configuration.LicenseKey);
            if (licenseKey is null)
            {
                _log("Module load canceled: license key is missing or invalid.");
                return ModuleStartResult.Canceled;
            }

            _configurationStore.SaveLicenseKey(targetProcessName, apps, licenseKey);
            configuration = _configurationStore.Load();
            _log("License key saved.");
        }

        await _winpkFilterManager.EnsureInstalledAsync().ConfigureAwait(false);

        _targetProcess = target;
        _log($"Selected module target: {target.ProcessName} pid={target.ProcessId}");
        if (!string.IsNullOrWhiteSpace(target.ProcessPath))
        {
            _log($"Target path: {target.ProcessPath}");
        }

        EnsureMessageClient();
        var moduleWindow = TryFindModuleWindow(target.ProcessId);
        if (moduleWindow == nint.Zero)
        {
            _runtimeDllPath = PrepareRuntimeModuleDll(configuration.ModuleDllName);
            ClearHookHandles();
            moduleWindow = await InstallGetMessageHooksAndWaitAsync(target.ProcessId, _runtimeDllPath).ConfigureAwait(false);
        }
        else
        {
            _log($"Existing module message window found for pid={target.ProcessId}.");
        }

        if (moduleWindow == nint.Zero)
        {
            ClearHookHandles();
            throw new InvalidOperationException("模组已尝试注入，但未找到模组消息窗口。请确认目标进程存在正在泵消息的 GUI 线程；WH_GETMESSAGE 只能在处理消息循环的线程中触发。");
        }

        _moduleWindow = moduleWindow;
        if (!SendCommand("RUN"))
        {
            throw new InvalidOperationException("模组收到 RUN 命令后返回失败，relay 未启动。请查看 proxifyre-core.log。");
        }

        StartHeartbeat();
        return ModuleStartResult.Started;
    }

    public void Reload()
    {
        if (_moduleWindow == nint.Zero)
        {
            _log("模组尚未载入，无法发送重载命令。");
            return;
        }

        if (!SendCommand("RELOAD"))
        {
            _log("模组重载命令返回失败。");
        }
    }

    public void StopRelay()
    {
        if (_moduleWindow != nint.Zero)
        {
            _ = SendCommand("STOP", TimeSpan.FromSeconds(2));
        }

        _relayRunning = false;
    }

    public ModuleProcessDisplayInfo GetDisplayInfo(string configuredTargetProcessName)
    {
        if (_targetProcess is { } target)
        {
            if (!ModuleProcessLocator.IsProcessAlive(target.ProcessId))
            {
                return new ModuleProcessDisplayInfo(
                    $"目标进程已退出: {target.ProcessName}  pid={target.ProcessId}",
                    "请先重新启动目标进程，然后再载入模组。");
            }

            if (_moduleWindow == nint.Zero)
            {
                return new ModuleProcessDisplayInfo(
                    $"目标进程存在，但未连接到模组: {target.ProcessName}  pid={target.ProcessId}",
                    "如果该进程已载入过 AOT DLL，UI 会继续尝试重连；否则点击载入模组进行注入。");
            }

            var state = _relayRunning ? "已载入并运行" : "已载入，转发已停止";
            return new ModuleProcessDisplayInfo(
                $"{state}: {target.ProcessName}  pid={target.ProcessId}",
                $"网络出站 socket 归属于目标进程 {target.ProcessName}；AOT DLL 会保留到该进程退出。");
        }

        var configuredName = AppConfiguration.NormalizeCoreProcessName(configuredTargetProcessName);
        return new ModuleProcessDisplayInfo(
            $"未载入，目标进程名为 {configuredName}",
            "点击载入模组后，将从同名进程中选择第一个可直接触发 WH_GETMESSAGE 的 GUI 进程。");
    }

    private void EnsureMessageClient()
    {
        _messageClient ??= new ModuleMessageClient(ApplyModuleEvent);
    }

    private ModuleAttachResult TryAttachExisting(string targetProcessName)
    {
        if (_disposed)
        {
            return ModuleAttachResult.NotLoaded;
        }

        var candidates = ModuleProcessLocator.FindAllByConfiguredName(targetProcessName);
        if (candidates.Count == 0)
        {
            _targetProcess = null;
            _moduleWindow = nint.Zero;
            _relayRunning = false;
            StopHeartbeat();
            return ModuleAttachResult.TargetProcessMissing;
        }

        EnsureMessageClient();

        foreach (var candidate in candidates)
        {
            var moduleWindow = TryFindModuleWindow(candidate.ProcessId);
            if (moduleWindow == nint.Zero)
            {
                continue;
            }

            _targetProcess = candidate;
            _moduleWindow = moduleWindow;
            _log($"Existing module message window found for pid={candidate.ProcessId}.");

            if (!SendCommand("PING", TimeSpan.FromSeconds(2)))
            {
                _relayRunning = false;
                return ModuleAttachResult.Unresponsive;
            }

            StartHeartbeat();
            return ModuleAttachResult.Attached;
        }

        _targetProcess = SelectPreferredModuleTarget(candidates);
        _moduleWindow = nint.Zero;
        _relayRunning = false;
        StopHeartbeat();
        return ModuleAttachResult.NotLoaded;
    }

    private ModuleTargetProcess ResolveModuleTarget(ModuleTargetProcess? explicitTargetProcess, string configuredProcessName)
    {
        if (explicitTargetProcess is not null)
        {
            return explicitTargetProcess;
        }

        var candidates = ModuleProcessLocator.FindAllByConfiguredName(configuredProcessName);
        if (candidates.Count == 0)
        {
            var processName = AppConfiguration.NormalizeCoreProcessName(configuredProcessName);
            throw new InvalidOperationException($"未找到模组目标进程：{processName}");
        }

        return SelectPreferredModuleTarget(candidates);
    }

    private ModuleTargetProcess SelectPreferredModuleTarget(IReadOnlyList<ModuleTargetProcess> candidates)
    {
        var summaries = candidates
            .Select(candidate => new ModuleTargetCandidate(candidate, GetHookTargetSummary(candidate.ProcessId)))
            .OrderBy(candidate => candidate.Summary.Rank)
            .ThenBy(candidate => candidate.Target.ProcessId)
            .ToArray();

        var selected = summaries[0];
        var minimumPid = candidates[0];
        if (selected.Target.ProcessId != minimumPid.ProcessId)
        {
            var minimumSummary = summaries.First(candidate => candidate.Target.ProcessId == minimumPid.ProcessId).Summary;
            _log($"Selected hookable module target instead of minimum pid: skipped pid={minimumPid.ProcessId} ({minimumSummary.Description}); selected pid={selected.Target.ProcessId} ({selected.Summary.Description}).");
        }

        return selected.Target;
    }

    private bool SendCommand(string command)
    {
        return SendCommand(command, null);
    }

    private bool SendCommand(string command, TimeSpan? timeout)
    {
        if (_moduleWindow == nint.Zero || _messageClient is null)
        {
            throw new InvalidOperationException("Module message channel is not ready.");
        }

        var payload = ModuleMessageProtocol.BuildCommand(
            command,
            Path.GetFullPath(_configurationStore.Path),
            _moduleLogPath ?? Path.Combine(AppContext.BaseDirectory, "proxifyre-core.log"),
            _messageClient.WindowHandle);

        return timeout is { } value
            ? _messageClient.SendCommand(_moduleWindow, payload, value)
            : _messageClient.SendCommand(_moduleWindow, payload);
    }

    private void StartHeartbeat()
    {
        lock (_heartbeatLock)
        {
            if (_disposed)
            {
                return;
            }

            _heartbeatTimer ??= new Timer(HeartbeatTimerCallback, null, HeartbeatInterval, HeartbeatInterval);
        }
    }

    private void StopHeartbeat()
    {
        Timer? timer;
        lock (_heartbeatLock)
        {
            timer = _heartbeatTimer;
            _heartbeatTimer = null;
            _heartbeatInProgress = false;
            _missedHeartbeats = 0;
            _heartbeatLossReported = false;
        }

        timer?.Dispose();
    }

    private void HeartbeatTimerCallback(object? state)
    {
        lock (_heartbeatLock)
        {
            if (_disposed || _heartbeatInProgress)
            {
                return;
            }

            _heartbeatInProgress = true;
        }

        try
        {
            CheckHeartbeat();
        }
        finally
        {
            lock (_heartbeatLock)
            {
                _heartbeatInProgress = false;
            }
        }
    }

    private void CheckHeartbeat()
    {
        var target = _targetProcess;
        if (target is null || _messageClient is null)
        {
            StopHeartbeat();
            return;
        }

        if (!ModuleProcessLocator.IsProcessAlive(target.ProcessId))
        {
            ClearConnection($"目标进程已退出，已断开模组连接: {target.ProcessName} pid={target.ProcessId}", target);
            return;
        }

        if (_moduleWindow == nint.Zero)
        {
            _moduleWindow = TryFindModuleWindow(target.ProcessId);
        }

        var heartbeatSent = false;
        if (_moduleWindow != nint.Zero)
        {
            try
            {
                heartbeatSent = SendCommand("HEARTBEAT", HeartbeatSendTimeout);
            }
            catch
            {
                heartbeatSent = false;
            }
        }

        if (heartbeatSent)
        {
            _missedHeartbeats = 0;
            _heartbeatLossReported = false;
            return;
        }

        _moduleWindow = TryFindModuleWindow(target.ProcessId);
        if (_moduleWindow != nint.Zero)
        {
            try
            {
                heartbeatSent = SendCommand("HEARTBEAT", HeartbeatSendTimeout);
            }
            catch
            {
                heartbeatSent = false;
            }

            if (heartbeatSent)
            {
                _missedHeartbeats = 0;
                _heartbeatLossReported = false;
                _log($"Reconnected to module message window for pid={target.ProcessId}.");
                return;
            }
        }

        _missedHeartbeats++;
        if (_missedHeartbeats < 2 || _heartbeatLossReported)
        {
            return;
        }

        _heartbeatLossReported = true;
        _relayRunning = false;
        _moduleEvent(new ModuleEvent(
            "lost",
            $"UI 与 relay 模组心跳中断，但目标进程仍存在: {target.ProcessName} pid={target.ProcessId}",
            false,
            target.ProcessId));
    }

    private void ClearConnection(string message, ModuleTargetProcess target)
    {
        _targetProcess = null;
        _moduleWindow = nint.Zero;
        _relayRunning = false;
        StopHeartbeat();
        _moduleEvent(new ModuleEvent("lost", message, false, target.ProcessId));
    }

    private static string PrepareRuntimeModuleDll(string dllName)
    {
        var nativeDll = FindNativeModuleDll(dllName);
        var configuration = GetConfigurationName(nativeDll);
        var runtimeDirectory = Path.Combine(AppContext.BaseDirectory, "runtime", configuration);
        Directory.CreateDirectory(runtimeDirectory);
        var baseName = Path.GetFileNameWithoutExtension(dllName);
        var runtimeDll = Path.Combine(runtimeDirectory, $"{baseName}_{DateTime.Now:yyyyMMdd_HHmmss_fff}.dll");
        File.Copy(nativeDll, runtimeDll, overwrite: true);
        return runtimeDll;
    }

    private static string FindNativeModuleDll(string dllName)
    {
        var baseDirectory = AppContext.BaseDirectory;
        var preferredConfiguration = GetPreferredConfigurationName(baseDirectory);
        var alternateConfiguration = preferredConfiguration.Equals("Release", StringComparison.OrdinalIgnoreCase)
            ? "Debug"
            : "Release";
        var candidates = new[]
        {
            Path.Combine(baseDirectory, dllName),
            Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "..", "native", preferredConfiguration, dllName)),
            Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "native", preferredConfiguration, dllName)),
            Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "..", "native", alternateConfiguration, dllName)),
            Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "native", alternateConfiguration, dllName)),
        };

        var existing = candidates
            .Where(File.Exists)
            .FirstOrDefault();

        if (existing is not null)
        {
            return existing;
        }

        throw new FileNotFoundException($"未找到 {dllName}。请先执行 build/publish 生成 AOT 模组。", candidates[0]);
    }

    private static string GetPreferredConfigurationName(string baseDirectory)
    {
        var directoryName = Path.GetFileName(baseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return directoryName.StartsWith("release_", StringComparison.OrdinalIgnoreCase)
            ? "Release"
            : "Debug";
    }

    private static string GetConfigurationName(string nativeDll)
    {
        var parent = Directory.GetParent(nativeDll);
        return parent?.Name is "Debug" or "Release" ? parent.Name : "Debug";
    }

    private async Task<nint> InstallGetMessageHooksAndWaitAsync(int targetProcessId, string dllPath)
    {
        var hookTargets = FindHookTargetsByProcessId(targetProcessId).ToArray();
        var windowThreadCount = hookTargets.Count(target => target.HasWindow);

        _log($"Injection: target process pid={targetProcessId}, window threads={windowThreadCount}, all threads={hookTargets.Length}");

        bool remoteThreadAttempted = false;
        string remoteThreadError = string.Empty;

        // If target has no window threads, it's a daemon/background process. Inject via CreateRemoteThread directly.
        if (windowThreadCount == 0 || hookTargets.Length == 0)
        {
            _log("Target process has no window threads. Attempting injection via CreateRemoteThread...");
            remoteThreadAttempted = true;
            if (InjectDllViaCreateRemoteThread(targetProcessId, dllPath, out remoteThreadError))
            {
                _log("CreateRemoteThread injection succeeded. Waiting for module message window...");
                var moduleWindow = await WaitForModuleWindowAsync(targetProcessId, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                if (moduleWindow != nint.Zero)
                {
                    _log("Module message window found via CreateRemoteThread injection.");
                    return moduleWindow;
                }
                _log("Warning: CreateRemoteThread succeeded but module message window was not found.");
            }
            else
            {
                _log($"CreateRemoteThread injection failed: {remoteThreadError}");
            }
        }

        if (hookTargets.Length == 0)
        {
            throw new InvalidOperationException($"无法注入模组：目标进程没有线程且 CreateRemoteThread 失败 ({remoteThreadError})。");
        }

        _log("Attempting injection via WH_GETMESSAGE hooks...");
        nint hDll = LoadLibraryW(dllPath);
        if (hDll == nint.Zero)
        {
            ThrowLastWin32Error($"LoadLibraryW failed: {dllPath}");
        }

        nint hookProc = GetProcAddress(hDll, ModuleMessageProtocol.HookExportName);
        if (hookProc == nint.Zero)
        {
            ThrowLastWin32Error($"GetProcAddress failed: {ModuleMessageProtocol.HookExportName}");
        }

        _log($"WH_GETMESSAGE hook candidates for pid={targetProcessId}: threads={hookTargets.Length}, windowThreads={windowThreadCount}, fallbackThreads={hookTargets.Length - windowThreadCount}.");

        var failures = new List<string>();
        foreach (var target in hookTargets)
        {
            nint hook = SetWindowsHookExW(WhGetMessage, hookProc, hDll, target.ThreadId);
            if (hook == nint.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                failures.Add($"tid={target.ThreadId} source={target.Source} error={error}");
                continue;
            }

            _hookHandles.Add(hook);
            WakeHookTarget(target);

            var moduleWindow = await WaitForModuleWindowAsync(targetProcessId, TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
            if (moduleWindow != nint.Zero)
            {
                _log($"Module hook installed for pid={targetProcessId}: hooks={_hookHandles.Count}, triggerThread={target.ThreadId}, source={target.Source}.");
                return moduleWindow;
            }
        }

        if (_hookHandles.Count == 0)
        {
            var detail = failures.Count == 0 ? "no hook target accepted" : string.Join("; ", failures.Take(5));
            var extraErr = remoteThreadAttempted ? $", CreateRemoteThread error: {remoteThreadError}" : "";
            throw new InvalidOperationException($"无法在目标进程的任何线程安装 WH_GETMESSAGE hook：{detail}{extraErr}");
        }

        _log($"Module hook installed for pid={targetProcessId}: hooks={_hookHandles.Count}; waiting for a target thread to process messages.");
        nint finalWindow = await WaitForModuleWindowAsync(targetProcessId, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        if (finalWindow == nint.Zero && !remoteThreadAttempted)
        {
            _log("WH_GETMESSAGE timed out. Attempting fallback via CreateRemoteThread...");
            if (InjectDllViaCreateRemoteThread(targetProcessId, dllPath, out remoteThreadError))
            {
                _log("Fallback CreateRemoteThread injection succeeded. Waiting for module message window...");
                finalWindow = await WaitForModuleWindowAsync(targetProcessId, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            }
            else
            {
                _log($"Fallback CreateRemoteThread injection failed: {remoteThreadError}");
            }
        }

        return finalWindow;
    }

    private static bool InjectDllViaCreateRemoteThread(int targetProcessId, string dllPath, out string errorMessage)
    {
        errorMessage = string.Empty;
        nint hProcess = nint.Zero;
        nint pRemoteMem = nint.Zero;
        nint hThread = nint.Zero;

        try
        {
            hProcess = OpenProcess(ProcessAllAccess, false, targetProcessId);
            if (hProcess == nint.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                errorMessage = $"OpenProcess failed with error code: {err}.";
                return false;
            }

            int sizeInBytes = (dllPath.Length + 1) * 2;
            pRemoteMem = VirtualAllocEx(hProcess, nint.Zero, (uint)sizeInBytes, MemCommit | MemReserve, PageReadWrite);
            if (pRemoteMem == nint.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                errorMessage = $"VirtualAllocEx failed with error code: {err}.";
                return false;
            }

            byte[] bytes = Encoding.Unicode.GetBytes(dllPath + "\0");
            if (!WriteProcessMemory(hProcess, pRemoteMem, bytes, (uint)bytes.Length, out _))
            {
                var err = Marshal.GetLastWin32Error();
                errorMessage = $"WriteProcessMemory failed with error code: {err}.";
                return false;
            }

            var hKernel32 = GetModuleHandleWString("kernel32.dll");
            if (hKernel32 == nint.Zero)
            {
                errorMessage = "GetModuleHandleW for kernel32.dll failed.";
                return false;
            }

            var pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
            if (pLoadLibrary == nint.Zero)
            {
                errorMessage = "GetProcAddress for LoadLibraryW failed.";
                return false;
            }

            hThread = CreateRemoteThread(hProcess, nint.Zero, 0, pLoadLibrary, pRemoteMem, 0, out _);
            if (hThread == nint.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                errorMessage = $"CreateRemoteThread failed with error code: {err}.";
                return false;
            }

            uint waitResult = WaitForSingleObject(hThread, 5000);
            if (waitResult == WaitTimeout)
            {
                errorMessage = "WaitForSingleObject timed out waiting for LoadLibraryW thread.";
                return false;
            }

            if (GetExitCodeThread(hThread, out uint exitCode))
            {
                if (exitCode == 0)
                {
                    errorMessage = "LoadLibraryW returned NULL in the remote process (DLL loading failed).";
                    return false;
                }
            }
            else
            {
                var err = Marshal.GetLastWin32Error();
                errorMessage = $"GetExitCodeThread failed with error code: {err}.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            errorMessage = $"Exception during CreateRemoteThread injection: {ex.Message}";
            return false;
        }
        finally
        {
            if (pRemoteMem != nint.Zero && hProcess != nint.Zero)
            {
                _ = VirtualFreeEx(hProcess, pRemoteMem, 0, MemRelease);
            }
            if (hThread != nint.Zero)
            {
                _ = CloseHandle(hThread);
            }
            if (hProcess != nint.Zero)
            {
                _ = CloseHandle(hProcess);
            }
        }
    }

    private static void WakeTargetProcess(int targetProcessId)
    {
        foreach (var target in FindHookTargetsByProcessId(targetProcessId))
        {
            WakeHookTarget(target);
        }
    }

    private static void WakeHookTarget(HookTargetInfo target)
    {
        _ = PostThreadMessageW(target.ThreadId, WmNull, nint.Zero, nint.Zero);

        if (target.HWnd != nint.Zero)
        {
            _ = PostMessageW(target.HWnd, WmNull, nint.Zero, nint.Zero);
        }
    }

    private static async Task<nint> WaitForModuleWindowAsync(int targetProcessId, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            var window = TryFindModuleWindow(targetProcessId);
            if (window != nint.Zero)
            {
                return window;
            }

            WakeTargetProcess(targetProcessId);
            await Task.Delay(100).ConfigureAwait(false);
        }

        return nint.Zero;
    }

    private static nint TryFindModuleWindow(int targetProcessId)
    {
        var parent = new nint(HwndMessage);
        nint current = nint.Zero;

        while (true)
        {
            current = FindWindowExW(parent, current, ModuleMessageProtocol.WindowClassName, null);
            if (current == nint.Zero)
            {
                return nint.Zero;
            }

            _ = GetWindowThreadProcessId(current, out var windowProcessId);
            if (windowProcessId == targetProcessId)
            {
                return current;
            }
        }
    }

    private static IEnumerable<WindowInfo> FindHookWindowsByProcessId(int processId)
    {
        var windows = new List<WindowInfo>();
        EnumWindows((hWnd, lParam) =>
        {
            var threadId = GetWindowThreadProcessId(hWnd, out var windowProcessId);
            if (windowProcessId == processId)
            {
                var className = GetClassNameText(hWnd);
                windows.Add(new WindowInfo(
                    hWnd,
                    threadId,
                    IsWindowVisible(hWnd),
                    IsLowPriorityHookWindowClass(className)));
            }

            return true;
        }, nint.Zero);

        return windows
            .OrderBy(window => window.IsLowPriority)
            .ThenByDescending(window => window.IsVisible);
    }

    private static HookTargetSummary GetHookTargetSummary(int processId)
    {
        var windows = FindHookWindowsByProcessId(processId).ToArray();
        var visibleWindows = windows.Count(window => window.IsVisible && !window.IsLowPriority);
        var hiddenWindows = windows.Count(window => !window.IsVisible && !window.IsLowPriority);
        var lowPriorityWindows = windows.Count(window => window.IsLowPriority);
        var threadCount = FindProcessThreadIds(processId).Count;
        return new HookTargetSummary(visibleWindows, hiddenWindows, lowPriorityWindows, threadCount);
    }

    private static IEnumerable<HookTargetInfo> FindHookTargetsByProcessId(int processId)
    {
        var seenThreadIds = new HashSet<uint>();

        foreach (var window in FindHookWindowsByProcessId(processId))
        {
            if (window.ThreadId == 0 || !seenThreadIds.Add(window.ThreadId))
            {
                continue;
            }

            yield return new HookTargetInfo(
                window.HWnd,
                window.ThreadId,
                window.IsVisible,
                window.IsLowPriority,
                HasWindow: true);
        }

        foreach (var threadId in FindProcessThreadIds(processId))
        {
            if (threadId == 0 || !seenThreadIds.Add(threadId))
            {
                continue;
            }

            yield return new HookTargetInfo(
                nint.Zero,
                threadId,
                IsVisible: false,
                IsLowPriority: false,
                HasWindow: false);
        }
    }

    private static IReadOnlyList<uint> FindProcessThreadIds(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            var threadIds = new List<uint>();

            foreach (ProcessThread thread in process.Threads)
            {
                try
                {
                    threadIds.Add((uint)thread.Id);
                }
                finally
                {
                    thread.Dispose();
                }
            }

            return threadIds.OrderBy(threadId => threadId).ToArray();
        }
        catch (ArgumentException)
        {
            return [];
        }
        catch (InvalidOperationException)
        {
            return [];
        }
        catch (Win32Exception)
        {
            return [];
        }
    }

    private static bool IsLowPriorityHookWindowClass(string className)
    {
        return className.Equals("IME", StringComparison.OrdinalIgnoreCase)
            || className.Equals("MSCTFIME UI", StringComparison.OrdinalIgnoreCase)
            || className.Equals("crashpad_SessionEndWatcher", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetClassNameText(nint hWnd)
    {
        var builder = new StringBuilder(256);
        var copied = GetClassNameW(hWnd, builder, builder.Capacity);
        return copied <= 0 ? string.Empty : builder.ToString();
    }

    private static void ThrowLastWin32Error(string message)
    {
        var error = Marshal.GetLastWin32Error();
        throw new Win32Exception(error, $"{message}. Win32 Error = {error}");
    }

    public void Dispose()
    {
        _disposed = true;
        StopHeartbeat();
        StopRelay();
        ClearHookHandles();

        _messageClient?.Dispose();
        _messageClient = null;
    }

    private void ClearHookHandles()
    {
        foreach (var hookHandle in _hookHandles)
        {
            if (hookHandle != nint.Zero)
            {
                _ = UnhookWindowsHookEx(hookHandle);
            }
        }

        _hookHandles.Clear();
    }

    private const int WhGetMessage = 3;
    private const int HwndMessage = -3;
    private const uint WmNull = 0x0000;

    private delegate bool EnumWindowsProc(nint hWnd, nint lParam);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint LoadLibraryW(string lpLibFileName);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern nint GetProcAddress(nint hModule, string lpProcName);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern nint SetWindowsHookExW(int idHook, nint lpfn, nint hMod, uint dwThreadId);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(nint hhk);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, nint lParam);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(nint hWnd);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern uint GetWindowThreadProcessId(nint hWnd, out int lpdwProcessId);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetClassNameW(nint hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint FindWindowExW(nint hWndParent, nint hWndChildAfter, string? lpszClass, string? lpszWindow);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostThreadMessageW(uint idThread, uint Msg, nint wParam, nint lParam);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessageW(nint hWnd, uint Msg, nint wParam, nint lParam);

    private const uint ProcessAllAccess = 0x001F0FFF;
    private const uint MemCommit = 0x00001000;
    private const uint MemReserve = 0x00002000;
    private const uint MemRelease = 0x00008000;
    private const uint PageReadWrite = 0x04;
    private const uint WaitTimeout = 0x00000102;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint processAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualAllocEx(nint hProcess, nint lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, uint nSize, out nint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes, uint dwStackSize, nint lpStartAddress, nint lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeThread(nint hThread, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualFreeEx(nint hProcess, nint lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint GetModuleHandleWString(string lpModuleName);

    private readonly record struct WindowInfo(nint HWnd, uint ThreadId, bool IsVisible, bool IsLowPriority);

    private readonly record struct ModuleTargetCandidate(ModuleTargetProcess Target, HookTargetSummary Summary);

    private readonly record struct HookTargetSummary(
        int VisibleWindowCount,
        int HiddenWindowCount,
        int LowPriorityWindowCount,
        int ThreadCount)
    {
        public int Rank
        {
            get
            {
                if (VisibleWindowCount > 0)
                {
                    return 0;
                }

                if (HiddenWindowCount > 0)
                {
                    return 1;
                }

                if (LowPriorityWindowCount > 0)
                {
                    return 2;
                }

                return ThreadCount > 0 ? 3 : 4;
            }
        }

        public string Description
        {
            get
            {
                if (VisibleWindowCount > 0)
                {
                    return $"visible hook window(s)={VisibleWindowCount}";
                }

                if (HiddenWindowCount > 0)
                {
                    return $"hidden hook window(s)={HiddenWindowCount}";
                }

                if (LowPriorityWindowCount > 0)
                {
                    return $"low-priority hook window(s)={LowPriorityWindowCount}";
                }

                return ThreadCount > 0 ? $"threads={ThreadCount}, no top-level window" : "no available thread";
            }
        }
    }

    private readonly record struct HookTargetInfo(nint HWnd, uint ThreadId, bool IsVisible, bool IsLowPriority, bool HasWindow)
    {
        public string Source => HasWindow
            ? IsVisible ? "visible-window" : IsLowPriority ? "low-priority-window" : "hidden-window"
            : "process-thread";
    }
}

public enum ModuleStartResult
{
    Canceled,
    Started
}

public enum ModuleAttachResult
{
    Attached,
    TargetProcessMissing,
    NotLoaded,
    Unresponsive
}

internal sealed record ModuleProcessDisplayInfo(string Text, string NetworkOwnerHint);
